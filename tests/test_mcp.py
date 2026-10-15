"""The MCP server, run against a real gateway over a real MCP session."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")
from mcp import Client, StdioServerParameters  # noqa: E402

from tests.fake_upstream import REPO  # noqa: E402
from torrenthub.mcp_server import NOTICE, _safe_target, build_server  # noqa: E402


def run(server, fn):
    async def go():
        async with Client(server) as c:
            return await fn(c)
    return asyncio.run(go())


async def call(c, name, **args):
    r = await c.call_tool(name, args)
    text = "".join(getattr(b, "text", "") for b in r.content)
    return r.is_error, (r.structured_content or (json.loads(text) if not r.is_error and text.startswith("{") else text))


def server_for(gateway, tmp_path, **kw):
    return build_server(gateway.url if hasattr(gateway, "url") else gateway, tmp_path / "dl", **kw)


def test_lists_the_tools(gateway, tmp_path):
    names = run(server_for(gateway, tmp_path), lambda c: _names(c))
    assert set(names) == {"repo_info", "check_trust", "fetch_file", "verify_file", "get_verdict", "gateway_status"}


async def _names(c):
    return [t.name for t in (await c.list_tools()).tools]


def test_repo_info_and_untrusted_notice(gateway, tmp_path):
    async def f(c):
        return await call(c, "repo_info", repo_id=REPO)
    err, doc = run(server_for(gateway, tmp_path), f)
    assert not err
    assert doc["repo"] == REPO and doc["file_count"] >= 3
    assert doc["untrusted_data"] == NOTICE
    assert {x["path"] for x in doc["files"]} >= {"config.json", "model.safetensors"}


def test_fetch_file_verifies_and_saves(gateway, tmp_path, upstream):
    async def f(c):
        return await call(c, "fetch_file", repo_id=REPO, path="model.safetensors"), await call(c, "fetch_file", repo_id=REPO, path="config.json")
    (e1, big), (e2, small) = run(server_for(gateway, tmp_path), f)
    assert not e1 and not e2
    assert Path(big["saved_to"]).read_bytes() == upstream.app.state.files["model.safetensors"]
    assert big["verified_against"] == "sha256" and small["verified_against"] == "git_blob_sha1"
    assert Path(small["saved_to"]).read_bytes() == upstream.app.state.files["config.json"]
    assert not list((tmp_path / "dl").rglob("*.part"))
    assert Path(big["saved_to"]).resolve().is_relative_to((tmp_path / "dl").resolve())


def test_verify_file_detects_tampering(gateway, tmp_path):
    async def f(c):
        _, d = await call(c, "fetch_file", repo_id=REPO, path="config.json")
        ok = await call(c, "verify_file", repo_id=REPO, path="config.json")
        Path(d["saved_to"]).write_bytes(b"changed")
        bad = await call(c, "verify_file", repo_id=REPO, path="config.json")
        missing = await call(c, "verify_file", repo_id=REPO, path="README.md")
        return ok, bad, missing
    ok, bad, missing = run(server_for(gateway, tmp_path), f)
    assert ok[1]["matches"] is True
    assert bad[1]["matches"] is False
    assert missing[0] is True


def test_wrong_bytes_are_refused_and_removed(gateway, tmp_path):
    """A gateway (or something between) serves bytes that do not match its own metadata."""
    import httpx

    def handler(request: httpx.Request) -> httpx.Response:
        real = httpx.get(str(request.url), timeout=30)
        body = real.content
        if "/resolve/" in request.url.path:
            body = bytes([body[0] ^ 1]) + body[1:]
        return httpx.Response(real.status_code, content=body, headers={"x-thub-source": "x"})

    client = httpx.AsyncClient(base_url=gateway.url, transport=httpx.MockTransport(handler))
    srv = build_server(gateway.url, tmp_path / "dl", client=client)

    async def f(c):
        return await call(c, "fetch_file", repo_id=REPO, path="config.json"), await call(c, "fetch_file", repo_id=REPO, path="model.safetensors")
    (e1, m1), (e2, m2) = run(srv, f)
    assert e1 and e2
    assert "do not match" in str(m1) and "do not match" in str(m2)
    assert not [p for p in (tmp_path / "dl").rglob("*") if p.is_file()]


@pytest.mark.parametrize("path", ["../x", "/etc/passwd", "a/../../x", "a//b", "a\0b", "./x", ""])
def test_unsafe_paths_never_leave_the_root(tmp_path, path):
    with pytest.raises(Exception):
        _safe_target(tmp_path, REPO, "abc", path)


def test_bad_ids_and_revisions_are_rejected(gateway, tmp_path):
    async def f(c):
        return [
            await call(c, "repo_info", repo_id="../../etc"),
            await call(c, "repo_info", repo_id=REPO, revision="a/../b"),
            await call(c, "fetch_file", repo_id=REPO, path="../../x"),
            await call(c, "fetch_file", repo_id=REPO, path="nope.bin"),
        ]
    for err, _ in run(server_for(gateway, tmp_path), f):
        assert err
    assert not [p for p in (tmp_path / "dl").rglob("*") if p.is_file()]


def test_size_cap(gateway, tmp_path):
    async def f(c):
        return await call(c, "fetch_file", repo_id=REPO, path="model.safetensors")
    err, msg = run(server_for(gateway, tmp_path, max_bytes=1000), f)
    assert err and "limit" in str(msg)
    assert not list((tmp_path / "dl").rglob("model.safetensors*"))


def test_check_trust_and_status(gateway, tmp_path):
    async def f(c):
        return await call(c, "check_trust", repo_id=REPO), await call(c, "gateway_status")
    (e1, trust), (e2, st) = run(server_for(gateway, tmp_path), f)
    assert not e1 and not e2
    assert trust["repo"] == REPO and "hash_source" in trust and "meaning" in trust
    assert st["healthy"] is True and "peer_share" in st


def test_unknown_repo_is_a_tool_error(gateway, tmp_path):
    async def f(c):
        return await call(c, "repo_info", repo_id="nobody/nothing")
    err, _ = run(server_for(gateway, tmp_path), f)
    assert err


def test_policy_endpoint_reports_signed_mode(nodes, upstream):
    import httpx
    key = "ab" * 32
    n = nodes("n", upstream.url, trust=[(REPO, f"signed:{key}")])
    d = httpx.get(f"{n.url}/api/thub/policy/{REPO}").json()
    assert d["hash_source"] == "signed" and d["signers"] == [key]


def test_stdio_server_works(gateway, tmp_path):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "torrenthub", "mcp", "--gateway", gateway.url, "--download-root", str(tmp_path / "dl2")],
    )
    async def go():
        async with Client(params) as c:
            return await call(c, "repo_info", repo_id=REPO)
    err, doc = asyncio.run(go())
    assert not err and doc["repo"] == REPO
