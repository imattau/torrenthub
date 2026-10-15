"""Attestations changing what a gateway serves, end to end, with real HTTP between the parts."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pickle
import stat
import struct
import subprocess
import sys
import threading
from collections import OrderedDict

import httpx
import pytest

pytest.importorskip("mcp")
from mcp import Client  # noqa: E402

from tests.conftest import Server, free_port
from tests.fake_upstream import REPO, build_app
from tests.test_trust import A, B, C, D, ROOT, key, pub
from torrenthub import events as E
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.mcp_server import build_server
from torrenthub.signer import Signer, SignerClient, SignerConfig, serve
from torrenthub.verifier import Verifier

POLICY = """
[[file]]
match = ["*.bin"]
claim = "format_scan"
independent = 2
min_trust = 0.5

[[file]]
match = ["*.safetensors"]
claim = "hash_verified"
"""


class Evil:
    def __reduce__(self):
        return (os.system, ("true",))


def safetensors_bytes() -> bytes:
    n = 300 * 1000
    header = json.dumps({"w": {"dtype": "F32", "shape": [300, 1000], "data_offsets": [0, n * 4]}}).encode()
    return struct.pack("<Q", len(header)) + header + b"\0" * (n * 4)


FILES = {
    "config.json": b'{"a": 1}\n',
    "good.safetensors": safetensors_bytes(),
    "benign.bin": pickle.dumps(OrderedDict(w=b"x" * 1_300_000), protocol=4),
    "evil.bin": pickle.dumps([Evil(), b"y" * 1_300_000], protocol=4),
}
SHA = {p: hashlib.sha256(d).hexdigest() for p, d in FILES.items()}


@pytest.fixture()
def world(tmp_path):
    up = Server(build_app(dict(FILES)), free_port()).start()
    pol = tmp_path / "policy.toml"
    pol.write_text(POLICY)

    def gateway(name, **kw):
        port = free_port()
        s = Settings(data_dir=tmp_path / name, upstream=up.url, public_url=f"http://127.0.0.1:{port}", roots=[ROOT], anchor="", **kw)
        srv = Server(create_app(s), port).start()
        srv.settings = s
        return srv

    g = gateway("g", policy=str(pol))   # the consumer, with a policy
    w = gateway("w")                    # holds the bytes, no policy: where verifiers get them
    for p in FILES:
        assert httpx.get(f"{w.url}/{REPO}/resolve/main/{p}", timeout=60).status_code == 200
    yield types_ns(up=up, g=g, w=w, tmp=tmp_path)
    for s in (g, w, up):
        s.stop()


def types_ns(**kw):
    import types

    return types.SimpleNamespace(**kw)


def data(result):
    return result.structured_content or json.loads("".join(getattr(b, "text", "") for b in result.content))


def post(gw, ev):
    r = httpx.post(f"{gw.url}/api/thub/events", json=ev, timeout=30)
    assert r.status_code in (200, 202), r.text
    return r.json()["status"]


def get(gw, path):
    return httpx.get(f"{gw.url}/{REPO}/resolve/main/{path}", timeout=60)


def vouch(n, claims=("format_scan", "hash_verified"), w=0.8):
    return E.build_endorsement(key(1), pub(n), [f"attest:{c}" for c in claims], w, created_at=100)


def attest_all(world, n, only=None):
    v = Verifier(key(n), world.w.app_store if False else _store(world))
    for p, sha in SHA.items():
        if only and p not in only:
            continue
        for ev in v.attest_blob(sha):
            assert post(world.g, ev) == "accepted"


def _store(world):
    # the app keeps its Store on app.state; Server holds the app object it was given
    return world.w.server.config.app.state.store


# ------------------------------------------------------------------ behaviour

def test_files_are_refused_until_enough_independent_trusted_attestors_vouch(world):
    assert get(world.g, "config.json").status_code == 200  # no rule for it
    r = get(world.g, "benign.bin")
    assert r.status_code == 403 and r.headers["x-error-code"] == "PolicyRefused" and "0 of 2" in r.json()["error"]
    assert get(world.g, "good.safetensors").status_code == 403

    post(world.g, vouch(2))
    post(world.g, vouch(3))
    attest_all(world, 2)
    assert get(world.g, "benign.bin").status_code == 403, "one attestor is not two"
    assert get(world.g, "good.safetensors").status_code == 200, "this rule needs only hash_verified from one"
    attest_all(world, 3)
    r = get(world.g, "benign.bin")
    assert r.status_code == 200 and r.content == FILES["benign.bin"] and r.headers["x-thub-attested-by"] == "2"


def test_two_attestors_with_a_common_voucher_are_not_enough(world):
    mid = E.build_endorsement(key(1), pub(2), ["attest:*"], 0.9, delegable=True, created_at=100)
    post(world.g, mid)
    post(world.g, E.build_endorsement(key(2), pub(3), ["attest:format_scan"], 0.9, created_at=100))
    post(world.g, E.build_endorsement(key(2), pub(4), ["attest:format_scan"], 0.9, created_at=100))
    for n in (3, 4):
        for ev in Verifier(key(n), _store(world)).attest_blob(SHA["benign.bin"]):
            post(world.g, ev)
    r = get(world.g, "benign.bin")
    assert r.status_code == 403 and "1 of 2" in r.json()["error"]


def test_a_failed_scan_by_a_trusted_attestor_blocks_the_file(world):
    for n in (2, 3):
        post(world.g, vouch(n))
    attest_all(world, 2, only=["evil.bin", "benign.bin"])
    attest_all(world, 3, only=["benign.bin"])
    r = get(world.g, "evil.bin")
    assert r.status_code == 403 and "failed" in r.json()["error"]
    d = httpx.get(f"{world.g.url}/api/thub/verdict/{SHA['evil.bin']}", params={"claim": "format_scan"}).json()
    assert d["status"] == "negative" and d["failed_attestors"] == [A]
    assert get(world.g, "benign.bin").status_code == 200


def test_a_bad_attestor_is_caught_by_replication(world):
    liars = (2, 3)
    for n in liars:
        post(world.g, vouch(n))
    post(world.g, E.build_endorsement(key(1), pub(5), ["attest:replication"], 0.9, created_at=100))
    lies = [E.build_attestation(key(n), "format_scan", "x", SHA["evil.bin"], ok=True, tool="lazy", created_at=200) for n in liars]
    for ev in lies:
        post(world.g, ev)
    assert get(world.g, "evil.bin").status_code == 200, "the policy is only as good as its attestors"

    replicator = Verifier(key(5), _store(world))
    out = [replicator.replicate(ev) for ev in lies]
    assert all(E.parse_event(o).match is False for o in out)
    post(world.g, out[0])
    assert get(world.g, "evil.bin").status_code == 403, "one liar gone leaves one attestor, and two are needed"
    post(world.g, out[1])
    d = httpx.get(f"{world.g.url}/api/thub/verdict/{SHA['evil.bin']}", params={"claim": "format_scan", "n": 2}).json()
    assert set(d["refuted_attestors"]) == {A, B}
    # honest work by the same attestors on another file is dropped too: they are refuted for everything
    for ev in Verifier(key(2), _store(world)).attest_blob(SHA["benign.bin"]):
        post(world.g, ev)
    assert get(world.g, "benign.bin").status_code == 403


def test_a_replication_by_someone_not_trusted_for_it_changes_nothing(world):
    for n in (2, 3):
        post(world.g, vouch(n))
    lies = [E.build_attestation(key(n), "format_scan", "x", SHA["evil.bin"], ok=True, created_at=200) for n in (2, 3)]
    for ev in lies:
        post(world.g, ev)
    for ev in lies:
        post(world.g, Verifier(key(9), _store(world)).replicate(ev))
    assert get(world.g, "evil.bin").status_code == 200


def test_trusted_revocation_beats_attestation(world):
    for n in (2, 3):
        post(world.g, vouch(n))
    attest_all(world, 2)
    attest_all(world, 3)
    assert get(world.g, "benign.bin").status_code == 200
    post(world.g, E.build_endorsement(key(1), pub(6), ["revoke"], 0.9, created_at=100))
    post(world.g, E.build_revocation(key(6), "x", SHA["benign.bin"], reason="found a backdoor", created_at=300))
    r = get(world.g, "benign.bin")
    assert r.status_code == 403 and r.headers["x-error-code"] == "Revoked"
    assert get(world.g, "good.safetensors").status_code == 200


def test_policy_endpoint_lists_the_rules(world):
    d = httpx.get(f"{world.g.url}/api/thub/policy/{REPO}").json()
    assert [r["claim"] for r in d["file_rules"]] == ["format_scan", "hash_verified"]
    assert d["file_rules"][0]["independent"] == 2


def test_a_bad_policy_file_stops_startup(tmp_path):
    bad = tmp_path / "p.toml"
    bad.write_text("[[file]]\nclaim = 'nope'\n")
    with pytest.raises(Exception, match="claim"):
        create_app(Settings(data_dir=tmp_path / "d", upstream="http://127.0.0.1:9", policy=str(bad), anchor=""))


# ------------------------------------------------------------------------ CLI

def cli(world, data_dir, *args):
    env = dict(os.environ, THUB_DATA=str(data_dir), THUB_ROOTS=ROOT)
    return subprocess.run([sys.executable, "-m", "torrenthub", *args], capture_output=True, text=True, env=env, timeout=120)


def test_cli_verify_blobs_then_replicate(world):
    for n in (2, 3):
        post(world.g, vouch(n))
    post(world.g, E.build_endorsement(key(1), pub(5), ["attest:replication"], 0.9, created_at=100))
    kf = {n: world.tmp / f"k{n}" for n in (2, 3, 5)}
    for n, f in kf.items():
        f.write_text(key(n).hex())
    wdata = world.w.settings.data_dir
    p = cli(world, wdata, "verify-blobs", "--key-file", str(kf[2]), "--post", world.g.url)
    assert p.returncode == 0, p.stderr
    tally = json.loads(p.stdout)
    assert tally == {"accepted": 6}, "3 large blobs (config.json is small and has no sha256): hash_verified and format_scan for each"
    assert get(world.g, "good.safetensors").status_code == 200
    p = cli(world, wdata, "replicate", "--key-file", str(kf[5]), "--from", world.g.url)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == {"accepted": 6}
    again = cli(world, wdata, "replicate", "--key-file", str(kf[5]), "--from", world.g.url)
    assert json.loads(again.stdout) == {}, "already replicated, so nothing new"
    p = cli(world, world.g.settings.data_dir, "verdict", SHA["benign.bin"], "--claim", "format_scan", "--independent", "2")
    assert json.loads(p.stdout)["status"] == "unsatisfied"


# ------------------------------------------------------------- signer and MCP

@pytest.fixture()
def signer_process(tmp_path):
    """A signer serving on a Unix socket, in a thread of its own event loop."""
    root = tmp_path / "dl"
    root.mkdir()
    sock = str(tmp_path / "s.sock")
    s = Signer(key(8), SignerConfig(root, tmp_path / "audit.jsonl"))
    loop = asyncio.new_event_loop()
    ready = threading.Event()
    holder = {}

    def run():
        asyncio.set_event_loop(loop)
        holder["srv"] = loop.run_until_complete(serve(s, sock))
        ready.set()
        loop.run_forever()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    assert ready.wait(10)
    yield types_ns(sock=sock, signer=s, root=root, audit=tmp_path / "audit.jsonl")
    loop.call_soon_threadsafe(loop.stop)
    t.join(5)


def test_signer_socket_is_private_and_answers(signer_process):
    mode = stat.S_IMODE(os.stat(signer_process.sock).st_mode)
    assert mode == 0o600
    c = SignerClient(signer_process.sock)
    assert c.request({"op": "pubkey"})["pubkey"] == signer_process.signer.pubkey
    r = c.request({"op": "attest_file", "path": "/etc/passwd", "sha256": "00" * 32, "filenames": []})
    assert r["ok"] is False
    assert json.loads(signer_process.audit.read_text().splitlines()[-1])["decision"] == "refused"


def test_mcp_agent_attests_a_file_through_the_signer(world, signer_process, tmp_path):
    # the agent's own gateway is w; the signer's key is vouched for there
    signer_pk = signer_process.signer.pubkey
    ev = E.build_endorsement(key(1), signer_pk, ["attest:*"], 0.9, created_at=100)
    assert post(world.w, ev) == "accepted"
    server = build_server(world.w.url, signer_process.root, signer=signer_process.sock)

    async def go():
        async with Client(server) as c:
            names = {t.name for t in (await c.list_tools()).tools}
            r = await c.call_tool("attest_file", {"repo_id": REPO, "path": "benign.bin"})
            v = await c.call_tool("get_verdict", {"repo_id": REPO, "path": "benign.bin", "claim": "format_scan"})
            bad = await c.call_tool("attest_file", {"repo_id": REPO, "path": "config.json"})
            return names, r, v, bad

    names, r, v, bad = asyncio.run(go())
    assert "attest_file" in names and "get_verdict" in names
    assert not r.is_error, r.content
    sc = data(r)
    assert [(a["claim"], a["gateway"]) for a in sc["attestations"]] == [("hash_verified", "accepted"), ("format_scan", "accepted")]
    assert all(a["result"]["ok"] for a in sc["attestations"])
    assert data(v)["satisfied"] is True and data(v)["keys"] == [signer_pk]
    assert bad.is_error, "a small file has no sha256 to attest"
    assert sc["all_checks_passed"] is True and "limited check" in sc["summary"]
    assert not list(signer_process.root.rglob("config.json")), "refused before downloading anything"


def test_mcp_without_a_signer_cannot_attest(world, tmp_path):
    server = build_server(world.w.url, tmp_path / "dl2")

    async def go():
        async with Client(server) as c:
            return {t.name for t in (await c.list_tools()).tools}

    assert "attest_file" not in asyncio.run(go())


def test_mcp_attest_file_says_plainly_when_a_check_failed(world, signer_process):
    post(world.w, E.build_endorsement(key(1), signer_process.signer.pubkey, ["attest:*"], 0.9, created_at=100))
    server = build_server(world.w.url, signer_process.root, signer=signer_process.sock)

    async def go():
        async with Client(server) as c:
            return await c.call_tool("attest_file", {"repo_id": REPO, "path": "evil.bin"}), c.instructions

    r, instructions = asyncio.run(go())
    d = data(r)
    assert d["all_checks_passed"] is False
    assert d["summary"].startswith("CHECK FAILED, do not load this file") and "posix.system" in d["summary"]
    assert all(a["gateway"] == "accepted" for a in d["attestations"]), "stored fine, which is not the same as safe"
    assert "does not prove a file safe" in instructions and "get_verdict" in instructions
