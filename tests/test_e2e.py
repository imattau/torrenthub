"""End to end: the real huggingface_hub client talking to the gateway."""

from __future__ import annotations

import hashlib

import httpx
import pytest
from huggingface_hub import snapshot_download
from huggingface_hub.errors import RepositoryNotFoundError

from tests.fake_upstream import REPO
from torrenthub.torrent import bdecode, verify_file_against_info


def download(gateway, cache_dir):
    return snapshot_download(REPO, endpoint=gateway.url, cache_dir=str(cache_dir), token=False)


def test_snapshot_download_matches_upstream(gateway, upstream, tmp_path):
    local = download(gateway, tmp_path / "cache")
    for path, data in upstream.app.state.files.items():
        with open(f"{local}/{path}", "rb") as f:
            assert f.read() == data, path


def test_mirror_survives_upstream_outage(gateway, upstream, tmp_path):
    download(gateway, tmp_path / "cache1")
    hits_before = dict(upstream.app.state.hits)
    upstream.stop()

    local = download(gateway, tmp_path / "cache2")  # fresh client cache, dead upstream
    for path, data in upstream.app.state.files.items():
        with open(f"{local}/{path}", "rb") as f:
            assert f.read() == data, path
    assert upstream.app.state.hits["file"] == hits_before["file"]


def test_second_client_does_not_hit_upstream_for_files(gateway, upstream, tmp_path):
    download(gateway, tmp_path / "a")
    files_after_first = upstream.app.state.hits["file"]
    download(gateway, tmp_path / "b")
    assert upstream.app.state.hits["file"] == files_after_first


def test_torrent_for_large_file_is_valid(gateway, upstream, tmp_path):
    download(gateway, tmp_path / "cache")
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()

    listing = httpx.get(f"{gateway.url}/api/swarm/{REPO}/revision/main").json()
    assert [f["path"] for f in listing["files"]] == ["model.safetensors"]  # small files are not torrented
    entry = listing["files"][0]
    assert entry["sha256"] == sha and entry["available_here"]
    assert entry["magnet"].startswith(f"magnet:?xt=urn:btih:{entry['infohash']}")

    raw = httpx.get(entry["torrent"]).content
    meta = bdecode(raw)
    info = meta[b"info"]
    assert info[b"name"] == sha.encode()
    assert info[b"length"] == len(data)
    blob_path = gateway.app.state.store.blob_path(sha)
    assert verify_file_against_info(info, str(blob_path))
    seeds = [s.decode() for s in meta[b"url-list"]]
    assert f"{gateway.url}/blobs/{sha}" in seeds
    assert any(s.startswith(upstream.url) for s in seeds)
    assert meta[b"announce"] == b"udp://tracker.example.org:1337/announce"


def test_infohash_is_deterministic_across_independent_mirrors(gateway, upstream, tmp_path):
    """A second gateway mirroring the same blob must land in the same swarm."""
    from tests.conftest import Server, free_port
    from torrenthub.app import create_app
    from torrenthub.config import Settings

    download(gateway, tmp_path / "c1")
    first = httpx.get(f"{gateway.url}/api/swarm/{REPO}/revision/main").json()["files"][0]["infohash"]

    port = free_port()
    other = Server(
        create_app(
            Settings(
                data_dir=tmp_path / "other",
                upstream=upstream.url,
                public_url=f"http://127.0.0.1:{port}",
                trackers=["udp://different.example.net:80/announce"],
            )
        ),
        port,
    ).start()
    try:
        download(other, tmp_path / "c2")
        second = httpx.get(f"{other.url}/api/swarm/{REPO}/revision/main").json()["files"][0]["infohash"]
    finally:
        other.stop()
    assert first == second


def test_resolve_headers_and_head(gateway, upstream, tmp_path):
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"

    h = httpx.head(url)
    assert h.status_code == 200
    assert h.headers["x-repo-commit"] == upstream.app.state.commit
    assert h.headers["x-linked-etag"].strip('"') == sha
    assert h.headers["x-linked-size"] == str(len(data))
    assert h.headers["content-length"] == str(len(data))
    assert h.headers["accept-ranges"] == "bytes"

    cfg = httpx.head(f"{gateway.url}/{REPO}/resolve/main/config.json")
    assert "x-linked-etag" not in cfg.headers  # plain git file, not LFS


def test_range_requests(gateway, upstream):
    data = upstream.app.state.files["model.safetensors"]
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"
    r = httpx.get(url, headers={"Range": "bytes=100-199"})
    assert r.status_code == 206
    assert r.content == data[100:200]
    assert r.headers["content-range"] == f"bytes 100-199/{len(data)}"

    r = httpx.get(url, headers={"Range": f"bytes={len(data) - 10}-"})
    assert r.status_code == 206 and r.content == data[-10:]

    r = httpx.get(url, headers={"Range": "bytes=-5"})
    assert r.status_code == 206 and r.content == data[-5:]

    r = httpx.get(url, headers={"Range": f"bytes={len(data) + 5}-"})
    assert r.status_code == 416


def test_web_seed_endpoint_serves_ranges_and_only_held_blobs(gateway, upstream):
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()
    assert httpx.get(f"{gateway.url}/blobs/{sha}").status_code == 404  # not mirrored yet

    httpx.get(f"{gateway.url}/{REPO}/resolve/main/model.safetensors")  # triggers mirroring
    r = httpx.get(f"{gateway.url}/blobs/{sha}", headers={"Range": "bytes=1000-1999"})
    assert r.status_code == 206 and r.content == data[1000:2000]


def test_unknown_repo_maps_to_repo_not_found(gateway, tmp_path):
    with pytest.raises(RepositoryNotFoundError):
        snapshot_download("nobody/nothing", endpoint=gateway.url, cache_dir=str(tmp_path / "c"), token=False)


def test_missing_file_is_entry_not_found(gateway):
    r = httpx.get(f"{gateway.url}/{REPO}/resolve/main/nope.bin")
    assert r.status_code == 404
    assert r.headers["x-error-code"] == "EntryNotFound"


def test_corrupt_upstream_bytes_are_rejected(gateway, upstream):
    """If upstream serves bytes that do not match its own advertised hash, do not mirror them."""
    files = upstream.app.state.files
    original = files["model.safetensors"]
    sha = hashlib.sha256(original).hexdigest()
    # The fake upstream advertises the original hash but now serves altered bytes.
    # The response is streamed, so it starts before the check can run. The guarantee is
    # that the held-back tail is never released: the client cannot get a complete file.
    files["model.safetensors"] = b"\x00" + original[1:]
    got = None
    try:
        got = httpx.get(f"{gateway.url}/{REPO}/resolve/main/model.safetensors").content
    except httpx.HTTPError:
        pass  # connection dropped before the tail: expected
    assert got is None or len(got) < len(original)
    store = gateway.app.state.store
    assert not store.blob_complete(sha)
    assert not store.torrent_path(sha).exists()
    assert not store.tmp_path(sha).exists()  # no partial file left behind

    assert gateway.app.state.metrics.get("thub_integrity_failures_total", source="upstream") == 1

    # Once upstream serves the right bytes again, mirroring recovers.
    files["model.safetensors"] = original
    r = httpx.get(f"{gateway.url}/{REPO}/resolve/main/model.safetensors")
    assert r.status_code == 200 and r.content == original
