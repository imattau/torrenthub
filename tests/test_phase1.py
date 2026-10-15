"""Phase 1 features: streaming misses, slash revisions, eviction, policy, takedown, metrics."""

from __future__ import annotations

import asyncio
import hashlib
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from huggingface_hub import hf_hub_download, snapshot_download

from tests.conftest import Server, free_port
from tests.fake_upstream import REPO, build_app
from torrenthub.app import create_app
from torrenthub.config import Settings


def make_gateway(upstream, tmp_path, name="gw", **overrides):
    port = free_port()
    settings = Settings(
        data_dir=tmp_path / name,
        upstream=upstream.url,
        public_url=f"http://127.0.0.1:{port}",
        ref_ttl=0.0,
        **overrides,
    )
    app = create_app(settings)
    srv = Server(app, port).start()
    srv.app, srv.settings = app, settings
    return srv


def wait_until(pred, timeout=15.0, step=0.05):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


# ------------------------------------------------------------------ streaming

def test_first_bytes_arrive_before_download_finishes(gateway, upstream):
    upstream.app.state.delay = 0.08  # 14 chunks, about 1.1 s in total
    data = upstream.app.state.files["model.safetensors"]
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"
    got = bytearray()
    finished_at_first_byte = None
    with httpx.stream("GET", url, timeout=30) as r:
        assert r.headers["x-mirror-cache"] == "miss"
        assert r.headers["content-length"] == str(len(data))
        for chunk in r.iter_bytes():
            if finished_at_first_byte is None:
                finished_at_first_byte = upstream.app.state.finished
            got += chunk
    assert finished_at_first_byte == 0, "client had to wait for the whole download"
    assert bytes(got) == data


def _inflight(size=10_000, holdback=1_000):
    from pathlib import Path

    from torrenthub.mirror import Inflight
    from torrenthub.store import FileRec

    return Inflight(FileRec("f", size, "e", "k", True), Path("tmp"), Path("final"), holdback)


def test_tail_is_held_back_until_verified():
    """Bytes in the last `holdback` window are not released until the whole file is verified."""

    async def run():
        inf = _inflight()
        await inf.progress(10_000)  # every byte has been downloaded, none verified
        assert inf.releasable() == 9_000
        assert await inf.wait_for(8_999) == 9_000  # inside the safe window: released
        with pytest.raises(asyncio.TimeoutError):  # inside the held-back tail: blocked
            await asyncio.wait_for(inf.wait_for(9_000), timeout=0.2)
        waiter = asyncio.create_task(inf.wait_for(9_500))
        await asyncio.sleep(0.05)
        assert not waiter.done()
        await inf.finish()  # verification passed
        assert await waiter == 10_000

    asyncio.run(run())


def test_failed_verification_never_releases_tail():
    async def run():
        inf = _inflight()
        await inf.progress(10_000)
        waiter = asyncio.create_task(inf.wait_for(9_500))
        await asyncio.sleep(0.05)
        await inf.finish(RuntimeError("sha256 mismatch"))
        with pytest.raises(RuntimeError):
            await waiter
        with pytest.raises(RuntimeError):  # a reader arriving late is refused too
            await inf.wait_for(9_000)

    asyncio.run(run())


def test_file_smaller_than_holdback_is_fully_held_until_verified():
    async def run():
        inf = _inflight(size=500, holdback=1_000)
        await inf.progress(500)
        assert inf.releasable() == 0
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(inf.wait_for(0), timeout=0.2)
        await inf.finish()
        assert await inf.wait_for(0) == 500

    asyncio.run(run())


def test_concurrent_clients_share_one_upstream_download(gateway, upstream):
    upstream.app.state.delay = 0.03
    data = upstream.app.state.files["model.safetensors"]
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"

    def get(_):
        return httpx.get(url, timeout=30).content

    with ThreadPoolExecutor(4) as ex:
        results = list(ex.map(get, range(4)))
    assert all(r == data for r in results)
    assert upstream.app.state.file_hits["model.safetensors"] == 1


def test_client_disconnect_does_not_stop_mirroring(gateway, upstream):
    upstream.app.state.delay = 0.05
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"
    with httpx.stream("GET", url, timeout=30) as r:
        next(r.iter_bytes())  # read one chunk, then walk away
    store = gateway.app.state.store
    assert wait_until(lambda: store.blob_complete(sha), timeout=20)
    assert httpx.get(url).content == data


def test_range_request_on_inflight_download(gateway, upstream):
    upstream.app.state.delay = 0.05
    data = upstream.app.state.files["model.safetensors"]
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"
    r = httpx.get(url, headers={"Range": "bytes=1000-1999"}, timeout=30)
    assert r.status_code == 206 and r.content == data[1000:2000]
    r = httpx.get(url, headers={"Range": "bytes=-100"}, timeout=30)  # suffix needs total size
    assert r.status_code == 206 and r.content == data[-100:]


# ------------------------------------------------------------------ slash revisions

def test_pr_style_revision_with_client(gateway, upstream, tmp_path):
    local = snapshot_download(REPO, revision="refs/pr/1", endpoint=gateway.url, cache_dir=str(tmp_path / "c"), token=False)
    with open(f"{local}/config.json", "rb") as f:
        assert f.read() == upstream.app.state.files["config.json"]


def test_pr_style_revision_on_resolve_path(gateway, upstream, tmp_path):
    p = hf_hub_download(REPO, "config.json", revision="refs/pr/1", endpoint=gateway.url, cache_dir=str(tmp_path / "c"), token=False)
    with open(p, "rb") as f:
        assert f.read() == upstream.app.state.files["config.json"]
    store = gateway.app.state.store
    assert store.get_ref(REPO, "refs/pr/1") is not None


# ------------------------------------------------------------------ eviction

@pytest.fixture()
def two_blob_upstream():
    rng = random.Random(7)
    files = {"a.bin": rng.randbytes(1_500_000), "b.bin": rng.randbytes(1_500_000)}
    app = build_app(files)
    srv = Server(app, free_port()).start()
    srv.app = app
    yield srv
    srv.stop()


def test_lru_eviction_keeps_torrent_and_refills(two_blob_upstream, tmp_path):
    up = two_blob_upstream
    gw = make_gateway(up, tmp_path, max_disk_bytes=2_000_000)  # room for one blob
    try:
        store = gw.app.state.store
        a = hashlib.sha256(up.app.state.files["a.bin"]).hexdigest()
        b = hashlib.sha256(up.app.state.files["b.bin"]).hexdigest()
        ua, ub = (f"{gw.url}/{REPO}/resolve/main/{n}" for n in ("a.bin", "b.bin"))

        assert httpx.get(ua).content == up.app.state.files["a.bin"]
        time.sleep(0.02)
        assert httpx.get(ub).content == up.app.state.files["b.bin"]

        assert wait_until(lambda: not store.blob_complete(a))  # a was least recently used
        assert store.blob_complete(b)
        assert store.torrent_path(a).exists()  # torrent kept so the swarm can refill it
        assert store.disk_usage() <= 2_000_000

        # a is requested again: refilled from upstream (no swarm here), and b is now the LRU
        assert httpx.get(ua).content == up.app.state.files["a.bin"]
        assert wait_until(lambda: store.blob_complete(a) and not store.blob_complete(b))
        assert gw.app.state.metrics.get("thub_evictions_total") == 2
    finally:
        gw.stop()


def test_access_refreshes_lru_order(two_blob_upstream, tmp_path):
    up = two_blob_upstream
    gw = make_gateway(up, tmp_path, max_disk_bytes=4_000_000)  # room for both
    try:
        store = gw.app.state.store
        a = hashlib.sha256(up.app.state.files["a.bin"]).hexdigest()
        b = hashlib.sha256(up.app.state.files["b.bin"]).hexdigest()
        httpx.get(f"{gw.url}/{REPO}/resolve/main/a.bin")
        time.sleep(0.02)
        httpx.get(f"{gw.url}/{REPO}/resolve/main/b.bin")
        time.sleep(0.02)
        httpx.get(f"{gw.url}/{REPO}/resolve/main/a.bin")  # a is now newer than b
        order = [x.key for x in store.lru_candidates()]
        assert order == [b, a]
    finally:
        gw.stop()


def test_no_budget_means_no_eviction(two_blob_upstream, tmp_path):
    up = two_blob_upstream
    gw = make_gateway(up, tmp_path)  # max_disk_bytes defaults to 0 (unlimited)
    try:
        httpx.get(f"{gw.url}/{REPO}/resolve/main/a.bin")
        httpx.get(f"{gw.url}/{REPO}/resolve/main/b.bin")
        assert gw.app.state.store.count_blobs() == 2
        assert gw.app.state.metrics.get("thub_evictions_total") == 0
    finally:
        gw.stop()


# ------------------------------------------------------------------ policy and takedown

def test_deny_glob_returns_451(upstream, tmp_path):
    gw = make_gateway(upstream, tmp_path, deny=["acme/*"])
    try:
        r = httpx.get(f"{gw.url}/{REPO}/resolve/main/config.json")
        assert r.status_code == 451 and r.headers["x-error-code"] == "RepoBlocked"
        assert httpx.get(f"{gw.url}/api/models/{REPO}/revision/main").status_code == 451
        assert upstream.app.state.hits["info"] == 0  # never even asked upstream
    finally:
        gw.stop()


def test_allow_list_restricts_repos(upstream, tmp_path):
    gw = make_gateway(upstream, tmp_path, allow=["somebody-else/*"])
    try:
        r = httpx.get(f"{gw.url}/{REPO}/resolve/main/config.json")
        assert r.status_code == 404 and r.headers["x-error-code"] == "RepoNotFound"
    finally:
        gw.stop()


def test_block_blob_removes_bytes_torrent_and_refuses_serving(gateway, upstream):
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"
    assert httpx.get(url).content == data
    store = gateway.app.state.store
    assert store.torrent_path(sha).exists()

    asyncio.run(gateway.app.state.mirror.block(sha, "test takedown"))

    r = httpx.get(url)
    assert r.status_code == 451 and r.headers["x-error-code"] == "BlobBlocked"
    assert httpx.get(f"{gateway.url}/blobs/{sha}").status_code == 404
    assert httpx.get(f"{gateway.url}/torrents/{sha}.torrent").status_code == 404
    assert not store.blob_path(sha).exists() and not store.torrent_path(sha).exists()
    listing = httpx.get(f"{gateway.url}/api/swarm/{REPO}/revision/main").json()
    assert listing["files"] == []
    # Other files in the repo still work.
    assert httpx.get(f"{gateway.url}/{REPO}/resolve/main/config.json").status_code == 200
    # HEAD still answers from the catalogue, the content is what is refused.
    assert httpx.head(url).status_code == 200


# ------------------------------------------------------------------ metrics and prefetch

def test_metrics_endpoint(gateway, upstream):
    data = upstream.app.state.files["model.safetensors"]
    url = f"{gateway.url}/{REPO}/resolve/main/model.safetensors"
    httpx.get(url)  # miss
    httpx.get(url)  # hit
    text = httpx.get(f"{gateway.url}/metrics").text
    lines = {l.split(" ")[0]: l.split(" ")[1] for l in text.splitlines() if l and not l.startswith("#")}
    assert int(lines['thub_bytes_fetched_total{source="upstream"}']) >= len(data)
    assert int(lines['thub_bytes_served_total']) >= 2 * len(data)
    assert lines['thub_resolve_total{result="miss"}'] == "1"
    assert lines['thub_resolve_total{result="hit"}'] == "1"
    assert int(lines["thub_blobs"]) >= 1
    assert "# TYPE thub_disk_bytes gauge" in text


def test_prefetch_warms_files_after_metadata_read(upstream, tmp_path):
    gw = make_gateway(upstream, tmp_path, prefetch=True)
    try:
        httpx.get(f"{gw.url}/api/models/{REPO}/revision/main")
        data = upstream.app.state.files["model.safetensors"]
        sha = hashlib.sha256(data).hexdigest()
        store = gw.app.state.store
        assert wait_until(lambda: store.blob_complete(sha), timeout=20)
        assert upstream.app.state.file_hits.get("model.safetensors") == 1
        # the later client download is a hit and does not touch upstream again
        r = httpx.get(f"{gw.url}/{REPO}/resolve/main/model.safetensors")
        assert r.headers["x-mirror-cache"] == "hit"
        assert upstream.app.state.file_hits["model.safetensors"] == 1
    finally:
        gw.stop()


# ------------------------------------------------------------------ piece read-back verification

def _swarm_inflight(tmp_path, served: bytes, truth: bytes, piece_len=256 * 1024):
    """An Inflight whose file on disk is `served`, with piece hashes taken from `truth`."""
    from torrenthub.app import iter_inflight  # noqa: F401
    from torrenthub.mirror import Inflight
    from torrenthub.store import FileRec
    from torrenthub.torrent import PieceHasher

    path = tmp_path / "blob"
    path.write_bytes(served)
    h = PieceHasher(piece_len)
    h.update(truth)
    inf = Inflight(FileRec("f", len(truth), "k", "k", True), path, path, holdback=0)
    inf.piece_check = (piece_len, h.finish())
    inf.written = len(truth)
    inf.verified = True
    inf.done = True
    return inf


async def _collect(inf, start, end):
    from torrenthub.app import iter_inflight

    out = bytearray()
    async for chunk in iter_inflight(inf, start, end):
        out += chunk
    return bytes(out)


def test_readback_serves_correct_bytes_including_ranges(tmp_path):
    data = random.Random(3).randbytes(700_000)  # 3 pieces, the last one short
    inf = _swarm_inflight(tmp_path, data, data)
    assert asyncio.run(_collect(inf, 0, len(data) - 1)) == data
    assert asyncio.run(_collect(inf, 262_000, 524_500)) == data[262_000:524_501]  # crosses a boundary
    assert asyncio.run(_collect(inf, len(data) - 10, len(data) - 1)) == data[-10:]


def test_readback_refuses_a_piece_that_does_not_match_the_torrent(tmp_path):
    from torrenthub.app import StreamAborted, iter_inflight

    data = random.Random(4).randbytes(700_000)
    piece = 256 * 1024
    bad = data[:piece + 5] + bytes([data[piece + 5] ^ 1]) + data[piece + 6:]  # corrupt byte in piece 1
    inf = _swarm_inflight(tmp_path, bad, data)

    async def run():
        got = bytearray()
        with pytest.raises(StreamAborted):
            async for chunk in iter_inflight(inf, 0, len(data) - 1):
                got += chunk
        return bytes(got)

    got = asyncio.run(run())
    assert got == data[:piece]  # piece 0 was fine and went out; nothing from piece 1 did
