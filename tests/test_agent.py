"""Agent mode: a gateway whose upstream is another torrenthub gateway (a hub) and which pulls
large files from the swarm instead of over HTTP. Real libtorrent, real HF client, loopback.

Topology used below:  fake HF  ->  hub  ->  agent  ->  agent2
Web seeds are stripped on agents, so bytes for big files can only arrive over the peer wire.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

import httpx
import pytest
from huggingface_hub import snapshot_download

from tests.conftest import Server, free_port
from tests.fake_upstream import REPO
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length

pytest.importorskip("libtorrent")
from torrenthub.swarm import LibtorrentSwarm  # noqa: E402
from tests.helpers import SMALL_FILES_BUDGET, Node, assert_repo_equals, warm_hub  # noqa: E402

# ---------------------------------------------------------------------------------------

def test_agent_pulls_big_file_from_peers_not_hub_http(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    upstream.stop()  # origin is gone: everything now depends on the hub and the swarm

    agent = nodes("agent", hub.url, peers=[hub.endpoint], swarm_first=True, swarm_stall=10)
    before = hub.served()
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    assert hub.served() - before < SMALL_FILES_BUDGET, "the big file went over the hub's HTTP"
    assert agent.metrics.get("thub_bytes_fetched_total", source="swarm") == len(data)
    assert agent.metrics.get("thub_torrent_fetch_total", result="ok") == 1
    # The agent kept the torrent, so it can seed to others, with the same infohash as the hub.
    assert agent.store.blob_complete(sha)
    assert agent.store.get_blob(sha).infohash == hub.store.get_blob(sha).infohash


def test_agent_streams_while_swarm_download_is_in_progress(nodes, upstream):
    hub = nodes("hub", upstream.url, )
    hub.swarm.ses.apply_settings({"upload_rate_limit": 1_000_000, "ignore_limits_on_local_network": False})
    data, sha = warm_hub(hub, upstream)
    agent = nodes("agent", hub.url, peers=[hub.endpoint], swarm_first=True, swarm_stall=10)

    got = bytearray()
    in_progress_at_first_byte = None
    with httpx.stream("GET", f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60) as r:
        assert r.headers["x-mirror-cache"] == "miss"
        for chunk in r.iter_bytes():
            if in_progress_at_first_byte is None:
                inf = agent.app.state.mirror._inflight.get(sha)
                in_progress_at_first_byte = inf is not None and not inf.done and inf.written < len(data)
            got += chunk
    assert in_progress_at_first_byte, "client waited for the whole swarm download"
    assert bytes(got) == data


def test_agent_falls_back_to_http_when_swarm_has_no_peers(nodes, upstream):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    agent = nodes("agent", hub.url, swarm_first=True, swarm_stall=1.0)  # no peer hint, no DHT

    before = hub.served()
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)
    assert r.status_code == 200 and r.content == data
    assert agent.metrics.get("thub_swarm_fallback_total") == 1
    assert hub.served() - before >= len(data)  # it did come over HTTP from the hub
    assert agent.store.blob_complete(sha)


def test_agent_rejects_a_torrent_that_is_not_about_the_blob(nodes, upstream):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    # Replace the hub's torrent with a valid-looking one for a different name.
    hasher = PieceHasher(choose_piece_length(len(data)))
    hasher.update(data)
    wrong, _ = build_torrent(
        name="not-the-blob", length=len(data), piece_length=choose_piece_length(len(data)), pieces=hasher.finish()
    )
    hub.store.torrent_path(sha).write_bytes(wrong)

    agent = nodes("agent", hub.url, peers=[hub.endpoint], swarm_first=True, swarm_stall=1.0)
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)
    assert r.status_code == 200 and r.content == data  # served over HTTP instead
    assert agent.metrics.get("thub_torrent_fetch_total", result="rejected") == 1
    assert agent.metrics.get("thub_bytes_fetched_total", source="swarm") == 0


def test_swarm_content_that_fails_sha256_is_never_published(nodes, upstream, tmp_path):
    """A poisoned index hands out a torrent over bad bytes, named as the real blob. Every piece
    checks out against that torrent, so only the sha256 comparison can catch it."""
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    mid = len(data) // 2
    bad = data[:mid] + bytes([data[mid] ^ 0xFF]) + data[mid + 1:]

    pl = choose_piece_length(len(bad))
    hasher = PieceHasher(pl)
    hasher.update(bad)
    evil_torrent, _ = build_torrent(name=sha, length=len(bad), piece_length=pl, pieces=hasher.finish())
    hub.store.torrent_path(sha).write_bytes(evil_torrent)  # the hub now serves the poisoned torrent

    evil_dir = tmp_path / "evil"
    evil_dir.mkdir()
    (evil_dir / sha).write_bytes(bad)
    (tmp_path / "evil.torrent").write_bytes(evil_torrent)
    evil = LibtorrentSwarm(listen_port=free_port(), listen_host="127.0.0.1", dht=False)
    asyncio.run(evil.seed(tmp_path / "evil.torrent", evil_dir))

    agent = nodes("agent", hub.url, peers=[evil.peer_endpoint()], swarm_first=True, swarm_stall=10)
    url = f"{agent.url}/{REPO}/resolve/main/model.safetensors"

    received = None
    try:
        received = httpx.get(url, timeout=60).content
    except httpx.HTTPError:
        pass  # connection dropped before the held-back tail: expected
    assert received is None or len(received) < len(data)

    assert agent.metrics.get("thub_integrity_failures_total", source="swarm") == 1
    assert not agent.store.blob_complete(sha)
    assert not agent.store.blob_path(sha).exists()
    assert not agent.store.torrent_path(sha).exists()  # the poisoned torrent is not kept or seeded

    # A retry does not trust the swarm for this blob again, and gets the real bytes over HTTP.
    again = httpx.get(url, timeout=60)
    assert again.status_code == 200 and again.content == data
    assert agent.store.blob_complete(sha)


def test_agent_becomes_a_source_for_the_next_agent(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    agent1 = nodes("agent1", hub.url, peers=[hub.endpoint], swarm_first=True, swarm_stall=10)
    snapshot_download(REPO, endpoint=agent1.url, cache_dir=str(tmp_path / "c1"), token=False)

    # The hub and the origin go away completely.
    hub.stop()
    hub.swarm.ses.pause()
    upstream.stop()

    agent2 = nodes("agent2", agent1.url, peers=[agent1.endpoint], swarm_first=True, swarm_stall=10)
    before = agent1.served()
    local = snapshot_download(REPO, endpoint=agent2.url, cache_dir=str(tmp_path / "c2"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    assert agent1.served() - before < SMALL_FILES_BUDGET, "agent1 served the big file over HTTP"
    assert agent2.metrics.get("thub_bytes_fetched_total", source="swarm") == len(data)


def test_agent_without_swarm_first_never_asks_for_a_torrent(nodes, upstream):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    plain = nodes("plain", hub.url, peers=[hub.endpoint])  # swarm_first defaults to False
    r = httpx.get(f"{plain.url}/{REPO}/resolve/main/model.safetensors", timeout=60)
    assert r.status_code == 200 and r.content == data
    assert plain.metrics.get("thub_torrent_fetch_total", result="ok") == 0
    assert plain.metrics.get("thub_bytes_fetched_total", source="swarm") == 0
