"""Real libtorrent: seed on one node, fetch peer to peer on another.

The torrent lists web seeds (the gateway and the upstream). We strip every web seed
and stop the upstream, so the only way the bytes can arrive is over the BitTorrent
peer wire. That is the cost saving the whole design depends on.
"""

from __future__ import annotations

import asyncio
import hashlib

import httpx
import pytest

from tests.conftest import free_port
from tests.fake_upstream import REPO

lt = pytest.importorskip("libtorrent")

from torrenthub.swarm import LibtorrentSwarm  # noqa: E402
from torrenthub.torrent import strip_webseeds  # noqa: E402


def test_peer_to_peer_transfer_without_web_seeds(gateway, upstream, tmp_path):
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()

    # Mirror once so a torrent and blob exist on the gateway.
    httpx.get(f"{gateway.url}/{REPO}/resolve/main/model.safetensors")
    store = gateway.app.state.store
    torrent = store.torrent_path(sha)
    assert torrent.exists()
    upstream.stop()

    seeder = LibtorrentSwarm(listen_port=free_port(), listen_host="127.0.0.1", dht=False)
    leecher = LibtorrentSwarm(
        listen_port=free_port(), listen_host="127.0.0.1", dht=False, extra_peers=[seeder.peer_endpoint()]
    )
    # Seed from a copy so the test does not depend on the gateway's own session.
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    (seed_dir / sha).write_bytes(data)
    leech_dir = tmp_path / "leech"
    leech_dir.mkdir()

    stripped = tmp_path / "stripped.torrent"
    stripped.write_bytes(strip_webseeds(torrent.read_bytes()))  # peers only, no HTTP web seeds

    async def run():
        await seeder.seed(torrent, seed_dir)
        return await leecher.fetch(stripped, leech_dir, timeout=60)

    ok = asyncio.run(run())
    assert ok, "peer to peer fetch did not complete"
    assert hashlib.sha256((leech_dir / sha).read_bytes()).hexdigest() == sha


def test_gateway_refills_evicted_blob_from_swarm(upstream, tmp_path):
    """Evict the bytes, kill upstream, and a client download still succeeds via peers."""
    from huggingface_hub import hf_hub_download

    from tests.conftest import Server
    from torrenthub.app import create_app
    from torrenthub.config import Settings

    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()

    # A separate seeder node that holds the blob.
    seeder = LibtorrentSwarm(listen_port=free_port(), listen_host="127.0.0.1", dht=False)

    port = free_port()
    settings = Settings(
        data_dir=tmp_path / "gw",
        upstream=upstream.url,
        public_url=f"http://127.0.0.1:{port}",
        webseed_upstream=False,  # only the gateway's own (excluded) web seed, so peers must serve
        swarm_stall=5,
    )
    gw_swarm = LibtorrentSwarm(
        listen_port=free_port(), listen_host="127.0.0.1", dht=False, extra_peers=[seeder.peer_endpoint()]
    )
    gw_app = create_app(settings, swarm=gw_swarm)
    gw = Server(gw_app, port).start()
    try:
        httpx.get(f"{gw.url}/{REPO}/resolve/main/model.safetensors")  # mirror it
        store = gw_app.state.store
        torrent = store.torrent_path(sha)
        seed_dir = tmp_path / "seed"
        seed_dir.mkdir()
        (seed_dir / sha).write_bytes(data)
        asyncio.run(seeder.seed(torrent, seed_dir))

        upstream.stop()
        assert asyncio.run(gw_app.state.mirror.evict(sha))
        assert not store.blob_complete(sha)

        path = hf_hub_download(
            REPO, "model.safetensors", endpoint=gw.url, cache_dir=str(tmp_path / "c"), token=False
        )
        assert hashlib.sha256(open(path, "rb").read()).hexdigest() == sha
        assert store.blob_complete(sha)  # refilled and verified
    finally:
        gw.stop()


def test_outgoing_connections_use_tcp_unless_asked():
    """uTP first is libtorrent's default and was about 15x slower between two machines."""

    async def run():
        a = LibtorrentSwarm(free_port(), dht=False)
        b = LibtorrentSwarm(free_port(), dht=False, outgoing_utp=True)
        try:
            sa, sb = a.ses.get_settings(), b.ses.get_settings()
            assert sa["enable_outgoing_utp"] is False and sa["enable_incoming_utp"] is True
            assert sb["enable_outgoing_utp"] is True
        finally:
            await a.close()
            await b.close()

    asyncio.run(run())


def test_env_switches_outgoing_utp(monkeypatch, tmp_path):
    from torrenthub.config import Settings

    monkeypatch.setenv("THUB_DATA", str(tmp_path))
    assert Settings.from_env().outgoing_utp is False
    monkeypatch.setenv("THUB_OUTGOING_UTP", "true")
    assert Settings.from_env().outgoing_utp is True
