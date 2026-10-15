"""Shared helpers for tests that run several real gateways with real libtorrent on loopback."""

from __future__ import annotations

import hashlib
import time

import httpx

from tests.conftest import Server, free_port
from tests.fake_upstream import REPO
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.swarm import LibtorrentSwarm

SMALL_FILES_BUDGET = 200_000  # config.json, README.md and a 1.5 KB file: far below the 3.5 MiB blob


class Node:
    def __init__(self, tmp_path, name, upstream_url, *, peers=(), upload_limit=0, **settings):
        settings.setdefault("anchor", "")  # no automatic Hugging Face anchor in tests unless asked for
        settings.setdefault("ref_ttl", 0.0)  # re-check upstream every time unless a test says otherwise
        port = free_port()
        self.swarm = LibtorrentSwarm(
            listen_port=free_port(), listen_host="127.0.0.1", dht=False,
            extra_peers=list(peers), upload_limit=upload_limit,
        )
        self.settings = Settings(
            data_dir=tmp_path / name,
            upstream=upstream_url,
            public_url=f"http://127.0.0.1:{port}",
            **settings,
        )
        self.app = create_app(self.settings, swarm=self.swarm)
        self.srv = Server(self.app, port).start()
        self.url = self.srv.url
        self.store = self.app.state.store
        self.metrics = self.app.state.metrics

    @property
    def endpoint(self):
        return self.swarm.peer_endpoint()

    def served(self) -> int:
        return int(self.metrics.get("thub_bytes_served_total"))

    def stop(self):
        self.srv.stop()


def warm_hub(hub, upstream):
    """Have the hub mirror every file, so it holds the bytes, a torrent for the big one, and is
    seeding it. Tests stop the origin afterwards, so nothing may be left to fetch lazily."""
    for path in upstream.app.state.files:
        assert httpx.get(f"{hub.url}/{REPO}/resolve/main/{path}", timeout=30).status_code == 200
    data = upstream.app.state.files["model.safetensors"]
    sha = hashlib.sha256(data).hexdigest()
    assert hub.store.blob_complete(sha) and hub.store.torrent_path(sha).exists()
    # The client has its bytes slightly before the hub starts seeding them. A peer that connects
    # in that gap is turned away and libtorrent does not retry quickly, so wait for the seed.
    ih = bytes.fromhex(hub.store.get_blob(sha).infohash)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        h = hub.swarm.ses.find_torrent(hub.swarm.lt.sha1_hash(ih))
        if h.is_valid() and h.status().is_seeding:
            time.sleep(0.5)  # observed: a connection in the first instant after this is not served
            break
        time.sleep(0.05)
    else:
        raise AssertionError("hub never started seeding")
    return data, sha


def assert_repo_equals(local, files):
    for path, data in files.items():
        with open(f"{local}/{path}", "rb") as f:
            assert f.read() == data, path


