from __future__ import annotations

import socket
import threading
import time

import pytest
import uvicorn

from tests.fake_upstream import build_app as build_fake
from torrenthub.app import create_app
from torrenthub.config import Settings


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, app, port: int):
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture()
def upstream():
    app = build_fake()
    srv = Server(app, free_port()).start()
    srv.app = app
    yield srv
    if srv.thread.is_alive():
        srv.stop()


@pytest.fixture()
def gateway(upstream, tmp_path):
    port = free_port()
    settings = Settings(
        data_dir=tmp_path / "data",
        upstream=upstream.url,
        public_url=f"http://127.0.0.1:{port}",
        trackers=["udp://tracker.example.org:1337/announce"],
        ref_ttl=0.0,  # always re-check upstream when it is reachable
    )
    app = create_app(settings)
    srv = Server(app, port).start()
    srv.settings = settings
    srv.app = app
    yield srv
    srv.stop()


@pytest.fixture()
def nodes(tmp_path):
    """Factory for real gateways with their own libtorrent session. All are stopped afterwards."""
    pytest.importorskip("libtorrent")
    from tests.helpers import Node

    made = []

    def make(name, upstream_url, **kw):
        n = Node(tmp_path, name, upstream_url, **kw)
        made.append(n)
        return n

    yield make
    for n in made:
        if n.srv.thread.is_alive():
            n.stop()
