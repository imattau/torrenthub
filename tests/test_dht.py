"""Peers finding each other through the DHT, with the hub as a node to start from and no tracker at all."""

from __future__ import annotations

import hashlib
import re
import sys
import time

import httpx
import pytest

pytest.importorskip("libtorrent")

from tests.conftest import free_port  # noqa: E402
from tests.test_publish import BIG, FILES, Hub, push, run  # noqa: E402
from torrenthub import clientswarm as cs  # noqa: E402
from torrenthub.swarm import LibtorrentSwarm  # noqa: E402

KEY = hashlib.sha256(BIG).hexdigest()
LOCAL = dict(dht=True, dht_public=False, dht_local=True, lsd=False)  # lsd off: on one machine, multicast would introduce everyone and hide the DHT  # a DHT of our own on this machine: no public routers, loopback allowed


@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0, tracker=False, dht=True, dht_public=False, dht_local=True, swarm_kw=LOCAL)
    run(push(h, tmp_path, FILES))
    yield h
    h.stop()


def http_bytes(hub) -> float:
    m = re.search(r"^thub_bytes_served_total\s+([0-9.e+]+)", httpx.get(f"{hub.url}/metrics", timeout=10).text, re.M)
    return float(m.group(1)) if m else 0.0


def cfg(**kw):
    base = dict(webseed=False, hubpeer=False, dht=True, dht_public=False, dht_local=True, lsd=False, stall=30.0, timeout=90.0, listen_host="127.0.0.1")
    base.update(kw)
    return cs.SwarmConfig(**base)


def test_the_hub_says_where_its_dht_node_is(hub):
    info = httpx.get(f"{hub.url}/api/thub/info", timeout=10).json()
    assert info["dht"] == {"host": "127.0.0.1", "port": hub.settings.listen_port} and info["tracker"] is None


def test_a_hub_with_the_dht_off_does_not_advertise_one(tmp_path):
    h = Hub(tmp_path, dht=False)
    try:
        assert httpx.get(f"{h.url}/api/thub/info", timeout=10).json()["dht"] is None
    finally:
        h.stop()


def test_a_client_finds_a_seeder_through_the_hubs_dht_node_with_no_tracker_and_no_address(hub, tmp_path):
    """The hub has no tracker. A fetches, keeps the torrent and seeds with a DHT node of its own, bootstrapped from the hub. The hub then
    stops seeding. B has no peer, no hub swarm port, no web seed, no tracker: the DHT is the only way it can learn that A exists."""
    a_dest = tmp_path / "a" / "objects" / KEY
    cs.fetch_blob(hub.url, KEY, len(BIG), a_dest, tmp_path / "a" / "work", cfg=cfg(hubpeer=True, stall=10.0, listen_port=free_port()), keep_torrent=tmp_path / "a" / "torrents" / f"{KEY}.torrent",
                  say=lambda m: None)
    info = httpx.get(f"{hub.url}/api/thub/info", timeout=10).json()
    a = cs.swarm_for(cfg(listen_port=free_port()), info)
    run(a.seed(tmp_path / "a" / "torrents" / f"{KEY}.torrent", a_dest.parent))
    try:
        assert run(a.dht_ready(10.0)), "A's DHT node joined the hub's"
        a.reannounce_all()  # what `torrenthub seed` does once the DHT is up
        time.sleep(2)
        run(hub.swarm.forget(hub.store.torrent_path(KEY)))
        before = http_bytes(hub)
        out = cs.fetch_blob(hub.url, KEY, len(BIG), tmp_path / "b" / KEY, tmp_path / "b" / "work", cfg=cfg(listen_port=free_port()), say=lambda m: None)
        assert out["via"] == "swarm" and (tmp_path / "b" / KEY).read_bytes() == BIG
        assert http_bytes(hub) == before, "not a byte over HTTP: it came from A, whom B found through the DHT"
    finally:
        run(a.close())


def test_without_the_hubs_node_the_same_client_finds_nobody(hub, tmp_path):
    """The control: the same setup with B told to ignore the hub's DHT node cannot find A, so it is that node doing the introducing."""
    a_dest = tmp_path / "a" / "objects" / KEY
    cs.fetch_blob(hub.url, KEY, len(BIG), a_dest, tmp_path / "a" / "work", cfg=cfg(hubpeer=True, stall=10.0, listen_port=free_port()), keep_torrent=tmp_path / "a" / "torrents" / f"{KEY}.torrent",
                  say=lambda m: None)
    info = httpx.get(f"{hub.url}/api/thub/info", timeout=10).json()
    a = cs.swarm_for(cfg(listen_port=free_port()), info)
    run(a.seed(tmp_path / "a" / "torrents" / f"{KEY}.torrent", a_dest.parent))
    try:
        time.sleep(4)
        run(hub.swarm.forget(hub.store.torrent_path(KEY)))
        before = http_bytes(hub)
        out = cs.fetch_blob(hub.url, KEY, len(BIG), tmp_path / "b" / KEY, tmp_path / "b" / "work", cfg=cfg(hubdht=False, stall=6.0, listen_port=free_port()), say=lambda m: None)
        assert out["via"] == "web" and http_bytes(hub) > before, "B fell back to HTTP because the DHT had nobody to introduce"
    finally:
        run(a.close())


# ------------------------------------------------------------------ the settings reach libtorrent

def test_the_client_settings_become_libtorrent_settings():
    sw = cs.swarm_for(cs.SwarmConfig(dht=True, dht_public=False, dht_local=True, upnp=True, dht_nodes=[("127.0.0.1", 1)]), None)
    s = sw.ses.get_settings()
    assert s["enable_upnp"] and s["enable_natpmp"] and s["dht_bootstrap_nodes"] == "" and s["dht_restrict_routing_ips"] is False
    plain = cs.swarm_for(cs.SwarmConfig(), None).ses.get_settings()
    assert not plain["enable_upnp"] and not plain["enable_natpmp"] and plain["dht_restrict_routing_ips"] is True, "the defaults are the cautious ones"


def test_dht_off_means_no_dht_nodes_and_no_local_discovery():
    s = cs.swarm_for(cs.SwarmConfig(dht=False, dht_nodes=[("127.0.0.1", 1)]), {"dht": {"host": "127.0.0.1", "port": 2}}).ses.get_settings()
    assert s["enable_dht"] is False and s["enable_lsd"] is False
    assert cs.swarm_for(cs.SwarmConfig(dht=True, lsd=False), None).ses.get_settings()["enable_lsd"] is False
    assert cs.swarm_for(cs.SwarmConfig(dht=False, lsd=True), None).ses.get_settings()["enable_lsd"] is True


def test_the_hubs_node_is_used_unless_told_not_to():
    seen = []

    class Spy(LibtorrentSwarm):
        def __init__(self, *a, dht_nodes=None, **k):
            seen.append(list(dht_nodes or []))
            super().__init__(*a, dht_nodes=dht_nodes, **k)

    import torrenthub.swarm as sw

    real = sw.LibtorrentSwarm
    sw.LibtorrentSwarm = Spy
    try:
        info = {"dht": {"host": "10.1.1.1", "port": 6881}}
        cs.swarm_for(cs.SwarmConfig(dht_nodes=[("10.2.2.2", 7)]), info)
        cs.swarm_for(cs.SwarmConfig(hubdht=False), info)
        cs.swarm_for(cs.SwarmConfig(dht=False), info)
    finally:
        sw.LibtorrentSwarm = real
    assert seen == [[("10.2.2.2", 7), ("10.1.1.1", 6881)], [], []]


def test_the_settings_come_from_git_config_and_the_environment(tmp_path, monkeypatch):
    import subprocess

    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "--add", "thub.dhtnode", "10.0.0.9:6881"], cwd=repo, check=True)
    subprocess.run(["git", "config", "thub.upnp", "true"], cwd=repo, check=True)
    c = cs.config_from_env(repo)
    assert c.dht_nodes == [("10.0.0.9", 6881)] and c.upnp is True and c.dht_public is True and c.dht_local is False and c.hubdht is True
    monkeypatch.setenv("THUB_CLIENT_DHT_PUBLIC", "0")
    monkeypatch.setenv("THUB_CLIENT_DHT_LOCAL", "1")
    monkeypatch.setenv("THUB_CLIENT_HUBDHT", "0")
    monkeypatch.setenv("THUB_DHT_NODES", "1.2.3.4:5")
    c = cs.config_from_env(repo)
    assert c.dht_public is False and c.dht_local is True and c.hubdht is False and ("1.2.3.4", 5) in c.dht_nodes


def test_a_session_asked_for_any_port_is_given_a_concrete_one():
    """libtorrent's DHT does not work on a session told to listen on port 0 (found on the VMs: a plain clone listened on port 0 and
    never found anyone, while the same code on a fixed port did). So "any port" is turned into a free one before the session starts."""
    from torrenthub.swarm import free_port

    sw = LibtorrentSwarm(0, "127.0.0.1", dht=True, dht_public=False, dht_local=True, lsd=False)
    try:
        spec = sw.ses.get_settings()["listen_interfaces"]
        assert spec.startswith("127.0.0.1:") and not spec.endswith(":0"), spec
    finally:
        run(sw.close())
    ports = {free_port("127.0.0.1") for _ in range(5)}
    assert all(0 < p < 65536 for p in ports)


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="listing the machine's addresses is Linux only; elsewhere the wildcard address is used as before")
def test_a_wildcard_listen_address_becomes_the_machines_addresses_when_the_dht_is_on():
    """The DHT answers nobody when the session listens on 0.0.0.0 on a machine with several interfaces; listing the addresses fixes it."""
    from torrenthub.swarm import local_ipv4_addresses

    addrs = local_ipv4_addresses()
    assert "127.0.0.1" in addrs
    with_dht = LibtorrentSwarm(0, "0.0.0.0", dht=True, lsd=False)
    without = LibtorrentSwarm(0, "0.0.0.0", dht=False)
    pinned = LibtorrentSwarm(0, "127.0.0.1", dht=True, lsd=False)
    try:
        spec = with_dht.ses.get_settings()["listen_interfaces"].split(",")
        assert sorted(s.rsplit(":", 1)[0] for s in spec) == sorted(addrs) and len({s.rsplit(":", 1)[1] for s in spec}) == 1, spec
        assert without.ses.get_settings()["listen_interfaces"].startswith("0.0.0.0:"), "without the DHT the wildcard is left alone"
        assert pinned.ses.get_settings()["listen_interfaces"].startswith("127.0.0.1:") and "," not in pinned.ses.get_settings()["listen_interfaces"], "an address you chose is left alone"
    finally:
        for s in (with_dht, without, pinned):
            run(s.close())
