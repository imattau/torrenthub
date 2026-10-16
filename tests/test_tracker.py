"""The hub as a BitTorrent tracker: peers find each other through it, with nobody told an address."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import os
import time
from urllib.parse import quote_from_bytes

import httpx
import pytest

pytest.importorskip("libtorrent")

from tests.test_publish import BIG, FILES, REPO, Hub, push, run  # noqa: E402
from torrenthub import clientswarm as cs  # noqa: E402
from torrenthub.swarm import LibtorrentSwarm  # noqa: E402
from torrenthub.torrent import bdecode, infohash_from_torrent, torrent_lists  # noqa: E402
from torrenthub.tracker import Tracker, parse_query  # noqa: E402

KEY = hashlib.sha256(BIG).hexdigest()
IH = bytes(range(20))


def peers(resp: bytes) -> list[tuple[str, int]]:
    d = bdecode(resp)
    raw, out = d[b"peers"], []
    for i in range(0, len(raw), 6):
        out.append((str(ipaddress.ip_address(raw[i:i + 4])), int.from_bytes(raw[i + 4:i + 6], "big")))
    return out


class Clock:
    t = 1000.0

    def __call__(self):
        return self.t


# ------------------------------------------------------------------ the tracker's rules

def test_a_peer_gets_the_others_but_not_itself():
    tr = Tracker()
    tr.announce(IH, "10.0.0.1", 6881, b"a" * 20, 0, "started", 50)
    assert peers(tr.announce(IH, "10.0.0.2", 7000, b"b" * 20, 100, "started", 50)) == [("10.0.0.1", 6881)]
    assert peers(tr.announce(IH, "10.0.0.1", 6881, b"a" * 20, 0, "", 50)) == [("10.0.0.2", 7000)]


def test_seeders_come_first_and_numwant_has_a_ceiling():
    tr = Tracker(numwant_max=5)
    for i in range(20):
        tr.announce(IH, f"10.0.1.{i}", 6881, b"x" * 20, 50, "started", 0)  # leechers
    tr.announce(IH, "10.0.2.1", 6881, b"s" * 20, 0, "started", 0)  # one seeder
    got = peers(tr.announce(IH, "10.0.3.1", 6881, b"n" * 20, 100, "started", 1000))
    assert len(got) == 5 and got[0] == ("10.0.2.1", 6881)
    assert peers(tr.announce(IH, "10.0.3.1", 6881, b"n" * 20, 100, "", 2)).__len__() == 2


def test_stopped_removes_and_silence_expires():
    clock = Clock()
    tr = Tracker(interval=100, clock=clock)
    tr.announce(IH, "10.0.0.1", 6881, b"a" * 20, 0, "started", 50)
    tr.announce(IH, "10.0.0.2", 6881, b"b" * 20, 0, "started", 50)
    tr.announce(IH, "10.0.0.2", 6881, b"b" * 20, 0, "stopped", 50)
    assert tr.peers_of(IH) == [("10.0.0.1", 6881)]
    clock.t += tr.ttl + 1
    assert tr.peers_of(IH) == [] and tr.stats()["torrents"] == 0


def test_the_number_of_peers_and_torrents_is_capped():
    tr = Tracker(max_peers=3, max_torrents=2)
    for i in range(10):
        tr.announce(IH, f"10.0.0.{i}", 6881, b"p" * 20, 0, "started", 0)
    assert len(tr.peers_of(IH)) == 3
    tr.announce(b"\x01" * 20, "10.0.9.1", 1, b"p" * 20, 0, "started", 0)
    assert b"failure reason" in tr.announce(b"\x02" * 20, "10.0.9.1", 1, b"p" * 20, 0, "started", 0), "a third torrent does not fit"


def test_addresses_and_ports_that_make_no_sense_are_refused():
    tr = Tracker()
    for ip, port, ih in (("0.0.0.0", 6881, IH), ("224.0.0.1", 6881, IH), ("not an ip", 6881, IH), ("10.0.0.1", 0, IH), ("10.0.0.1", 70000, IH), ("10.0.0.1", 6881, b"short")):
        assert b"failure reason" in tr.announce(ih, ip, port, b"p" * 20, 0, "started", 10), (ip, port)
    assert tr.stats()["peers"] == 0


def test_the_hub_offers_itself_as_a_seed_only_for_torrents_it_holds():
    tr = Tracker()
    tr.self_peer = ("192.0.2.7", 6881)
    assert peers(tr.announce(IH, "10.0.0.1", 7000, b"a" * 20, 100, "started", 50, held_here=True)) == [("192.0.2.7", 6881)]
    assert peers(tr.announce(b"\x09" * 20, "10.0.0.1", 7000, b"a" * 20, 100, "started", 50, held_here=False)) == []
    d = bdecode(tr.announce(IH, "10.0.0.1", 7000, b"a" * 20, 100, "", 50, held_here=True))
    assert d[b"complete"] == 1 and d[b"incomplete"] == 1


def test_ipv6_peers_and_the_non_compact_form():
    tr = Tracker()
    tr.announce(IH, "2001:db8::1", 6881, b"a" * 20, 0, "started", 50)
    d = bdecode(tr.announce(IH, "10.0.0.2", 7000, b"b" * 20, 100, "started", 50))
    assert d[b"peers"] == b"" and len(d[b"peers6"]) == 18
    d = bdecode(tr.announce(IH, "10.0.0.2", 7000, b"b" * 20, 100, "", 50, compact=False))
    assert d[b"peers"] == [{b"ip": b"2001:db8::1", b"port": 6881}]


def test_the_query_keeps_raw_bytes_for_the_hash_and_the_first_of_a_repeat():
    ih = bytes(range(256))[:20]
    q = parse_query(f"info_hash={quote_from_bytes(ih)}&port=1&port=2&peer_id={quote_from_bytes(b'-X-' + bytes(17))}".encode())
    assert q["info_hash"] == ih and q["port"] == b"1" and len(q["peer_id"]) == 20


# ------------------------------------------------------------------ on a hub

@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0)
    run(push(h, tmp_path, FILES))
    yield h
    h.stop()


def ih_of(hub, key=KEY) -> bytes:
    return bytes.fromhex(infohash_from_torrent(hub.store.torrent_path(key).read_bytes()))


def announce(hub, ih, port=6881, **extra):
    q = f"info_hash={quote_from_bytes(ih)}&peer_id={quote_from_bytes(b'-T-' + bytes(17))}&port={port}&left=0&compact=1" + "".join(f"&{k}={v}" for k, v in extra.items())
    return httpx.get(f"{hub.url}/announce?{q}", timeout=10)


def test_the_hub_answers_announces_for_a_torrent_it_holds(hub):
    r = announce(hub, ih_of(hub))
    d = bdecode(r.content)
    assert r.status_code == 200 and d[b"interval"] == 600 and b"failure reason" not in d
    assert hub.app.state.tracker.peers_of(ih_of(hub)) == [("127.0.0.1", 6881)]


def test_a_torrent_the_hub_does_not_hold_is_refused(hub):
    d = bdecode(announce(hub, os.urandom(20)).content)
    assert b"only serves torrents held by this hub" in d[b"failure reason"]
    assert hub.app.state.tracker.stats()["torrents"] == 0, "and nothing was remembered about it"


def test_a_blocked_blob_is_no_longer_announced(hub):
    hub.store.add_block(KEY, "takedown")
    assert b"failure reason" in bdecode(announce(hub, ih_of(hub)).content)


def test_the_ip_a_client_claims_is_ignored(hub):
    announce(hub, ih_of(hub), port=7777, ip="203.0.113.9")
    assert hub.app.state.tracker.peers_of(ih_of(hub)) == [("127.0.0.1", 7777)], "the address is the connection's, so nobody can list someone else"


def test_nonsense_numbers_are_an_answer_not_an_error(hub):
    for q in ("port=abc", "port=0", "port=99999"):
        d = bdecode(httpx.get(f"{hub.url}/announce?info_hash={quote_from_bytes(ih_of(hub))}&{q}&left=0", timeout=10).content)
        assert b"failure reason" in d, q


def test_announcing_is_rate_limited_per_address(tmp_path):
    h = Hub(tmp_path, tracker_per_ip_per_minute=1.0)
    try:
        run(push(h, tmp_path, FILES))
        codes = [announce(h, ih_of(h)).status_code for _ in range(45)]
        assert 429 in codes
    finally:
        h.stop()


def test_a_hub_with_the_tracker_off_says_so(tmp_path):
    h = Hub(tmp_path, tracker=False)
    try:
        run(push(h, tmp_path, FILES))
        assert b"does not run a tracker" in bdecode(announce(h, ih_of(h)).content)[b"failure reason"]
        assert httpx.get(f"{h.url}/api/thub/info", timeout=10).json()["tracker"] is None
        assert torrent_lists(httpx.get(f"{h.url}/torrents/{KEY}.torrent", timeout=10).content)[0] == []
    finally:
        h.stop()


def test_every_torrent_the_hub_hands_out_names_its_tracker_and_keeps_its_infohash(hub):
    served = httpx.get(f"{hub.url}/torrents/{KEY}.torrent", timeout=10).content
    assert f"{hub.url}/announce" in torrent_lists(served)[0]
    assert infohash_from_torrent(served) == infohash_from_torrent(hub.store.torrent_path(KEY).read_bytes()), "the same torrent, so the same swarm"
    assert httpx.get(f"{hub.url}/api/thub/info", timeout=10).json()["tracker"] == f"{hub.url}/announce"


def test_the_stats_endpoint(hub):
    announce(hub, ih_of(hub))
    s = httpx.get(f"{hub.url}/api/thub/tracker", timeout=10).json()
    assert s["enabled"] and s["torrents"] == 1 and s["peers"] == 1 and s["seeders"] == 1


# ------------------------------------------------------------------ finding each other through it

def http_bytes(hub) -> float:
    import re

    m = re.search(r"^thub_bytes_served_total\s+([0-9.e+]+)", httpx.get(f"{hub.url}/metrics", timeout=10).text, re.M)
    return float(m.group(1)) if m else 0.0


def test_a_new_client_finds_a_seeder_through_the_tracker_with_no_address_given_to_it(hub, tmp_path):
    """A downloads from the hub and seeds. The hub stops seeding and stops offering itself. B is given no peer, not the hub's swarm
    port, no web seed and no DHT: the tracker is the only way it can learn that A exists."""
    ih = ih_of(hub)
    # client A: gets the file, keeps the torrent, seeds it
    a_dest = tmp_path / "a" / "objects" / KEY
    cs.fetch_blob(hub.url, KEY, len(BIG), a_dest, tmp_path / "a" / "work", cfg=cs.SwarmConfig(webseed=False, dht=False, stall=10.0),
                  keep_torrent=tmp_path / "a" / "torrents" / f"{KEY}.torrent", say=lambda m: None)
    a_swarm = LibtorrentSwarm(0, listen_host="127.0.0.1", dht=False)
    a_port = a_swarm.ses.listen_port()

    async def seed():
        await a_swarm.seed(tmp_path / "a" / "torrents" / f"{KEY}.torrent", a_dest.parent)

    run(seed())
    try:
        end = time.time() + 20
        while time.time() < end and not any(p[1] == a_port for p in hub.app.state.tracker.peers_of(ih)):
            time.sleep(0.2)
        assert any(p[1] == a_port for p in hub.app.state.tracker.peers_of(ih)), "A announced itself to the hub's tracker"
        run(hub.swarm.forget(hub.store.torrent_path(KEY)))  # the hub stops seeding
        hub.app.state.tracker.self_peer = None  # and stops offering itself as a peer
        before = http_bytes(hub)
        cfg = cs.SwarmConfig(webseed=False, dht=False, hubpeer=False, peers=[], stall=25.0, timeout=60.0)
        out = cs.fetch_blob(hub.url, KEY, len(BIG), tmp_path / "b" / KEY, tmp_path / "b" / "work", cfg=cfg, say=lambda m: None)
        assert out["via"] == "swarm" and (tmp_path / "b" / KEY).read_bytes() == BIG
        assert http_bytes(hub) == before, "not a byte over HTTP: it came from A, whom B found through the tracker"
    finally:
        run(a_swarm.close())


def test_one_address_cannot_fill_a_torrent_with_its_own_ports():
    tr = Tracker(per_ip=4)
    for port in range(7000, 7010):
        tr.announce(IH, "10.0.0.1", port, b"p" * 20, 0, "started", 0)
    assert len(tr.peers_of(IH)) == 4
    tr.announce(IH, "10.0.0.2", 7000, b"q" * 20, 0, "started", 0)
    assert len(tr.peers_of(IH)) == 5, "another address is still welcome"
