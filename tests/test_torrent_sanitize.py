"""A torrent someone else made is used for its content definition only."""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import threading
import time

import pytest

from torrenthub.torrent import (
    PieceHasher, TorrentRejected, bdecode, bencode, build_torrent, choose_piece_length, infohash_from_torrent, sanitize_torrent,
    validate_torrent,
)


def make(trackers=(), webseeds=(), size=1_300_000):
    data = os.urandom(size)
    key = hashlib.sha256(data).hexdigest()
    ph = PieceHasher(choose_piece_length(size))
    ph.update(data)
    t, ih = build_torrent(name=key, length=size, piece_length=choose_piece_length(size), pieces=ph.finish(),
                          trackers=list(trackers), webseeds=list(webseeds), comment="mine")
    return t, ih, key, size


def hostile(base: bytes) -> bytes:
    meta = bdecode(base)
    meta.update({b"announce": b"http://10.0.0.5/announce", b"announce-list": [[b"udp://169.254.169.254:80"], [b"http://127.0.0.1:9/announce"]],
                 b"nodes": [[b"192.168.1.1", 6881]], b"url-list": [b"http://internal.example/secret"], b"httpseeds": [b"http://internal.example/h"],
                 b"x-extra": b"y" * 1000, b"created by": b"attacker", b"comment": b"c" * 500})
    return bencode(meta)


def test_everything_but_the_info_dictionary_is_dropped_and_the_infohash_is_unchanged():
    t, ih, key, size = make()
    evil = hostile(t)
    clean = sanitize_torrent(evil)
    assert bdecode(clean).keys() == {b"info"}
    assert infohash_from_torrent(clean) == infohash_from_torrent(evil) == ih
    validate_torrent(clean, key, size)
    lt = pytest.importorskip("libtorrent")
    assert lt.torrent_info(clean).info_hashes().v1.to_bytes().hex() == ih == lt.torrent_info(evil).info_hashes().v1.to_bytes().hex()


def test_only_the_callers_trackers_and_web_seeds_are_added():
    t, ih, key, size = make()
    clean = sanitize_torrent(hostile(t), ["udp://tracker.example:1337/announce", "http://t2.example/announce"], ["https://hub.example/blobs/x"])
    meta = bdecode(clean)
    assert set(meta) == {b"info", b"announce", b"announce-list", b"url-list"}
    assert meta[b"announce"] == b"udp://tracker.example:1337/announce"
    assert meta[b"announce-list"] == [[b"udp://tracker.example:1337/announce"], [b"http://t2.example/announce"]]
    assert meta[b"url-list"] == [b"https://hub.example/blobs/x"]
    assert infohash_from_torrent(clean) == ih
    lt = pytest.importorskip("libtorrent")
    ti = lt.torrent_info(clean)
    assert [x.url for x in ti.trackers()] == ["udp://tracker.example:1337/announce", "http://t2.example/announce"]
    assert ti.web_seeds()[0]["url"] == "https://hub.example/blobs/x"
    assert infohash_from_torrent(sanitize_torrent(clean)) == ih, "idempotent"


def test_a_non_canonical_info_dictionary_is_refused():
    t, ih, key, size = make()
    info = bdecode(t)[b"info"]
    # the same dictionary with its keys out of order: it hashes differently depending on who encodes it
    items = list(info.items())
    reordered = b"d" + b"".join(bencode(k) + bencode(v) for k, v in reversed(items)) + b"e"
    bad = b"d4:info" + reordered + b"e"
    with pytest.raises(TorrentRejected, match="canonical"):
        sanitize_torrent(bad)


@pytest.mark.parametrize("data", [
    b"", b"x", b"le", b"d", b"de", b"d4:infoe", b"d4:infoi5ee", b"d4:info" + b"d" * 3 + b"e" * 3 + b"e",
    b"d4:info" + b"l" * 50_000 + b"e" * 50_000 + b"e",          # nested far past the recursion limit
    b"d4:infod1:ai1eeei1e", b"d4:infod1:ai1ee" + b"e" * 10,
    b"d" + b"1:a" + b"i" + b"9" * 6000 + b"e" + b"e",            # an integer too long to convert
])
def test_malformed_and_hostile_encodings_are_rejected_cleanly(data):
    with pytest.raises(TorrentRejected):
        sanitize_torrent(data)


def test_oversize_input_is_refused_before_parsing():
    with pytest.raises(TorrentRejected, match="too large"):
        sanitize_torrent(b"d" + b"1:a" + b"0:" * 3_000_000 + b"e")


def test_a_swarm_session_started_from_a_sanitized_torrent_contacts_nobody(tmp_path):
    pytest.importorskip("libtorrent")
    from torrenthub.swarm import LibtorrentSwarm

    hits = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    deadline = time.time() + 7

    def serve():
        srv.settimeout(0.5)
        while time.time() < deadline:
            try:
                c, _ = srv.accept()
                hits.append(c.recv(2048).split(b"\r\n")[0])
                c.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    t, ih, key, size = make(trackers=[f"http://127.0.0.1:{port}/announce"])

    async def run(torrent: bytes) -> None:
        (tmp_path / "w.torrent").write_bytes(torrent)
        sw = LibtorrentSwarm(0, listen_host="127.0.0.1", dht=False)
        await sw.start(tmp_path / "w.torrent", tmp_path)
        await asyncio.sleep(3.5)
        await sw.close()

    asyncio.run(run(t))
    assert any(b"/announce" in h for h in hits), "control: the raw torrent does make the session call the tracker"
    hits.clear()
    asyncio.run(run(sanitize_torrent(t)))
    srv.close()
    assert hits == [], "a sanitized torrent makes no request"
