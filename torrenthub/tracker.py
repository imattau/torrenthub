"""The hub's own BitTorrent tracker (BEP 3, HTTP, compact peer lists), so peers find each other
through the hub without being told anyone's address.

What it does: a client that joins a torrent announces itself (its port, whether it is seeding), and
gets back some of the others who announced the same torrent. A clone that comes up later finds the
clone that finished earlier and is seeding.

What it is careful about, because a tracker is a list of addresses that other machines will connect to:

  * It answers only for torrents this hub holds. It is not an open tracker for anyone's swarm.
  * The address it records is the one the connection came from. A client's `ip=` parameter is ignored,
    so nobody can put someone else's address into the list and send traffic at them.
  * Entries expire, the number of peers per torrent, of entries one address may hold for a torrent, and of torrents and entries in all is capped, an announce is limited
    per address (the app's rate limit), and `numwant` has a ceiling.
  * Unspecified and multicast addresses are refused.

What it does not do: authenticate anyone, hide who is downloading what from the hub, or help two peers
that cannot reach each other (both behind NAT, with no port mapping): it hands out addresses, it does not
punch holes.
"""

from __future__ import annotations

import ipaddress
import random
import socket
import threading
import time
from urllib.parse import unquote_to_bytes

from .torrent import bencode

EVENTS = {"", "started", "stopped", "completed"}


class Tracker:
    def __init__(self, interval: int = 600, min_interval: int = 60, max_peers: int = 300, max_torrents: int = 100_000,
                 numwant_max: int = 60, per_ip: int = 4, max_total: int = 1_000_000, clock=time.time):
        self.interval, self.min_interval = interval, min_interval
        self.ttl = interval * 2 + 60  # a peer that missed two announces is gone
        self.max_peers, self.max_torrents, self.numwant_max = max_peers, max_torrents, numwant_max
        self.per_ip, self.max_total = per_ip, max_total
        self.clock = clock
        self._t: dict[bytes, dict[tuple[str, int], list]] = {}  # infohash -> (ip, port) -> [last seen, seeding, peer id]
        self._lock = threading.Lock()
        self.self_peer: tuple[str, int] | None = None  # this hub's own swarm endpoint, offered as a seed for torrents it holds

    # ------------------------------------------------------------------ announcing
    def announce(self, infohash: bytes, ip: str, port: int, peer_id: bytes, left: int | None, event: str, numwant: int,
                 compact: bool = True, held_here: bool = False) -> bytes:
        """The bencoded answer to one announce. `held_here` says this hub holds the torrent complete (the caller checked)."""
        if len(infohash) != 20:
            return self.failure("info_hash must be 20 bytes")
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return self.failure("cannot tell your address")
        if addr.is_unspecified or addr.is_multicast:
            return self.failure("that address cannot be a peer")
        if not 0 < port < 65536:
            return self.failure("port out of range")
        event = event if event in EVENTS else ""
        now = self.clock()
        with self._lock:
            peers = self._t.get(infohash)
            if peers is None:
                if len(self._t) >= self.max_torrents:
                    self._sweep(now)
                    if len(self._t) >= self.max_torrents:
                        return self.failure("the tracker is full")
                peers = self._t.setdefault(infohash, {})
            self._expire(peers, now)
            key = (str(addr), port)
            if event == "stopped":
                peers.pop(key, None)
            elif key in peers:
                peers[key] = [now, left == 0, peer_id[:20]]
            elif len(peers) < self.max_peers and sum(1 for k in peers if k[0] == key[0]) < self.per_ip and self._total_locked() < self.max_total:
                peers[key] = [now, left == 0, peer_id[:20]]
            numwant = max(0, min(numwant, self.numwant_max))
            others = [(k, v) for k, v in peers.items() if k != key]
            seeders = [k for k, v in others if v[1]]
            leechers = [k for k, v in others if not v[1]]
            random.shuffle(seeders)
            random.shuffle(leechers)
            chosen = (seeders + leechers)[:numwant]
            if held_here and self.self_peer and self.self_peer != key and self.self_peer not in chosen and numwant:
                chosen = [self.self_peer] + chosen[: numwant - 1]
            complete = sum(1 for v in peers.values() if v[1]) + (1 if held_here and self.self_peer else 0)
            incomplete = sum(1 for v in peers.values() if not v[1])
            if not peers:
                self._t.pop(infohash, None)
        body: dict = {"interval": self.interval, "min interval": self.min_interval, "complete": complete, "incomplete": incomplete}
        if compact:
            v4, v6 = b"", b""
            for ip_s, p in chosen:
                a = ipaddress.ip_address(ip_s)
                if a.version == 4:
                    v4 += a.packed + p.to_bytes(2, "big")
                else:
                    v6 += a.packed + p.to_bytes(2, "big")
            body["peers"] = v4
            if v6:
                body["peers6"] = v6
        else:
            body["peers"] = [{"ip": ip_s, "port": p} for ip_s, p in chosen]
        return bencode(body)

    @staticmethod
    def failure(reason: str) -> bytes:
        return bencode({"failure reason": reason})

    # ------------------------------------------------------------------ housekeeping
    def _expire(self, peers: dict, now: float) -> None:
        for k in [k for k, v in peers.items() if now - v[0] > self.ttl]:
            del peers[k]

    def _sweep(self, now: float) -> None:
        for ih in list(self._t):
            self._expire(self._t[ih], now)
            if not self._t[ih]:
                del self._t[ih]

    def _total_locked(self) -> int:
        return sum(len(p) for p in self._t.values())

    def stats(self) -> dict:
        with self._lock:
            self._sweep(self.clock())
            return {"torrents": len(self._t), "peers": sum(len(p) for p in self._t.values()),
                    "seeders": sum(1 for p in self._t.values() for v in p.values() if v[1])}

    def peers_of(self, infohash: bytes) -> list[tuple[str, int]]:
        with self._lock:
            peers = self._t.get(infohash, {})
            self._expire(peers, self.clock())
            return sorted(peers)


def parse_query(raw: bytes) -> dict[str, bytes]:
    """The announce query as bytes: info_hash and peer_id are raw bytes, not text. Repeats keep the first."""
    out: dict[str, bytes] = {}
    for part in raw.split(b"&"):
        k, _, v = part.partition(b"=")
        name = k.decode("latin-1")
        if name and name not in out:
            out[name] = unquote_to_bytes(v.replace(b"+", b" ")) if name not in ("info_hash", "peer_id") else unquote_to_bytes(v)
    return out


def own_endpoint(public_url: str, port: int) -> tuple[str, int] | None:
    """This hub's address for peers, if its public URL names one we can resolve to an IPv4 address."""
    from urllib.parse import urlsplit

    host = urlsplit(public_url).hostname
    if not host or not 0 < port < 65536:
        return None
    try:
        return str(ipaddress.ip_address(host)), port
    except ValueError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0], port
    except OSError:
        return None
