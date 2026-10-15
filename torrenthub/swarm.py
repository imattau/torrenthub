"""BitTorrent swarm adapters.

The gateway talks to a Swarm interface so the HTTP side can be tested without a
torrent engine. LibtorrentSwarm is the real implementation.

Blob files are stored as blobs/<aa>/<key> and the torrent name is <key>, so the
blob directory is the libtorrent save path and no copying or renaming is needed.

A swarm download is a handle the gateway polls. It reports how many bytes from the start
of the file are complete, and libtorrent has already checked each of those pieces against
the SHA-1 hashes in the torrent. That is what lets the gateway stream to a client while the
download is still running.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path


class SwarmDownload:
    def prefix_bytes(self) -> int:
        """Bytes from the start of the file whose pieces are complete and hash-checked."""
        return 0

    def complete(self) -> bool:
        return False

    def peers(self) -> int:
        return 0

    def snapshot(self) -> dict:
        """Bytes libtorrent has downloaded (checked or not), its download rate and peer count."""
        return {}

    def cancel(self) -> None:
        """Stop downloading. Does not delete files."""


class Swarm:
    enabled = False

    async def seed(self, torrent_path: Path, save_dir: Path) -> None:
        """Start seeding a blob that is already complete and verified on disk."""

    async def forget(self, torrent_path: Path) -> None:
        """Stop tracking a torrent, for example after its bytes are evicted."""

    async def start(self, torrent_path: Path, save_dir: Path) -> SwarmDownload | None:
        """Begin downloading in file order. None means this swarm cannot download."""
        return None

    async def fetch(self, torrent_path: Path, save_dir: Path, timeout: float) -> bool:
        """Download to completion or give up. Mostly for tests and tools."""
        dl = await self.start(torrent_path, save_dir)
        if dl is None:
            return False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if dl.complete():
                return True
            await asyncio.sleep(0.2)
        dl.cancel()
        return False

    async def stats(self) -> dict:
        return {}

    async def close(self) -> None:
        pass


class NullSwarm(Swarm):
    pass


class _LtDownload(SwarmDownload):
    def __init__(self, lt, session, handle, info):
        self._lt = lt
        self._ses = session
        self._h = handle
        self._n = info.num_pieces()
        self._piece_len = info.piece_length()
        self._total = info.total_size()
        self._cursor = 0

    def prefix_bytes(self) -> int:
        while self._cursor < self._n and self._h.have_piece(self._cursor):
            self._cursor += 1
        return min(self._cursor * self._piece_len, self._total)

    def complete(self) -> bool:
        st = self._h.status()
        return bool(st.is_seeding or st.is_finished)

    def peers(self) -> int:
        return self._h.status().num_peers

    def snapshot(self) -> dict:
        st = self._h.status()
        return {"done": st.total_done, "rate": st.download_rate, "peers": st.num_peers}

    def cancel(self) -> None:
        if self._h.is_valid():
            self._ses.remove_torrent(self._h)


class LibtorrentSwarm(Swarm):
    enabled = True

    def __init__(
        self,
        listen_port: int = 6881,
        listen_host: str = "0.0.0.0",
        extra_peers: list[tuple[str, int]] | None = None,
        dht: bool = True,
        upload_limit: int = 0,
        outgoing_utp: bool = False,
    ):
        import libtorrent as lt

        self.lt = lt
        # Static peer hints, for example sibling gateways. Useful when DHT and trackers
        # are unavailable (private deployments, tests).
        self.extra_peers = extra_peers or []
        settings = {
            "listen_interfaces": f"{listen_host}:{listen_port}",
            "enable_dht": dht,
            "enable_lsd": dht,
            "enable_upnp": False,
            "enable_natpmp": False,
            "allow_multiple_connections_per_ip": True,
            # libtorrent dials over uTP (UDP) first by default. Between two machines on a fast
            # link that measured about 20 MB/s against 350 MB/s over TCP, so dial TCP. Incoming
            # uTP stays on, so peers that prefer it can still reach us.
            "enable_outgoing_utp": outgoing_utp,
        }
        if upload_limit:
            settings["upload_rate_limit"] = upload_limit
            # Loopback counts as a local network, which libtorrent exempts from limits by default.
            settings["ignore_limits_on_local_network"] = False
        self.ses = lt.session(settings)

    def _hint_peers(self, handle) -> None:
        for host, port in self.extra_peers:
            handle.connect_peer((host, port))

    def _params(self, torrent_path: Path, save_dir: Path):
        atp = self.lt.add_torrent_params()
        atp.ti = self.lt.torrent_info(str(torrent_path))
        atp.save_path = str(save_dir)
        return atp

    def _existing(self, atp):
        h = self.ses.find_torrent(atp.ti.info_hashes().v1)
        return h if h.is_valid() else None

    async def seed(self, torrent_path: Path, save_dir: Path) -> None:
        atp = self._params(torrent_path, save_dir)
        if self._existing(atp):
            return
        # The blob was hash-verified at ingest, so skip the full recheck on startup.
        atp.flags |= self.lt.torrent_flags.seed_mode
        self.ses.add_torrent(atp)

    async def connect(self, torrent_path: Path, host: str, port: int) -> bool:
        """Dial a peer for a torrent we already hold. For a publisher behind NAT this is how the
        hub gets the bytes: the connection goes out, so no open port is needed. True if the
        torrent is known to the session."""
        h = self.ses.find_torrent(self.lt.torrent_info(str(torrent_path)).info_hashes().v1)
        if not h.is_valid():
            return False
        h.connect_peer((host, port))
        return True

    async def forget(self, torrent_path: Path) -> None:
        ti = self.lt.torrent_info(str(torrent_path))
        h = self.ses.find_torrent(ti.info_hashes().v1)
        if h.is_valid():
            self.ses.remove_torrent(h)

    def peer_endpoint(self) -> tuple[str, int]:
        return ("127.0.0.1", self.ses.listen_port())

    async def start(self, torrent_path: Path, save_dir: Path) -> SwarmDownload | None:
        atp = self._params(torrent_path, save_dir)
        stale = self._existing(atp)
        if stale:  # for example a seeding entry whose bytes were evicted
            self.ses.remove_torrent(stale)
        atp.flags |= self.lt.torrent_flags.sequential_download
        handle = self.ses.add_torrent(atp)
        self._hint_peers(handle)
        return _LtDownload(self.lt, self.ses, handle, atp.ti)

    async def stats(self) -> dict:
        torrents = self.ses.get_torrents()
        return {"torrents": len(torrents), "dht_nodes": self.ses.status().dht_nodes}

    async def close(self) -> None:
        self.ses.pause()


def parse_peers(items: list[str]) -> list[tuple[str, int]]:
    peers = []
    for item in items:
        host, sep, port = item.rpartition(":")
        if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError(f"THUB_PEERS entry {item!r}: expected host:port")
        peers.append((host.strip("[]"), int(port)))
    return peers


def make_swarm(kind: str, listen_port: int, peers: list[str] | None = None, outgoing_utp: bool = False) -> Swarm:
    if kind == "libtorrent":
        return LibtorrentSwarm(listen_port, extra_peers=parse_peers(peers or []), outgoing_utp=outgoing_utp)
    return NullSwarm()
