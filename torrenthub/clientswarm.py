"""Fetching a blob the way the rest of torrenthub does: over BitTorrent first (client side).

The filter, `pull-files` and the git remote helper use this. For a blob named by its sha256:

  1. take the torrent from the hub (a few hundred bytes; the hub is only asked for metadata),
  2. check it is a torrent for exactly this blob (and, when a signed manifest named the infohash,
     that it is that one),
  3. join the swarm: trackers and DHT as configured, the hub's own swarm port as one direct peer,
     any peers named in `thub.peer` / THUB_PEERS, and the hub's web seed as a last resort inside
     libtorrent itself,
  4. if nothing arrives for `stall` seconds, or the swarm has no peer, fall back to plain HTTP from the hub,
  5. in every case hash the whole file; keep it only if it is the sha256 asked for.

What this does not do: it does not make peers appear. With no tracker, no DHT peer and no hint, the
only peer is the hub, which is where HTTP would have gone anyway.

Configuration (git config first, then the environment):
  thub.swarm / THUB_CLIENT_SWARM=0     turn the swarm off (HTTP only)
  thub.peer (repeatable) / THUB_PEERS  host:port of peers to try directly
  thub.tracker (repeatable) / THUB_TRACKERS   extra trackers
  thub.dht / THUB_CLIENT_DHT=0         turn DHT and local discovery off
  thub.webseed / THUB_CLIENT_WEBSEED=0 do not give libtorrent the hub's web seed (so only peers count)
  thub.dhtnode (repeatable) / THUB_DHT_NODES  DHT nodes to bootstrap from; thub.hubdht / THUB_CLIENT_HUBDHT=0 ignore the hub's own
  thub.dhtpublic / THUB_CLIENT_DHT_PUBLIC=0   do not use the public bootstrap routers; thub.dhtlocal / THUB_CLIENT_DHT_LOCAL=1 accept private DHT nodes
  thub.listenHost / THUB_CLIENT_LISTEN_HOST   address to listen on (default 0.0.0.0)
  thub.lsd / THUB_CLIENT_LSD=0         turn off local service discovery (multicast on the LAN); by default it follows thub.dht
  thub.upnp / THUB_CLIENT_UPNP=1       ask the router to forward the listen port (UPnP, NAT-PMP)
  thub.hubpeer / THUB_CLIENT_HUBPEER=0 do not offer the hub's swarm port as a direct peer (so trackers, DHT and hints do the finding)
  thub.swarmTimeout, thub.swarmStall / THUB_CLIENT_TIMEOUT, THUB_CLIENT_STALL   seconds
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from .gitrepo import GitError
from .torrent import TorrentRejected, bdecode, infohash_from_torrent, sanitize_torrent, validate_torrent

CHUNK = 1 << 20


@dataclass
class SwarmConfig:
    enabled: bool = True
    peers: list = field(default_factory=list)  # (host, port)
    trackers: list = field(default_factory=list)
    dht: bool = True
    webseed: bool = True
    dht_nodes: list = field(default_factory=list)  # (host, port) of DHT nodes to bootstrap from, besides the hub's
    dht_public: bool = True  # also use the public bootstrap routers
    dht_local: bool = False  # accept private and loopback DHT nodes
    upnp: bool = False  # ask the router to forward the listen port (UPnP and NAT-PMP)
    hubdht: bool = True  # bootstrap from the hub's own DHT node
    lsd: bool | None = None  # local service discovery (multicast on the LAN); None follows dht
    hubpeer: bool = True  # offer the hub's own swarm port as a peer; off, only trackers, DHT and hints find peers
    timeout: float = 3600.0
    stall: float = 30.0
    listen_port: int = 0
    listen_host: str = "0.0.0.0"


def _git_values(key: str, cwd=None) -> list[str]:
    r = subprocess.run(["git", "config", "--get-all", key], cwd=cwd, capture_output=True, text=True)
    return [v for v in r.stdout.splitlines() if v] if r.returncode == 0 else []


def _flag(git_key: str, env_key: str, default: bool, cwd=None) -> bool:
    env = os.environ.get(env_key)
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off")
    vals = _git_values(git_key, cwd)
    return vals[-1].strip().lower() not in ("0", "false", "no", "off") if vals else default


def _lsd(cwd) -> bool | None:
    env = os.environ.get("THUB_CLIENT_LSD")
    if env is not None:
        return env.strip().lower() not in ("0", "false", "no", "off")
    vals = _git_values("thub.lsd", cwd)
    return vals[-1].strip().lower() not in ("0", "false", "no", "off") if vals else None


def parse_peers(items) -> list[tuple[str, int]]:
    out = []
    for item in items:
        host, sep, port = item.strip().rpartition(":")
        if sep and host and port.isdigit() and 0 < int(port) < 65536:
            out.append((host.strip("[]"), int(port)))
    return out


def config_from_env(cwd=None) -> SwarmConfig:
    peers = _git_values("thub.peer", cwd) + os.environ.get("THUB_PEERS", "").replace(",", " ").split()
    trackers = _git_values("thub.tracker", cwd) + os.environ.get("THUB_TRACKERS", "").replace(",", " ").split()
    num = lambda k, env, d: float(os.environ.get(env) or (_git_values(k, cwd) or [d])[-1])
    return SwarmConfig(enabled=_flag("thub.swarm", "THUB_CLIENT_SWARM", True, cwd), peers=parse_peers(peers), trackers=trackers,
                       dht=_flag("thub.dht", "THUB_CLIENT_DHT", True, cwd), webseed=_flag("thub.webseed", "THUB_CLIENT_WEBSEED", True, cwd),
                       hubpeer=_flag("thub.hubpeer", "THUB_CLIENT_HUBPEER", True, cwd),
                       hubdht=_flag("thub.hubdht", "THUB_CLIENT_HUBDHT", True, cwd), dht_public=_flag("thub.dhtpublic", "THUB_CLIENT_DHT_PUBLIC", True, cwd),
                       dht_local=_flag("thub.dhtlocal", "THUB_CLIENT_DHT_LOCAL", False, cwd), lsd=_lsd(cwd), upnp=_flag("thub.upnp", "THUB_CLIENT_UPNP", False, cwd),
                       dht_nodes=parse_peers(_git_values("thub.dhtnode", cwd) + os.environ.get("THUB_DHT_NODES", "").replace(",", " ").split()),
                       timeout=num("thub.swarmTimeout", "THUB_CLIENT_TIMEOUT", "3600"), stall=num("thub.swarmStall", "THUB_CLIENT_STALL", "30"),
                       listen_host=(os.environ.get("THUB_CLIENT_LISTEN_HOST") or (_git_values("thub.listenHost", cwd) or ["0.0.0.0"])[-1]))


def _say(msg: str) -> None:
    print(f"thub: {msg}", file=sys.stderr, flush=True)


def _hash(path: Path) -> tuple[str, int]:
    h, n = hashlib.sha256(), 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def fetch_blob(hub: str, key: str, size: int, dest: Path, work: Path, *, infohash: str | None = None, cfg: SwarmConfig | None = None,
               keep_torrent: Path | None = None, say=_say) -> dict:
    """Get blob `key` (a sha256) of `size` bytes into `dest`. Returns {"via": "swarm"|"web", ...}.
    Raises GitError if nothing could produce the right bytes."""
    cfg = cfg or SwarmConfig()
    hub = hub.rstrip("/")
    work = Path(work)
    work.mkdir(parents=True, exist_ok=True)
    if cfg.enabled:
        try:
            got = asyncio.run(_via_swarm(hub, key, size, dest, work, infohash, cfg, keep_torrent, say))
            if got:
                return got
        except (TorrentRejected, httpx.HTTPError, OSError, RuntimeError) as e:
            say(f"the swarm could not be used for {key[:12]} ({type(e).__name__}: {e}); asking the hub over HTTP")
    _via_http(hub, key, size, dest, work)
    return {"via": "web"}


async def _via_swarm(hub, key, size, dest, work, infohash, cfg, keep_torrent, say) -> dict | None:
    with httpx.Client(timeout=30, follow_redirects=True) as c:
        r = c.get(f"{hub}/torrents/{key}.torrent")
        if r.status_code != 200:
            return None
        raw = r.content
        try:
            info = c.get(f"{hub}/api/thub/info").json()
        except (httpx.HTTPError, ValueError):
            info = {}
    validate_torrent(raw, key, size)
    if infohash and infohash_from_torrent(raw) != infohash:
        raise TorrentRejected("the torrent is not the one the signed manifest names")
    trackers = list(dict.fromkeys([*cfg.trackers, *_trackers_of(raw)]))
    peers = list(cfg.peers)
    port = (info.get("swarm") or {}).get("port")
    host = urlsplit(hub).hostname
    if port and host and cfg.hubpeer:
        peers.append((host, int(port)))
    torrent = work / f"{key}.torrent"
    torrent.write_bytes(sanitize_torrent(raw, trackers, [f"{hub}/blobs/{key}"] if cfg.webseed else []))
    target = work / key
    target.unlink(missing_ok=True)
    swarm = swarm_for(cfg, info, peers)
    try:
        if cfg.dht:
            await swarm.dht_ready(5.0)
        dl = await swarm.start(torrent, work)
        say(f"fetching {key[:12]} ({size:,} bytes) from the swarm: {len(peers)} peer hint(s), {len(trackers)} tracker(s)")
        start = last_move = last_nudge = time.monotonic()
        seen = -1
        while not dl.complete():
            snap = dl.snapshot()
            if snap.get("done", 0) != seen:
                seen, last_move = snap.get("done", 0), time.monotonic()
            now = time.monotonic()
            if now - last_move > 5 and now - last_nudge > 5 and dl.peers() == 0:
                dl.nudge()  # nobody yet: ask the trackers and the DHT again
                last_nudge = now
            if now - last_move > cfg.stall or now - start > cfg.timeout:
                dl.cancel()
                say(f"nothing arrived from the swarm for {cfg.stall:.0f}s; asking the hub over HTTP")
                target.unlink(missing_ok=True)
                return None
            await asyncio.sleep(0.2)
        digest, n = await asyncio.to_thread(_hash, target)
        if digest != key or n != size:
            target.unlink(missing_ok=True)
            say(f"what the swarm delivered for {key[:12]} is not that file; asking the hub over HTTP")
            return None
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(target, dest)
        if keep_torrent is not None:
            keep_torrent.parent.mkdir(parents=True, exist_ok=True)
            keep_torrent.write_bytes(torrent.read_bytes())
        return {"via": "swarm", "seconds": round(time.monotonic() - start, 1), "peers": dl.peers()}
    finally:
        await swarm.close()


def swarm_for(cfg: SwarmConfig, info: dict | None = None, peers: list | None = None):
    """A libtorrent session set up from the client's configuration. The hub's DHT node (from /api/thub/info) is
    added to the routing table, so with the tracker off the hub is still somewhere to start looking from."""
    from .swarm import LibtorrentSwarm

    nodes = list(cfg.dht_nodes)
    d = (info or {}).get("dht")
    if cfg.dht and cfg.hubdht and isinstance(d, dict) and d.get("host") and d.get("port"):
        nodes.append((d["host"], int(d["port"])))
    return LibtorrentSwarm(cfg.listen_port, cfg.listen_host, extra_peers=list(cfg.peers) if peers is None else peers, dht=cfg.dht, dht_nodes=nodes if cfg.dht else [], dht_public=cfg.dht_public,
                           dht_local=cfg.dht_local, upnp=cfg.upnp, lsd=cfg.lsd)


def _trackers_of(raw: bytes) -> list[str]:
    meta = bdecode(raw)
    out = []
    first = meta.get(b"announce")
    if isinstance(first, bytes):
        out.append(first.decode("utf-8", "replace"))
    for tier in meta.get(b"announce-list", []) or []:
        for t in tier if isinstance(tier, list) else [tier]:
            if isinstance(t, bytes):
                out.append(t.decode("utf-8", "replace"))
    return list(dict.fromkeys(t for t in out if urlsplit(t).scheme in ("udp", "http", "https")))


def _via_http(hub: str, key: str, size: int, dest: Path, work: Path) -> None:
    from .pointers import download

    try:
        download(hub, key, size, dest, work)
    except (httpx.HTTPError, ValueError) as e:
        raise GitError(f"{hub}: {e}") from e
