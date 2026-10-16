"""`torrenthub doctor`: is this machine set up to run a hub?

It reads the settings the hub would start with (the same environment variables) and checks the things that, in this project's
experience, go wrong: a public URL that says localhost, a swarm port that is closed or not the one clients are told about, an old
git, no libtorrent, a data directory that cannot be written, publishing switched on with nobody allowed to publish. Each line is
`ok`, `warn` or `fail`; the exit status is 1 if anything failed.

With `--probe` it also asks the running hub, at its public URL, what it believes about itself, which catches a reverse proxy that
rewrites the host or a port that was mapped differently from what the hub advertises.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .config import Settings


@dataclass
class Check:
    level: str  # ok | warn | fail
    name: str
    detail: str

    def line(self) -> str:
        return f"{self.level:4}  {self.name}: {self.detail}"


def _git_version() -> tuple[int, ...] | None:
    try:
        out = subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", out)
    return tuple(int(x) for x in m.groups() if x) if m else None


def _can_bind(port: int, kind: int) -> bool:
    with socket.socket(socket.AF_INET, kind) as s:
        try:
            s.bind(("0.0.0.0", port))
            return True
        except OSError:
            return False


def _is_private_host(host: str) -> bool:
    import ipaddress

    if host in ("localhost", ""):
        return True
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        return False


def run(s: Settings, probe: bool = False) -> list[Check]:
    out: list[Check] = []
    add = lambda level, name, detail: out.append(Check(level, name, detail))

    if sys.version_info < (3, 11):
        add("fail", "python", f"{sys.version.split()[0]}; torrenthub needs 3.11 or newer")
    else:
        add("ok", "python", sys.version.split()[0])

    gv = _git_version()
    if gv is None:
        add("warn" if s.publish_quota <= 0 else "fail", "git", "not installed: git backed publishing, `host`, smart HTTP and packs need it")
    elif gv < (2, 32):
        add("fail", "git", f"{'.'.join(map(str, gv))} is too old: the sandbox around hostile packs uses GIT_CONFIG_GLOBAL (git 2.32 or newer)")
    else:
        add("ok", "git", ".".join(map(str, gv)))

    swarm_on = s.swarm == "libtorrent"
    try:
        import libtorrent

        add("ok", "libtorrent", libtorrent.__version__)
    except ImportError:
        add("fail" if swarm_on else "warn", "libtorrent", "not installed (pip install 'torrenthub[swarm]'); without it nothing is shared over BitTorrent")
    if not swarm_on:
        add("warn", "swarm", "THUB_SWARM is not 'libtorrent': this hub serves over HTTP only, and publishers cannot send it big files")

    try:
        import coincurve  # noqa: F401

        add("ok", "signing", "libsecp256k1 (constant time)")
    except ImportError:
        add("warn", "signing", "pure Python signing, whose timing depends on the key; pip install 'torrenthub[fast]' on anything that signs")

    d = Path(s.data_dir)
    try:
        d.mkdir(parents=True, exist_ok=True)
        probe_file = d / ".doctor"
        probe_file.write_text("x")
        probe_file.unlink()
        free = shutil.disk_usage(d).free
        gib = free / 2**30
        want = s.max_disk_bytes or 0
        if want and free < want:
            add("warn", "data dir", f"{d} is writable but has {gib:,.0f} GiB free and THUB_MAX_DISK is {want / 2**30:,.0f} GiB")
        elif gib < 10:
            add("warn", "data dir", f"{d} is writable, only {gib:,.1f} GiB free")
        else:
            add("ok", "data dir", f"{d} is writable, {gib:,.0f} GiB free")
    except OSError as e:
        add("fail", "data dir", f"{d} cannot be written: {e}")

    u = urlsplit(s.public_url)
    host = u.hostname or ""
    if u.scheme not in ("http", "https") or not host:
        add("fail", "public url", f"{s.public_url!r} is not an http(s) URL")
    elif _is_private_host(host) and swarm_on:
        add("warn", "public url", f"{s.public_url} names this machine or a private address; peers elsewhere cannot use the web seeds, LFS links or tracker address built from it (THUB_PUBLIC_URL)")
    else:
        add("ok", "public url", s.public_url)
        if u.scheme == "http" and not _is_private_host(host):
            add("warn", "tls", "the public URL is plain http: put a TLS terminating proxy in front (DEPLOY.md) before clients on the internet use it")
        try:
            socket.getaddrinfo(host, None)
        except OSError:
            add("warn", "public url", f"{host} does not resolve from here")

    if swarm_on:
        p = s.listen_port
        tcp, udp = _can_bind(p, socket.SOCK_STREAM), _can_bind(p, socket.SOCK_DGRAM)
        if tcp and udp:
            add("ok", "swarm port", f"{p} is free for TCP and UDP (open both in the firewall)")
        else:
            add("warn", "swarm port", f"{p} is already in use for {'TCP' if not tcp else ''}{' and ' if not tcp and not udp else ''}{'UDP' if not udp else ''} "
                                       "(fine if this is the hub already running)")
        if s.advertised_swarm_port != s.listen_port:
            add("ok", "swarm public port", f"clients are told {s.advertised_swarm_port}, the hub listens on {s.listen_port}")
        if s.tracker is False and not s.dht:
            add("warn", "discovery", "the tracker and the DHT are both off: peers can find each other only through hints")

    if s.publish_quota > 0:
        if not s.roots:
            add("fail", "publishing", "THUB_PUBLISH_QUOTA is set but THUB_ROOTS is empty, so nobody is allowed to publish")
        else:
            add("ok", "publishing", f"quota {s.publish_quota / 2**30:,.1f} GiB per key; {len(s.roots)} root key(s)")
        if s.publish_allow_force:
            add("warn", "publishing", "THUB_PUBLISH_ALLOW_FORCE is on: a signer may rewrite a branch it can publish to")
    if s.max_disk_bytes == 0 and swarm_on:
        add("warn", "disk budget", "THUB_MAX_DISK is 0 (unlimited): a mirror fills the disk until someone notices")

    try:
        import resource

        soft = resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        add("ok" if soft >= 4096 else "warn", "open files", f"limit {soft}" + ("" if soft >= 4096 else "; a busy swarm needs more (systemd: LimitNOFILE=65536)"))
    except (ImportError, OSError):
        pass

    if os.environ.get("FORWARDED_ALLOW_IPS") is None and u.scheme == "https":
        add("warn", "proxy", "the public URL is https but FORWARDED_ALLOW_IPS is unset: behind a reverse proxy every client looks like the proxy to the rate limits (default trusts loopback only)")

    if probe:
        out += probe_running(s)
    return out


def probe_running(s: Settings) -> list[Check]:
    """Ask the running hub, at its public URL, what it says about itself."""
    import httpx

    out = []
    base = s.public_url.rstrip("/")
    try:
        r = httpx.get(f"{base}/api/thub/info", timeout=10, follow_redirects=True)
        info = r.json()
    except Exception as e:  # noqa: BLE001
        return [Check("fail", "probe", f"{base}/api/thub/info did not answer: {type(e).__name__}: {e}")]
    if info.get("public_url", "").rstrip("/") != base:
        out.append(Check("fail", "probe", f"the hub says its public URL is {info.get('public_url')!r}, not {base!r}: THUB_PUBLIC_URL differs from the address you reached it at"))
    else:
        out.append(Check("ok", "probe", f"{base} reaches the hub and it agrees about its address"))
    sw = (info.get("swarm") or {})
    port, host = sw.get("port"), urlsplit(base).hostname
    if sw.get("enabled") and port and host:
        try:
            with socket.create_connection((host, int(port)), timeout=5):
                out.append(Check("ok", "probe", f"the swarm port {host}:{port} accepts TCP connections"))
        except OSError as e:
            out.append(Check("fail", "probe", f"the swarm port {host}:{port} did not accept a TCP connection ({e}): closed in the firewall, or not the port the hub listens on"))
    elif not sw.get("enabled"):
        out.append(Check("warn", "probe", "the hub reports its swarm is off"))
    return out
