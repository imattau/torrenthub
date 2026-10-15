from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _bool(v: str | None, default: bool) -> bool:
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def parse_size(v: str | None, default: int = 0) -> int:
    """'500G', '64M', '1024' to bytes (binary multiples)."""
    if not v:
        return default
    v = v.strip().upper().removesuffix("IB").removesuffix("B")
    mult = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    if v and v[-1] in mult:
        return int(float(v[:-1]) * mult[v[-1]])
    return int(v)


def _list(v: str | None, default: list[str]) -> list[str]:
    items = [x.strip() for x in (v or "").split(",") if x.strip()]
    return items or default


def _anchor(v: str | None) -> str | None:
    if v is None:
        return None
    v = v.strip()
    return "" if v.lower() in {"", "none", "off"} else v.rstrip("/")


TRUST_MODES = ("anchor", "anchor-or-hub", "hub", "signed")


def parse_trust(v: str | None) -> list[tuple[str, str]]:
    """'acme/*=hub,*=anchor-or-hub' to [('acme/*', 'hub'), ('*', 'anchor-or-hub')]."""
    rules = []
    for item in _list(v, []):
        glob, sep, mode = item.partition("=") if "=" in item else ("", "", "")
        if mode.startswith("signed:"):
            from .signing import parse_pubkey

            try:
                keys = [parse_pubkey(k) for k in mode[len("signed:"):].split("+")]
            except ValueError as e:
                raise ValueError(f"THUB_TRUST entry {item!r}: {e}") from e
            mode = "signed:" + "+".join(keys)
        elif mode == "signed":
            raise ValueError(f"THUB_TRUST entry {item!r}: signed needs keys, as signed:<npub or hex>[+<npub or hex>]")
        if not sep or not glob or mode.split(":")[0] not in TRUST_MODES:
            raise ValueError(
                f"THUB_TRUST entry {item!r}: expected <repo glob>=<anchor|anchor-or-hub|hub|signed:KEY[+KEY]>"
            )
        rules.append((glob, mode))
    return rules


def parse_keys(v: str | None) -> list[str]:
    """'npub1...,abcd...' to a list of 64 hex keys."""
    from .signing import parse_pubkey

    out = []
    for k in _list(v, []):
        try:
            out.append(parse_pubkey(k))
        except ValueError as e:
            raise ValueError(f"THUB_ROOTS entry {k!r}: {e}") from e
    return out


def effective_anchor(s: "Settings") -> str:
    """The anchor URL in force, or "" for none."""
    if s.anchor is not None:
        return s.anchor
    return "https://huggingface.co" if s.swarm_first else ""


@dataclass
class Settings:
    data_dir: Path
    upstream: str = "https://huggingface.co"
    # Several upstream hubs, in priority order. When set, `upstream` is ignored.
    upstreams: list[str] = field(default_factory=list)
    # How many upstreams must agree on a repo's file table before it is accepted. 1 means the
    # first that answers is trusted. Needs at least that many upstreams.
    quorum: int = 1
    # Seconds to wait for each upstream's metadata answer when asking several at once.
    meta_timeout: float = 15.0
    # The origin that decides what the correct hashes are. When set, repo metadata comes only
    # from here and the other upstreams supply torrents and bytes, which are checked against
    # it. None means automatic: Hugging Face in agent mode (swarm_first), nothing otherwise.
    # "" turns it off.
    anchor: str | None = None
    # If the anchor cannot be reached: refuse new metadata (True) or fall back to the other
    # upstreams, trusting them (False). Metadata already stored is served either way.
    anchor_required: bool = True
    # Per repo choice of where the correct hashes come from: (glob on repo id, mode), first match
    # wins. Modes: "anchor" (the anchor only; if it says 404 the answer is 404), "anchor-or-hub"
    # (the anchor, and if it does not have the repo, the hubs, marked as such), "hub" (the hubs
    # only). Repos that match nothing use "anchor" when there is an anchor, else the upstreams.
    trust: list[tuple[str, str]] = field(default_factory=list)
    # Lockfile of commits and their file tables, and how strictly it is applied.
    lockfile: Path | None = None
    lock_mode: str = "verify"
    # Externally reachable base URL of this gateway. Used for BEP-19 web seed URLs.
    public_url: str = "http://localhost:8080"
    trackers: list[str] = field(default_factory=list)
    # Mirror repos on first request instead of only via the `mirror` command.
    lazy_mirror: bool = True
    # Only LFS files at least this big get a torrent. Small files are served directly.
    torrent_min_size: int = 1024 * 1024
    # How long a branch name (for example "main") is trusted before re-checking upstream.
    ref_ttl: float = 300.0
    # Log pauses of at least this many seconds in upstream and client streams. 0 turns it off.
    gap_warn: float = 5.0
    # Also list the upstream resolve URL as a web seed in each torrent.
    webseed_upstream: bool = True
    swarm: str = "none"  # "none" or "libtorrent"
    listen_port: int = 6881
    # Static peer hints, "host:port" each. For a known sibling gateway, or to tell "the transfer
    # works" apart from "peer discovery works" when testing. Normal discovery is still on.
    peers: list[str] = field(default_factory=list)
    # Dial peers over uTP first (libtorrent's default). Off: dial TCP. See swarm.py for why.
    outgoing_utp: bool = False
    # Keys this gateway pins as roots (hex or npub). Events from keys reachable from a root go in
    # the main event store with a large allowance. Everyone else is quarantined. See PROTOCOL.md.
    roots: list[str] = field(default_factory=list)
    trust_hops: int = 3
    # TOML policy file: what must be attested before this gateway serves a file. See policy.py.
    policy: str | None = None
    hf_token: str | None = None
    # Agent mode: on a miss, ask the upstream hub for the blob's torrent and download from
    # peers first. Off by default because it exposes this machine's IP address to peers.
    swarm_first: bool = False
    # Seconds with zero swarm progress before falling back to HTTP from the upstream.
    swarm_stall: float = 20.0
    # Seconds without progress, after bytes have started flowing, before the download fails.
    # No HTTP fallback at that point, because a client may already hold part of the file.
    swarm_timeout: float = 300.0
    # Let the swarm also pull from web seeds listed in the torrent. Off by default: web seeds
    # are HTTP, so using them sends the bytes back through the hub and defeats the saving.
    use_webseeds: bool = False
    # Disk budget in bytes. 0 means unlimited. Only blobs that have a torrent are evicted.
    max_disk_bytes: int = 0
    # While streaming a first download to a client, never release the last N bytes until the
    # whole file has been verified. A client therefore never receives a complete corrupt file.
    # Small on purpose: no byte is released until this many have been written, so it is also the
    # silence a slow-link client sits through before its first byte.
    stream_holdback: int = 64 * 1024
    # Repo policy: fnmatch globs on repo ids. Deny wins over allow.
    allow: list[str] = field(default_factory=lambda: ["*"])
    deny: list[str] = field(default_factory=list)
    # After a repo's metadata is first read, fetch all its files in the background.
    prefetch: bool = False
    prefetch_concurrency: int = 2

    @classmethod
    def from_env(cls) -> "Settings":
        e = os.environ.get
        return cls(
            data_dir=Path(e("THUB_DATA", "./data")),
            upstream=(_list(e("THUB_UPSTREAMS"), []) or [e("THUB_UPSTREAM", "https://huggingface.co")])[0].rstrip("/"),
            upstreams=[u.rstrip("/") for u in _list(e("THUB_UPSTREAMS"), [])],
            quorum=int(e("THUB_QUORUM", "1")),
            meta_timeout=float(e("THUB_META_TIMEOUT", "15")),
            anchor=_anchor(e("THUB_ANCHOR")),
            anchor_required=_bool(e("THUB_ANCHOR_REQUIRED"), True),
            trust=parse_trust(e("THUB_TRUST")),
            lockfile=Path(e("THUB_LOCKFILE")) if e("THUB_LOCKFILE") else None,
            lock_mode=e("THUB_LOCK_MODE", "verify"),
            public_url=e("THUB_PUBLIC_URL", "http://localhost:8080").rstrip("/"),
            trackers=[t for t in e("THUB_TRACKERS", "").split(",") if t],
            lazy_mirror=_bool(e("THUB_LAZY_MIRROR"), True),
            torrent_min_size=int(e("THUB_TORRENT_MIN_SIZE", str(1024 * 1024))),
            ref_ttl=float(e("THUB_REF_TTL", "300")),
            webseed_upstream=_bool(e("THUB_WEBSEED_UPSTREAM"), True),
            swarm=e("THUB_SWARM", "none"),
            listen_port=int(e("THUB_LISTEN_PORT", "6881")),
            peers=_list(e("THUB_PEERS"), []),
            outgoing_utp=_bool(e("THUB_OUTGOING_UTP"), False),
            roots=parse_keys(e("THUB_ROOTS")),
            trust_hops=int(e("THUB_TRUST_HOPS", "3")),
            policy=e("THUB_POLICY") or None,
            hf_token=e("HF_TOKEN") or None,
            swarm_first=_bool(e("THUB_SWARM_FIRST"), False),
            swarm_stall=float(e("THUB_SWARM_STALL", "20")),
            swarm_timeout=float(e("THUB_SWARM_TIMEOUT", "300")),
            use_webseeds=_bool(e("THUB_USE_WEBSEEDS"), False),
            max_disk_bytes=parse_size(e("THUB_MAX_DISK")),
            stream_holdback=parse_size(e("THUB_STREAM_HOLDBACK"), 64 * 1024),
            allow=_list(e("THUB_ALLOW"), ["*"]),
            deny=_list(e("THUB_DENY"), []),
            gap_warn=float(e("THUB_GAP_WARN", "5")),
            prefetch=_bool(e("THUB_PREFETCH"), False),
            prefetch_concurrency=int(e("THUB_PREFETCH_CONCURRENCY", "2")),
        )
