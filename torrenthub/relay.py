"""Talking to a Nostr relay (NIP-01), so events can travel through relays as well as hubs.

Every event here is already a NIP-01 event, so the adapter adds no new format. It sends events
with EVENT and waits for the relay's OK, reads them back with REQ until EOSE, reads the relay's
NIP-11 information document to learn its limits, and answers a NIP-42 AUTH challenge if a signing
key is given. Nothing read from a relay is believed: pulled events go through the same admission
as events from a hub, which checks the signature and the sender's standing again.

What a relay does to these events is the part that is easy to get wrong:

* Kinds 36777 to 36786 are in the addressable range (30000 to 39999). A relay keeps only the
  latest event per kind, key and `d` tag. Events built here carry a content-derived `d` tag so
  different events never replace one another (events.py `_signed`). `probe` checks what a
  particular relay does with events that have none.
* Relays cap message and content size, the number of tags, and sometimes the kinds they accept.
  `check_fits` tests an event against a relay's published limits, and `probe` finds the real ones.
  A version 2 manifest keeps a large file table out of the event for this reason (manifest.py).
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, field

import httpx

try:
    import websockets
except ImportError:  # the adapter is an optional extra: pip install 'torrenthub[relay]'
    websockets = None

from . import events as E
from .signing import public_key, sign_event

MAX_RECEIVE = 16 * 1024 * 1024  # largest single message read back from a relay
NOTICE_KEEP = 20
# Relays rarely publish how big a single event may be (NIP-11 gives only the message size), yet
# strfry, which most large relays run, refuses events over 65536 bytes by default. Measured: its
# NIP-11 says 131072 for messages and it took 65541 wire bytes and refused 69646.
COMMON_MAX_EVENT_BYTES = 65536


class RelayError(Exception):
    pass


def _need_websockets() -> None:
    if websockets is None:
        raise RelayError("the relay adapter needs the websockets package: pip install 'torrenthub[relay]'")


def http_url(ws_url: str) -> str:
    return ws_url.replace("wss://", "https://", 1).replace("ws://", "http://", 1)


@dataclass
class PublishResult:
    id: str
    accepted: bool
    message: str = ""

    @property
    def prefix(self) -> str:
        """The machine readable part of a relay's reason (duplicate, rate-limited, blocked, ...)."""
        head, sep, _ = self.message.partition(":")
        return head if sep else ""

    @property
    def duplicate(self) -> bool:
        return self.accepted or self.prefix == "duplicate"


# ----------------------------------------------------------------------------- NIP-11

async def info(url: str, timeout: float = 10.0) -> dict:
    """The relay's NIP-11 document, or {} if it has none or cannot be read."""
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as c:
            r = await c.get(http_url(url), headers={"Accept": "application/nostr+json"})
        doc = r.json() if r.status_code == 200 else {}
        return doc if isinstance(doc, dict) else {}
    except (httpx.HTTPError, ValueError):
        return {}


def check_fits(ev: dict, limits: dict | None, max_event_bytes: int | None = COMMON_MAX_EVENT_BYTES) -> list[str]:
    """Reasons a relay with these NIP-11 `limitation` values would refuse this event, if any.
    `max_event_bytes` is the cap on the event itself that relays often enforce without publishing
    (default 64 KiB; None turns the check off). An empty list means nothing known rules it out."""
    lim = limits or {}
    out = []
    ev_len = len(json.dumps(ev, separators=(",", ":"), ensure_ascii=False).encode())
    if max_event_bytes and ev_len > max_event_bytes:
        out.append(f"event is {ev_len} bytes; relays commonly refuse events over {max_event_bytes} without saying so")
    msg_len = len(json.dumps(["EVENT", ev], separators=(",", ":"), ensure_ascii=False).encode())
    if lim.get("max_message_length") and msg_len > lim["max_message_length"]:
        out.append(f"message is {msg_len} bytes; the relay reads at most {lim['max_message_length']}")
    if lim.get("max_content_length") and len(ev.get("content", "")) > lim["max_content_length"]:
        out.append(f"content is {len(ev['content'])} characters; the limit is {lim['max_content_length']}")
    if lim.get("max_event_tags") and len(ev.get("tags", [])) > lim["max_event_tags"]:
        out.append(f"{len(ev['tags'])} tags; the limit is {lim['max_event_tags']}")
    if lim.get("min_pow_difficulty"):
        out.append(f"the relay wants proof of work (difficulty {lim['min_pow_difficulty']}); this adapter does not mine")
    now = time.time()
    if lim.get("created_at_lower_limit") and ev["created_at"] < now - lim["created_at_lower_limit"]:
        out.append("created_at is older than the relay accepts")
    if lim.get("created_at_upper_limit") and ev["created_at"] > now + lim["created_at_upper_limit"]:
        out.append("created_at is further ahead than the relay accepts")
    return out


# ---------------------------------------------------------------------------- the wire

class Relay:
    """One connection. Use as `async with Relay(url, auth_secret=...) as r`."""

    def __init__(self, url: str, *, auth_secret: bytes | None = None, timeout: float = 20.0):
        _need_websockets()
        if not url.startswith(("ws://", "wss://")):
            raise RelayError("a relay address starts with ws:// or wss://")
        self.url, self.auth_secret, self.timeout = url, auth_secret, timeout
        self.ws = None
        self.notices: list[str] = []
        self.challenge: str | None = None
        self._authed = False

    async def __aenter__(self):
        await self._open()
        return self

    async def _open(self) -> None:
        try:
            self.ws = await websockets.connect(self.url, max_size=MAX_RECEIVE, open_timeout=self.timeout, ping_interval=None)
        except Exception as e:  # noqa: BLE001
            raise RelayError(f"cannot connect to {self.url}: {type(e).__name__}: {e}") from e
        self.challenge, self._authed = None, False

    async def ensure_open(self) -> None:
        """Reconnect if the relay hung up, which many do on a message they will not read."""
        if self.ws is None or self.ws.state.name != "OPEN":
            await self._open()

    async def __aexit__(self, *exc):
        if self.ws is not None:
            await self.ws.close()

    async def _recv(self, timeout: float | None = None) -> list:
        raw = await asyncio.wait_for(self.ws.recv(), timeout or self.timeout)
        try:
            msg = json.loads(raw)
        except ValueError as e:
            raise RelayError("the relay sent something that is not JSON") from e
        if not isinstance(msg, list) or not msg:
            raise RelayError("the relay sent a message that is not an array")
        if msg[0] == "NOTICE" and len(msg) > 1:
            self.notices = (self.notices + [str(msg[1])])[-NOTICE_KEEP:]
        elif msg[0] == "AUTH" and len(msg) > 1:
            self.challenge = str(msg[1])
        return msg

    async def _authenticate(self) -> bool:
        """Answer a NIP-42 challenge with the signing key, if there is one."""
        if self.auth_secret is None or self.challenge is None or self._authed:
            return False
        ev = sign_event(self.auth_secret, 22242, [["relay", self.url], ["challenge", self.challenge]], "", int(time.time()))
        await self.ws.send(json.dumps(["AUTH", ev]))
        for _ in range(5):
            try:
                m = await self._recv(5)
            except asyncio.TimeoutError:
                break
            if m[0] == "OK" and m[1] == ev["id"]:
                self._authed = bool(m[2])
                return self._authed
        return False

    async def publish_one(self, ev: dict) -> PublishResult:
        res = PublishResult(ev["id"], False, "not sent")
        for attempt in range(2):
            await self.ensure_open()
            try:
                await self.ws.send(json.dumps(["EVENT", ev], separators=(",", ":")))
            except websockets.ConnectionClosed:
                return PublishResult(ev["id"], False, "closed: the relay hung up")
            while True:
                try:
                    m = await self._recv()
                except asyncio.TimeoutError:
                    return PublishResult(ev["id"], False, "timeout: no OK from the relay")
                except websockets.ConnectionClosed as e:
                    return PublishResult(ev["id"], False, f"closed: the relay hung up ({e.rcvd.reason if e.rcvd else 'no reason given'})")
                if m[0] == "OK" and len(m) >= 3 and m[1] == ev["id"]:
                    res = PublishResult(ev["id"], bool(m[2]), str(m[3]) if len(m) > 3 else "")
                    break
            if not res.accepted and res.prefix == "auth-required" and attempt == 0 and await self._authenticate():
                continue
            return res
        return res

    async def publish(self, events: list[dict], *, spacing: float = 0.0, retries: int = 3) -> list[PublishResult]:
        out = []
        for ev in events:
            delay = 1.0
            for _ in range(retries + 1):
                res = await self.publish_one(ev)
                if res.prefix != "rate-limited":
                    break
                await asyncio.sleep(delay)
                delay *= 2
            out.append(res)
            if spacing:
                await asyncio.sleep(spacing)
        return out

    async def fetch(self, filters: list[dict]) -> tuple[list[dict], str]:
        """Stored events matching any of `filters`, read until EOSE. Returns (events, note) where
        note is empty or the reason the relay gave for closing the subscription early."""
        sub = "t" + os.urandom(6).hex()
        note = ""
        got: list[dict] = []
        for attempt in range(2):
            await self.ensure_open()
            try:
                await self.ws.send(json.dumps(["REQ", sub, *filters]))
            except websockets.ConnectionClosed:
                return got, "closed: the relay hung up"
            got: list[dict] = []
            note = ""
            while True:
                try:
                    m = await self._recv()
                except asyncio.TimeoutError:
                    return got, "timeout: the relay stopped answering before EOSE"
                except websockets.ConnectionClosed:
                    return got, "closed: the relay hung up"
                if m[0] == "EVENT" and len(m) >= 3 and m[1] == sub and isinstance(m[2], dict):
                    got.append(m[2])
                elif m[0] == "EOSE" and m[1] == sub:
                    break
                elif m[0] == "CLOSED" and m[1] == sub:
                    note = str(m[2]) if len(m) > 2 else "closed"
                    break
            if note.startswith("auth-required") and attempt == 0 and await self._authenticate():
                continue
            try:
                await self.ws.send(json.dumps(["CLOSE", sub]))
            except Exception:  # noqa: BLE001
                pass
            return got, note
        return got, note


async def fetch_all(url: str, base: dict, *, page: int = 500, max_events: int = 20_000, auth_secret: bytes | None = None,
                    timeout: float = 20.0) -> tuple[list[dict], str]:
    """Every stored event matching `base`, paging back through time with `until`. A relay that
    caps `limit` below `page` just gives shorter pages; stops when a page adds nothing new."""
    seen: dict[str, dict] = {}
    note = ""
    until = None
    async with Relay(url, auth_secret=auth_secret, timeout=timeout) as r:
        while len(seen) < max_events:
            f = dict(base, limit=page)
            if until is not None:
                f["until"] = until
            evs, note = await r.fetch([f])
            fresh = [e for e in evs if isinstance(e.get("id"), str) and e["id"] not in seen]
            for e in fresh:
                seen[e["id"]] = e
            if note or not fresh:
                break
            until = min(int(e["created_at"]) for e in evs)
    return list(seen.values()), note


async def publish_all(url: str, events: list[dict], *, auth_secret: bytes | None = None, spacing: float = 0.0,
                      timeout: float = 20.0) -> list[PublishResult]:
    async with Relay(url, auth_secret=auth_secret, timeout=timeout) as r:
        return await r.publish(events, spacing=spacing)


def to_filter(*, kinds=None, authors=None, since=None, until=None, tags: dict | None = None) -> dict:
    """A NIP-01 filter. `tags` maps a single letter to values, for example {"x": [sha]}; relays index
    the first value of each tag, which is how these events put their hashes."""
    f: dict = {}
    if kinds:
        f["kinds"] = [int(k) for k in kinds]
    if authors:
        f["authors"] = list(authors)
    if since is not None:
        f["since"] = int(since)
    if until is not None:
        f["until"] = int(until)
    for letter, values in (tags or {}).items():
        if len(letter) != 1 or not letter.isalpha():
            raise ValueError("relays index single letter tags only")
        f[f"#{letter}"] = list(values)
    return f


# ------------------------------------------------------------------------------ probe

@dataclass
class Probe:
    url: str
    nip11: dict = field(default_factory=dict)
    connected: bool = False
    kinds: dict = field(default_factory=dict)         # kind -> "ok" or the relay's reason
    keeps_both_dless: bool | None = None               # two events, same key and kind, no d tag
    keeps_both_with_d: bool | None = None              # the same with distinct d tags (what this code sends)
    max_event_bytes: int | None = None                 # largest event the relay took (as sent over the wire)
    first_refused_bytes: int | None = None
    refusal: str = ""
    max_tags: int | None = None
    first_refused_tags: int | None = None
    tag_refusal: str = ""
    rtt_ms: float | None = None
    notes: list = field(default_factory=list)

    def asdict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


def _probe_event(secret: bytes, kind: int, content: str, tags: list, ts: int) -> dict:
    return sign_event(secret, kind, tags, content, ts)


async def probe(url: str, *, secret: bytes | None = None, max_bytes: int = 1024 * 1024, delete: bool = True,
                timeout: float = 20.0) -> Probe:
    """Find out what this relay will do with our events by sending some. Publishes real events to the
    relay, signed by a throwaway key, all tagged `t=torrenthub-probe`, and asks the relay to delete
    them afterwards (NIP-09). Do not point it at a relay you do not run or have permission to test:
    it sends up to `max_bytes` of padding."""
    _need_websockets()
    secret = secret or os.urandom(32)
    pk = public_key(secret).hex()
    res = Probe(url)
    res.nip11 = await info(url)
    now = int(time.time())
    sent: list[str] = []
    tag = ["t", "torrenthub-probe"]
    async with Relay(url, auth_secret=secret, timeout=timeout) as r:
        res.connected = True
        # 1. does it take each kind, and how long does an OK take
        fake = "ab" * 32
        samples = {
            E.IDENTITY: E.build_identity(secret, "unspecified", created_at=now),
            E.DELEGATION: E.build_delegation(secret, public_key(os.urandom(32)).hex(), ["publish:probe/x"], created_at=now),
            E.ENDORSEMENT: E.build_endorsement(secret, public_key(os.urandom(32)).hex(), ["work:*"], 0.5, created_at=now),
            E.REVOCATION: E.build_revocation(secret, "x", fake, reason="probe", created_at=now),
            E.ATTESTATION: E.build_attestation(secret, "hash_verified", "x", fake, ok=True, detail="probe", created_at=now),
            E.DERIVATION: E.build_derivation(secret, [fake], [{"x": "cd" * 32, "i": None, "size": 1}], "probe@1", created_at=now),
            E.REQUEST: E.build_request(secret, "hash_verified", [fake], deadline=now + 600, created_at=now),
        }
        req = samples[E.REQUEST]
        samples[E.CLAIM] = E.build_claim(secret, req["id"], expires=now + 300, created_at=now)
        samples[E.RESULT] = E.build_result(secret, req["id"], "failed", note="probe", created_at=now)
        from .manifest import MANIFEST_KIND, build_manifest

        samples[MANIFEST_KIND] = build_manifest(secret, "probe/x", {"sha": "ab" * 20, "siblings": [
            {"rfilename": "a", "size": 1, "lfs": {"size": 1, "sha256": fake}}]}, ["main"], created_at=now, seq=1)
        times = []
        for kind, ev in sorted(samples.items()):
            ev["tags"].append(tag)
            ev = sign_event(secret, kind, ev["tags"], ev["content"], ev["created_at"])
            t0 = time.perf_counter()
            pr = await r.publish_one(ev)
            times.append((time.perf_counter() - t0) * 1000)
            res.kinds[kind] = "ok" if pr.accepted else (pr.message or "refused")
            if pr.accepted:
                sent.append(ev["id"])
        res.rtt_ms = round(sorted(times)[len(times) // 2], 1) if times else None

        # 2. addressable replacement: the thing this module exists to get right
        async def two(d1, d2):
            ids = []
            for i, d in enumerate((d1, d2)):
                tags = [tag] + ([["d", d]] if d is not None else [])
                ev = sign_event(secret, E.ENDORSEMENT, tags, json.dumps({"probe": "replace", "n": i, "r": os.urandom(4).hex()}), now + i)
                pr = await r.publish_one(ev)
                if pr.accepted:
                    ids.append(ev["id"])
                    sent.append(ev["id"])
            evs, _ = await r.fetch([{"kinds": [E.ENDORSEMENT], "authors": [pk], "#t": ["torrenthub-probe"]}])
            return len({e["id"] for e in evs} & set(ids)), len(ids)

        kept, took = await two(None, None)
        res.keeps_both_dless = (kept == took == 2) if took == 2 else None
        kept, took = await two("probe-a-" + os.urandom(3).hex(), "probe-b-" + os.urandom(3).hex())
        res.keeps_both_with_d = (kept == took == 2) if took == 2 else None

        # 3. how big an event, found by doubling and then narrowing
        def padded(n_bytes: int) -> dict:
            pad = "x" * max(0, n_bytes - 400)
            return sign_event(secret, E.ATTESTATION, [tag, ["d", os.urandom(8).hex()]], pad, now)

        ok_size, bad_size, size = 0, 0, 2048
        while size <= max_bytes:
            ev = padded(size)
            wire = len(json.dumps(["EVENT", ev], separators=(",", ":")).encode())
            pr = await r.publish_one(ev)
            if pr.accepted:
                ok_size, size = wire, size * 2
                sent.append(ev["id"])
            else:
                bad_size, res.refusal = wire, pr.message
                break
        for _ in range(4 if bad_size and ok_size else 0):
            mid = (ok_size + bad_size) // 2
            ev = padded(mid)
            wire = len(json.dumps(["EVENT", ev], separators=(",", ":")).encode())
            pr = await r.publish_one(ev)
            if pr.accepted:
                ok_size = wire
                sent.append(ev["id"])
            else:
                bad_size = wire
        res.max_event_bytes = ok_size or None
        res.first_refused_bytes = bad_size or None
        if not bad_size and ok_size:
            res.notes.append(f"accepted every size tried, up to {ok_size} bytes (the probe's own cap)")

        # 4. how many tags
        ok_tags, bad_tags = 0, 0
        for n in (16, 64, 256, 1024, 4096):
            tags = [tag, ["d", os.urandom(8).hex()]] + [["t", f"probe{i}"] for i in range(n)]
            ev = sign_event(secret, E.ATTESTATION, tags, "{}", now)
            pr = await r.publish_one(ev)
            if pr.accepted:
                ok_tags = len(tags)
                sent.append(ev["id"])
            else:
                bad_tags, res.tag_refusal = len(tags), pr.message
                break
        res.max_tags, res.first_refused_tags = ok_tags or None, bad_tags or None

        # 5. tidy up
        if delete and sent:
            ids = sent[:]
            for i in range(0, len(ids), 200):
                await r.publish_one(sign_event(secret, 5, [["e", x] for x in ids[i:i + 200]] + [tag], "torrenthub relay probe", int(time.time())))
        res.notes += r.notices[-3:]
    return res
