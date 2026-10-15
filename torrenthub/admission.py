"""Who gets to put events on this hub, and how many.

Order of checks (PROTOCOL.md section 7): size, structure and signature, known kind, a clock
check, a per key token bucket, then tiering. A key in the hub's own graph goes in the main store
with a large allowance. A stranger goes to quarantine with a small one.

Admission is about the hub's resources. It has no say in what any consumer believes: consumers
work from signed events and their own roots.
"""

from __future__ import annotations

import time
import json
from dataclasses import dataclass

from .events import EventInvalid, parse_event
from .eventstore import EventStore
from .trust import Graph


@dataclass
class Limits:
    member_burst: int = 120
    member_per_minute: float = 60.0
    member_events_per_day: int = 5000
    member_bytes_per_day: int = 50 * 1024 * 1024
    stranger_burst: int = 5
    stranger_per_minute: float = 1.0
    stranger_stored: int = 20
    quarantine_ttl: int = 24 * 3600
    quarantine_total: int = 100_000  # most quarantined events held at once, over all keys
    max_future_seconds: int = 600


@dataclass
class Result:
    status: str  # "accepted", "quarantined", "duplicate", "rejected"
    reason: str = ""
    http: int = 200
    tier: str | None = None


class Bucket:
    def __init__(self, burst: float, per_minute: float, now: float):
        self.burst, self.rate, self.tokens, self.t = burst, per_minute / 60.0, float(burst), now

    def take(self, now: float) -> bool:
        self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class Admission:
    def __init__(self, store: EventStore, roots, limits: Limits | None = None, hops: int = 3):
        self.store = store
        self.roots = frozenset(roots)
        self.limits = limits or Limits()
        self.hops = hops
        self._buckets: dict[tuple[str, str], Bucket] = {}
        self._qcount = (0.0, 0)  # (when counted, how many) for the quarantine cap
        self._graph: Graph | None = None
        self._graph_key = None

    # ---------------------------------------------------------------- graph
    def graph(self, now: int | None = None) -> Graph:
        now = int(now if now is not None else time.time())
        key = (self.store.version, now // 60)  # expiry is checked to the minute
        if self._graph is None or self._graph_key != key:
            self._graph = Graph(self.store.main_events(), self.roots, now, self.hops, verified=True)
            self._graph_key = key
        return self._graph

    def is_member(self, pubkey: str, now: int | None = None) -> bool:
        return self.graph(now).reachable(pubkey)

    # ---------------------------------------------------------------- admit
    def admit(self, ev: dict, now: float | None = None) -> Result:
        now = time.time() if now is None else now
        lim = self.limits
        if not isinstance(ev, dict):
            return Result("rejected", "not an object", 400)
        try:
            parsed = parse_event(ev)
        except EventInvalid as e:
            too_big = "too large" in str(e)
            return Result("rejected", str(e), 413 if too_big else 400)
        if ev["created_at"] > now + lim.max_future_seconds:
            return Result("rejected", "created_at is too far in the future", 400)
        if self.store.tier_of(ev["id"]):
            return Result("duplicate", "already held", 200)
        member = self.is_member(ev["pubkey"], int(now))
        tier = "main" if member else "quarantine"
        bk = (ev["pubkey"], tier)
        b = self._buckets.get(bk)
        if b is None:
            b = self._buckets[bk] = Bucket(
                lim.member_burst if member else lim.stranger_burst,
                lim.member_per_minute if member else lim.stranger_per_minute, now)
        if len(self._buckets) > 20000:
            self._buckets = {k: v for k, v in self._buckets.items() if v.tokens < v.burst}
        if not b.take(now):
            return Result("rejected", "rate limit", 429)
        if member:
            n, size = self.store.usage_since(ev["pubkey"], int(now) - 86400)
            cap_n, cap_b = self._daily_caps(ev["pubkey"], int(now))
            if n >= cap_n or size + len(json.dumps(ev)) > cap_b:
                return Result("rejected", "daily allowance used", 429)
        else:
            if self.store.count(ev["pubkey"], "quarantine") >= lim.stranger_stored:
                return Result("rejected", "quarantine allowance used", 429)
            if self._quarantine_size(now) >= lim.quarantine_total:
                return Result("rejected", "quarantine is full; try again later", 503)
        self.store.add(ev, tier, int(now))
        if tier == "main":
            self._promote_waiting(int(now))
        return Result("accepted" if member else "quarantined", "", 200 if member else 202, tier)

    def _daily_caps(self, pubkey: str, now: int) -> tuple[int, int]:
        """The hub's own allowance, lowered by any delegation limit that applies to this key."""
        cap_n, cap_b = self.limits.member_events_per_day, self.limits.member_bytes_per_day
        g = self.graph(now)
        for d in g.delegations:
            if d.subject == pubkey:
                if d.max_events_per_day is not None:
                    cap_n = min(cap_n, d.max_events_per_day)
                if d.max_bytes_per_day is not None:
                    cap_b = min(cap_b, d.max_bytes_per_day)
        return cap_n, cap_b

    def _promote_waiting(self, now: int) -> None:
        """A key that joined the graph after posting gets its waiting events moved to main.
        Without this the stored result would depend on the order events arrived in."""
        moved = True
        while moved:
            moved = False
            for author in self.store.quarantine_authors():
                if self.is_member(author, now):
                    for ev in self.store.quarantined_by(author):
                        self.store.promote(ev["id"])
                    moved = True

    def _quarantine_size(self, now: float) -> int:
        """How many events are quarantined, counted at most every ten seconds."""
        when, n = self._qcount
        if now - when > 10:
            when, n = now, self.store.counts().get("quarantine", 0)
        self._qcount = (when, n + 1)  # the caller is about to add one; keep the count current between recounts
        return n

    def purge(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        return self.store.purge_quarantine(int(now) - self.limits.quarantine_ttl)
