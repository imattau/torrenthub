"""Keep two hubs' event stores level: pull what the other has, push what it lacks.

Events are signed and each hub checks them again on admission, so a hub that syncs from a bad
peer takes in nothing it would not have accepted from anyone else. This is on demand, not
gossip: run it when you want, or from a timer. Only the main tier is pushed. A stranger's
quarantined events stay where they are.
"""

from __future__ import annotations

import time

import httpx

from .admission import Admission
from .eventstore import MAX_LIMIT, EventStore
from .events import DELEGATION, ENDORSEMENT, KINDS

MAX_EVENTS = 100_000  # most events looked at from one peer in one run


def post_event(url: str, ev: dict, *, client: httpx.Client | None = None, tries: int = 6, timeout: float = 30.0) -> httpx.Response:
    """POST one event, waiting out a 429 the way the server asks (Retry-After) up to `tries` times.
    A hub rate limits by address and by key, and a client with many events must be able to wait."""
    r = None
    for _ in range(tries):
        r = (client or httpx).post(url, json=ev, timeout=timeout)
        if r.status_code != 429:
            return r
        try:
            wait = float(r.headers.get("retry-after", 2))
        except ValueError:
            wait = 2.0
        time.sleep(min(max(wait, 0.2), 30.0))
    return r


def _page_through(client: httpx.Client, base: str, kinds, limit: int = MAX_LIMIT):
    """Every event the peer holds of these kinds, newest first. The API pages with `until`, which
    is inclusive, so events on the boundary second come back again and are skipped here. More than
    `limit` events in one second would stall the walk; it stops there rather than loop."""
    seen: set[str] = set()
    until = None
    while len(seen) < MAX_EVENTS:
        params = {"kinds": ",".join(str(k) for k in kinds), "limit": limit}
        if until is not None:
            params["until"] = until
        r = client.get(base + "/api/thub/events", params=params)
        r.raise_for_status()
        page = r.json().get("events", [])
        fresh = [e for e in page if e.get("id") not in seen]
        for e in fresh:
            seen.add(e["id"])
            yield e
        if len(page) < limit or not fresh:
            return
        until = min(e["created_at"] for e in page)


def sync(adm: Admission, url: str, kinds=KINDS, *, pull: bool = True, push: bool = True,
         client: httpx.Client | None = None) -> dict:
    """Returns counts: pulled (by admission result), pushed (by the peer's answer), and
    `remote_events` / `local_events` seen."""
    store: EventStore = adm.store
    base = url.rstrip("/")
    own = client is None
    client = client or httpx.Client(timeout=30)
    out: dict = {"pulled": {}, "pushed": {}}
    try:
        remote = list(_page_through(client, base, kinds))
        remote_ids = {ev["id"] for ev in remote}
        if pull:
            # Trust edges first, oldest first, so authors are members by the time their own events
            # arrive. An event that still comes early is quarantined and promoted later by the
            # store, so the end state does not depend on this order, only the tally does.
            edges = (ENDORSEMENT, DELEGATION)
            for ev in sorted(remote, key=lambda e: (e["kind"] not in edges, e["created_at"], e["id"])):
                if store.get(ev["id"]) is None:
                    st = adm.admit(ev).status
                    out["pulled"][st] = out["pulled"].get(st, 0) + 1
        out["remote_events"] = len(remote_ids)
        local = list(_local_events(store, kinds))
        out["local_events"] = len(local)
        if push:
            pending = [e for e in local if e["id"] not in remote_ids]
            for ev in pending:
                r = post_event(base + "/api/thub/events", ev, client=client)
                try:
                    st = r.json().get("status", f"http{r.status_code}")
                except ValueError:
                    st = f"http{r.status_code}"
                out["pushed"][st] = out["pushed"].get(st, 0) + 1
    finally:
        if own:
            client.close()
    return out


def _local_events(store: EventStore, kinds):
    seen: set[str] = set()
    until = None
    while len(seen) < MAX_EVENTS:
        page = store.query(list(kinds), until=until, limit=MAX_LIMIT)
        fresh = [e for e in page if e["id"] not in seen]
        for e in fresh:
            seen.add(e["id"])
            yield e
        if len(page) < MAX_LIMIT or not fresh:
            return
        until = min(e["created_at"] for e in page)
