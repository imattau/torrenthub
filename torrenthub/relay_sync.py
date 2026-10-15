"""Moving events and manifests between a local store and a Nostr relay.

push: send what this store holds. Each event is first checked against the relay's published limits
(NIP-11), so one that cannot fit is reported and skipped instead of failing at the relay. Only the
main tier goes out: a stranger's quarantined events stay here.

pull: read events from the relay and give each to admission, exactly as an event from a hub would
be. The relay is not trusted for anything. A forged event is rejected, and a stranger's event is
quarantined and changes nothing.
"""

from __future__ import annotations

from . import events as E
from .admission import Admission
from .manifest import MANIFEST_KIND, ManifestInvalid, verify_manifest
from .relay import COMMON_MAX_EVENT_BYTES, check_fits, fetch_all, info, publish_all, to_filter
from .store import Store
from .sync import _local_events


async def push(adm: Admission, url: str, kinds=E.KINDS, *, since: int | None = None, authors=None,
               auth_secret: bytes | None = None, limits: dict | None = None, spacing: float = 0.0,
               max_event_bytes: int | None = COMMON_MAX_EVENT_BYTES) -> dict:
    """Returns counts: sent, accepted, duplicate, refused (by the relay's reason prefix), and
    skipped (cannot fit the relay's limits, with the first few reasons)."""
    if limits is None:
        limits = (await info(url)).get("limitation") or {}
    out: dict = {"considered": 0, "accepted": 0, "duplicate": 0, "refused": {}, "skipped": 0, "skip_reasons": []}
    batch = []
    for ev in _local_events(adm.store, kinds):
        if since is not None and ev["created_at"] < since:
            continue
        if authors and ev["pubkey"] not in authors:
            continue
        out["considered"] += 1
        why = check_fits(ev, limits, max_event_bytes)
        if why:
            out["skipped"] += 1
            if len(out["skip_reasons"]) < 5:
                out["skip_reasons"].append(f"{ev['id'][:12]} kind {ev['kind']}: {why[0]}")
            continue
        batch.append(ev)
    for pr in await publish_all(url, batch, auth_secret=auth_secret, spacing=spacing):
        if pr.accepted and pr.prefix != "duplicate":
            out["accepted"] += 1
        elif pr.duplicate:
            out["duplicate"] += 1
        else:
            key = pr.prefix or pr.message[:40] or "refused"
            out["refused"][key] = out["refused"].get(key, 0) + 1
    return out


async def pull(adm: Admission, url: str, kinds=E.KINDS, *, since: int | None = None, authors=None,
               auth_secret: bytes | None = None, tags: dict | None = None) -> dict:
    """Returns counts of what admission did with each event (accepted, quarantined, rejected, ...),
    plus `fetched` and any `note` the relay gave for ending early."""
    evs, note = await fetch_all(url, to_filter(kinds=kinds, authors=authors, since=since, tags=tags), auth_secret=auth_secret)
    out: dict = {"fetched": len(evs)}
    trust_edges = (E.ENDORSEMENT, E.DELEGATION)
    # Trust edges first and oldest first, as in sync.py, so authors are members when their own events arrive.
    for ev in sorted(evs, key=lambda e: (e.get("kind") not in trust_edges, e.get("created_at", 0), e.get("id", ""))):
        if adm.store.get(ev.get("id", "")) is not None:
            out["already"] = out.get("already", 0) + 1
            continue
        st = adm.admit(ev).status
        out[st] = out.get(st, 0) + 1
    if note:
        out["note"] = note
    return out


def known_authors(adm: Admission) -> set[str]:
    """Roots, and every key this store's own graph already counts as a member."""
    g = adm.graph()
    candidates = {e.subject for e in g.endorsements} | {d.subject for d in g.delegations} | set(adm.roots)
    return {k for k in candidates if k in adm.roots or g.reachable(k)}


async def pull_following(adm: Admission, url: str, kinds=E.KINDS, *, since: int | None = None, auth_secret: bytes | None = None,
                         rounds: int = 6, chunk: int = 50) -> dict:
    """Pull only from keys this store already trusts, and keep going as trust grows: round one asks
    for the roots' events, which name more keys, round two asks for theirs, and so on until a round
    finds nothing new. A stranger's events are never requested, so they cannot fill the store."""
    total: dict = {"rounds": 0, "fetched": 0}
    asked: set[str] = set()
    for _ in range(rounds):
        authors = sorted(known_authors(adm) - asked)
        if not authors:
            break
        asked |= set(authors)
        total["rounds"] += 1
        got_any = False
        for i in range(0, len(authors), chunk):
            out = await pull(adm, url, kinds, since=since, authors=authors[i:i + chunk], auth_secret=auth_secret)
            for k, v in out.items():
                if isinstance(v, int):
                    total[k] = total.get(k, 0) + v
            got_any = got_any or out.get("accepted", 0) > 0
            if "note" in out:
                total["note"] = out["note"]
        if not got_any and not (known_authors(adm) - asked):
            break
    total["authors_asked"] = len(asked)
    return total


async def push_manifests(store: Store, url: str, repos: list[str], *, auth_secret: bytes | None = None, limits: dict | None = None,
                         max_event_bytes: int | None = COMMON_MAX_EVENT_BYTES) -> dict:
    if limits is None:
        limits = (await info(url)).get("limitation") or {}
    out: dict = {"considered": 0, "accepted": 0, "duplicate": 0, "refused": {}, "skipped": 0, "skip_reasons": []}
    batch = []
    for repo in repos:
        for ev in store.list_manifests(repo):
            out["considered"] += 1
            why = check_fits(ev, limits, max_event_bytes)
            if why:
                out["skipped"] += 1
                out["skip_reasons"].append(f"{repo}@{ev['id'][:12]}: {why[0]}")
            else:
                batch.append(ev)
    for pr in await publish_all(url, batch, auth_secret=auth_secret):
        if pr.accepted and pr.prefix != "duplicate":
            out["accepted"] += 1
        elif pr.duplicate:
            out["duplicate"] += 1
        else:
            out["refused"][pr.prefix or pr.message[:40] or "refused"] = out["refused"].get(pr.prefix or pr.message[:40] or "refused", 0) + 1
    return out


async def pull_manifests(store: Store, url: str, signers: set[str], repos: list[str], *, auth_secret: bytes | None = None) -> dict:
    """Manifests signed by one of `signers` for one of `repos`. A signer you do not name is ignored,
    however many relays repeat its events."""
    evs, note = await fetch_all(url, to_filter(kinds=[MANIFEST_KIND], authors=sorted(signers)), auth_secret=auth_secret)
    out: dict = {"fetched": len(evs), "stored": 0, "ignored": 0}
    for ev in evs:
        repo = next((t[1] for t in ev.get("tags", []) if len(t) >= 2 and t[0] == "repo"), None)
        if repo not in repos:
            out["ignored"] += 1
            continue
        try:
            verify_manifest(ev, signers, repo)
        except ManifestInvalid:
            out["ignored"] += 1
            continue
        out["stored"] += int(bool(store.add_manifest(ev)))
    if note:
        out["note"] = note
    return out
