"""The participant events: identity, delegation, endorsement and revocation.

All use the NIP-01 layout from signing.py, with ASCII JSON content and a version field.
Kind numbers 36778 to 36782 were checked against the NIPs README table and the NIPs repo's pull
requests, issues and code on 2026-10-16: no collisions. Nobody has registered them, so they are
not reserved. Change them in one place here if a NIP ever claims them. PROTOCOL.md section 3
lists the assigned and reserved numbers.

parse_event() is the one place that decides whether an event is well formed. It does not decide
whether anyone should believe it. That is trust.py.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from .signing import sign_event, verify_event

IDENTITY = 36778
DELEGATION = 36779
ENDORSEMENT = 36780
REVOCATION = 36781
ATTESTATION = 36782
KINDS = (IDENTITY, DELEGATION, ENDORSEMENT, REVOCATION, ATTESTATION)

# Claim types and how each can be checked (PROTOCOL.md section 3.6). The class comes from here,
# never from the author. D: anyone can recompute it. R: anyone can re-run it, within tolerance.
# S: the author's word.
CLAIM_CLASS = {"hash_verified": "D", "format_scan": "D", "replication": "D", "eval": "R", "licence_check": "S", "review": "S"}

MAX_EVENT_BYTES = 64 * 1024
MAX_SCOPES = 32
MAX_SCOPE_LEN = 128
LABELS = ("human", "agent", "org", "unspecified")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SCOPE_RE = re.compile(r"^[A-Za-z0-9_.:/*@+-]{1,128}$")
TARGET_KINDS = ("event", "key", "x")


class EventInvalid(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    id: str
    pubkey: str
    created_at: int
    label: str
    recovery: str | None
    note: str
    supersedes: str | None


@dataclass(frozen=True)
class Delegation:
    id: str
    issuer: str
    subject: str
    created_at: int
    scope: tuple[str, ...]
    not_before: int
    expires: int | None
    redelegable: bool
    max_events_per_day: int | None
    max_bytes_per_day: int | None


@dataclass(frozen=True)
class Endorsement:
    id: str
    issuer: str
    subject: str
    created_at: int
    scope: tuple[str, ...]
    weight: float
    delegable: bool
    expires: int | None


@dataclass(frozen=True)
class Attestation:
    id: str
    issuer: str
    created_at: int
    claim: str
    subject_kind: str  # "x" a blob sha256, or "e" another event
    subject: str
    ok: bool | None  # hash_verified, format_scan: did it pass
    match: bool | None  # replication: did the re-run agree
    detail: str
    tool: str
    tool_x: str | None
    cls: str


@dataclass(frozen=True)
class Revocation:
    id: str
    issuer: str
    created_at: int
    target_kind: str
    target: str
    reason: str
    severity: str
    taint: bool
    successor: str | None = None  # rotation: the key that inherits the revoked key's standing


def _dump(body: dict) -> str:
    return json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def _scopes(scope) -> list[str]:
    if isinstance(scope, str):
        scope = [scope]
    if not isinstance(scope, list) or not scope or len(scope) > MAX_SCOPES:
        raise ValueError("scope must be a short non empty list")
    for s in scope:
        if not isinstance(s, str) or not SCOPE_RE.match(s):
            raise ValueError(f"bad scope {s!r}")
    return sorted(set(scope))


def _key(k: str) -> str:
    if not isinstance(k, str) or not HEX64.match(k):
        raise ValueError("keys must be 64 hex characters")
    return k


def _now(created_at: int | None) -> int:
    return int(created_at if created_at is not None else time.time())


# ------------------------------------------------------------------ builders

def build_identity(secret: bytes, label: str = "unspecified", recovery: str | None = None, note: str = "",
                   supersedes: str | None = None, created_at: int | None = None) -> dict:
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}")
    body = {"v": 1, "label": label, "recovery": _key(recovery) if recovery else None, "note": note[:500]}
    tags = [["e", supersedes, "supersedes"]] if supersedes else []
    return sign_event(secret, IDENTITY, tags, _dump(body), _now(created_at))


def build_delegation(secret: bytes, subject: str, scope, *, not_before: int = 0, expires: int | None = None,
                     redelegable: bool = False, max_events_per_day: int | None = None,
                     max_bytes_per_day: int | None = None, created_at: int | None = None) -> dict:
    body = {
        "v": 1, "subject": _key(subject), "scope": _scopes(scope), "not_before": int(not_before),
        "expires": None if expires is None else int(expires), "redelegable": bool(redelegable),
        "limits": {"max_events_per_day": max_events_per_day, "max_bytes_per_day": max_bytes_per_day},
    }
    return sign_event(secret, DELEGATION, [["p", subject]], _dump(body), _now(created_at))


def build_endorsement(secret: bytes, subject: str, scope, weight: float, *, delegable: bool = False,
                      expires: int | None = None, created_at: int | None = None) -> dict:
    if isinstance(weight, bool) or not (0 < weight <= 1):
        raise ValueError("weight must be in (0, 1]")
    body = {
        "v": 1, "subject": _key(subject), "scope": _scopes(scope), "weight": float(weight),
        "delegable": bool(delegable), "expires": None if expires is None else int(expires),
    }
    return sign_event(secret, ENDORSEMENT, [["p", subject]], _dump(body), _now(created_at))


def build_revocation(secret: bytes, target_kind: str, target: str, reason: str = "", severity: str = "normal",
                     taint: bool = False, successor: str | None = None, created_at: int | None = None) -> dict:
    if target_kind not in TARGET_KINDS:
        raise ValueError(f"target_kind must be one of {TARGET_KINDS}")
    if not HEX64.match(target):
        raise ValueError("target must be 64 hex characters")
    body = {"v": 1, "target_kind": target_kind, "target": target, "reason": reason[:500],
            "severity": severity if severity in ("low", "normal", "high") else "normal", "taint": bool(taint)}
    tag = {"event": "e", "key": "p", "x": "x"}[target_kind]
    tags = [[tag, target]]
    if successor is not None:
        # Key rotation: revoke the old key and name the key that takes over its standing.
        if target_kind != "key":
            raise ValueError("only a key can have a successor")
        if not HEX64.match(successor) or successor == target:
            raise ValueError("successor must be a different key of 64 hex characters")
        body["successor"] = successor
        tags.append(["p", successor, "successor"])
    return sign_event(secret, REVOCATION, tags, _dump(body), _now(created_at))


def build_attestation(secret: bytes, claim: str, subject_kind: str, subject: str, *, ok: bool | None = None,
                      match: bool | None = None, detail: str = "", tool: str = "", tool_x: str | None = None,
                      evidence: dict | None = None, created_at: int | None = None) -> dict:
    if claim not in CLAIM_CLASS:
        raise ValueError(f"claim must be one of {sorted(CLAIM_CLASS)}")
    if subject_kind not in ("x", "e") or not HEX64.match(subject):
        raise ValueError("subject must be an x or e reference of 64 hex characters")
    if claim == "replication":
        if subject_kind != "e" or not isinstance(match, bool):
            raise ValueError("a replication refers to an event and says match true or false")
        result = {"match": match, "detail": detail[:500]}
    else:
        if claim in ("hash_verified", "format_scan") and (subject_kind != "x" or not isinstance(ok, bool)):
            raise ValueError(f"{claim} refers to a blob and says ok true or false")
        result = {"ok": ok, "detail": detail[:500]}
    body = {"v": 1, "claim": claim, "subject": {subject_kind: subject}, "result": result,
            "method": {"tool": tool[:100], "tool_x": tool_x}, "evidence": evidence}
    return sign_event(secret, ATTESTATION, [[subject_kind, subject], ["claim", claim]], _dump(body), _now(created_at))


# ------------------------------------------------------------------- parsing

def _opt_int(v):
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
        raise ValueError("expected a non negative integer or null")
    return v


def parse_event(ev: dict, check_sig: bool = True):
    """Check structure and signature (unless the caller already did: the store only holds events
    that were checked on the way in, and checking costs about 20 ms each in pure Python). Returns Identity, Delegation, Endorsement or Revocation.
    Raises EventInvalid."""
    try:
        if not isinstance(ev, dict):
            raise EventInvalid("not an object")
        if len(json.dumps(ev)) > MAX_EVENT_BYTES:
            raise EventInvalid("event too large")
        kind = ev.get("kind")
        if kind not in KINDS:
            raise EventInvalid("unknown kind")
        if check_sig and not verify_event(ev):
            raise EventInvalid("bad id or signature")
        body = json.loads(ev["content"])
        if not isinstance(body, dict) or body.get("v") != 1:
            raise EventInvalid("not a version 1 event")
        eid, pub, ts = ev["id"], _key(ev["pubkey"]), int(ev["created_at"])
        if kind == IDENTITY:
            if body.get("label") not in LABELS:
                raise ValueError("bad label")
            rec = body.get("recovery")
            sup = [t[1] for t in ev["tags"] if len(t) >= 3 and t[0] == "e" and t[2] == "supersedes"]
            if len(sup) > 1:
                raise ValueError("more than one supersedes")
            return Identity(eid, pub, ts, body["label"], _key(rec) if rec else None, str(body.get("note", ""))[:500],
                            _key(sup[0]) if sup else None)
        if kind == DELEGATION:
            lim = body.get("limits") or {}
            d = Delegation(eid, pub, _key(body["subject"]), ts, tuple(_scopes(body["scope"])),
                           int(body.get("not_before", 0)), _opt_int(body.get("expires")),
                           bool(body.get("redelegable", False)), _opt_int(lim.get("max_events_per_day")),
                           _opt_int(lim.get("max_bytes_per_day")))
            if d.subject == d.issuer:
                raise ValueError("a key cannot delegate to itself")
            _check_tag(ev, "p", d.subject)
            return d
        if kind == ENDORSEMENT:
            w = body["weight"]
            if isinstance(w, bool) or not isinstance(w, (int, float)) or not (0 < w <= 1):
                raise ValueError("weight must be in (0, 1]")
            e = Endorsement(eid, pub, _key(body["subject"]), ts, tuple(_scopes(body["scope"])), float(w),
                            bool(body.get("delegable", False)), _opt_int(body.get("expires")))
            if e.subject == e.issuer:
                raise ValueError("a key cannot endorse itself")
            _check_tag(ev, "p", e.subject)
            return e
        if kind == ATTESTATION:
            claim = body.get("claim")
            if claim not in CLAIM_CLASS:
                raise ValueError("unknown claim")
            subj = body["subject"]
            if not isinstance(subj, dict) or len(subj) != 1:
                raise ValueError("subject must name exactly one thing")
            (sk, sv), = subj.items()
            if sk not in ("x", "e") or not isinstance(sv, str) or not HEX64.match(sv):
                raise ValueError("bad subject")
            res = body.get("result")
            if not isinstance(res, dict):
                raise ValueError("bad result")
            ok = res.get("ok")
            match = res.get("match")
            if claim == "replication":
                if sk != "e" or not isinstance(match, bool):
                    raise ValueError("a replication refers to an event and says match true or false")
                ok = None
            else:
                match = None
                if claim in ("hash_verified", "format_scan") and (sk != "x" or not isinstance(ok, bool)):
                    raise ValueError(f"{claim} refers to a blob and says ok true or false")
                if ok is not None and not isinstance(ok, bool):
                    raise ValueError("ok must be true or false")
            meth = body.get("method") or {}
            tool_x = meth.get("tool_x")
            if tool_x is not None and not (isinstance(tool_x, str) and HEX64.match(tool_x)):
                raise ValueError("bad tool_x")
            _check_tag(ev, sk, sv)
            _check_tag(ev, "claim", claim)
            return Attestation(eid, pub, ts, claim, sk, sv, ok, match, str(res.get("detail", ""))[:500],
                               str(meth.get("tool", ""))[:100], tool_x, CLAIM_CLASS[claim])
        tk = body.get("target_kind")
        if tk not in TARGET_KINDS:
            raise ValueError("bad target_kind")
        target = body["target"]
        if not isinstance(target, str) or not HEX64.match(target):
            raise ValueError("bad target")
        _check_tag(ev, {"event": "e", "key": "p", "x": "x"}[tk], target)
        succ = body.get("successor")
        if succ is not None:
            if tk != "key" or not isinstance(succ, str) or not HEX64.match(succ) or succ == target:
                raise ValueError("bad successor")
            if not any(len(t) >= 3 and t[0] == "p" and t[1] == succ and t[2] == "successor" for t in ev["tags"]):
                raise ValueError("missing successor tag that matches the signed content")
        return Revocation(eid, pub, ts, tk, target, str(body.get("reason", ""))[:500],
                          str(body.get("severity", "normal")), bool(body.get("taint", False)), succ)
    except EventInvalid:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise EventInvalid(f"malformed: {type(e).__name__}: {e}") from e


def _check_tag(ev: dict, name: str, value: str) -> None:
    if not any(len(t) >= 2 and t[0] == name and t[1] == value for t in ev["tags"]):
        raise ValueError(f"missing {name} tag that matches the signed content")
