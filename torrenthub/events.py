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

import hashlib
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
DERIVATION = 36783
REQUEST = 36784
CLAIM = 36785
RESULT = 36786
KINDS = (IDENTITY, DELEGATION, ENDORSEMENT, REVOCATION, ATTESTATION, DERIVATION, REQUEST, CLAIM, RESULT)

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
DATA_ORIGINS = ("human", "synthetic", "mixed", "unknown")
TASK_RE = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,63}$")
WANTS = ("attestation", "artifact")
RESULT_STATUSES = ("done", "failed", "declined")
MAX_DEADLINE_SECONDS = 30 * 86400  # a request cannot stay open longer than this
MAX_REQUEST_INPUTS = 16
MAX_REWARD_LEN = 200
MAX_DERIVATION_REFS = 32
MAX_ARGS_BYTES = 2000
MAX_SYNTHETIC_DEPTH = 64
INFOHASH_RE = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")


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
class Derivation:
    """Outputs made from inputs by a named tool. What the issuer says, not what is true: it is
    class D only for a consumer that lists the tool's hash as bit exact (PROTOCOL.md 3.5)."""
    id: str
    issuer: str
    created_at: int
    inputs: tuple[str, ...]  # sha256 of each input blob
    outputs: tuple[tuple[str, str | None, int | None], ...]  # (sha256, infohash, size)
    tool: str
    tool_x: str | None  # sha256 of the tool or its container image
    args: dict
    data_origin: str
    synthetic_depth: int
    licences: dict  # {"inputs": {sha256: licence}, "output": licence}


@dataclass(frozen=True)
class Request:
    """Someone asks for work (PROTOCOL.md 3.8). It is a request, not an order: anyone may ignore
    it, and it carries no payment. `reward` is an opaque pointer to wherever settlement happens."""
    id: str
    issuer: str
    created_at: int
    task: str
    inputs: tuple[str, ...]
    args: dict
    spec_x: str | None
    deadline: int
    reward: str | None
    want: str  # "attestation": the answer is attestation events; "artifact": the answer is new blobs


@dataclass(frozen=True)
class Claim:
    """"I am working on this", good until `expires`. Advisory: it stops nobody else and proves
    nothing, and a claim that never turns into a result simply lapses."""
    id: str
    issuer: str
    created_at: int
    request: str
    expires: int


@dataclass(frozen=True)
class Result:
    """A worker's answer to a request. The substance is in what it points at: attestation events
    the worker signed, or output blobs (with a derivation event saying how they were made)."""
    id: str
    issuer: str
    created_at: int
    request: str
    status: str
    attestations: tuple[str, ...]
    outputs: tuple[tuple[str, str | None, int | None], ...]  # (sha256, infohash, size)
    derivation: str | None
    note: str


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


def _signed(secret: bytes, kind: int, tags: list, content: str, created_at: int) -> dict:
    """Sign an event, adding a `d` tag made from its content unless it has one.

    Every kind here is in NIP-01's addressable range (30000 to 39999), where a relay keeps only the
    latest event per kind, key and `d` tag, and a missing `d` counts as the empty string. Without
    this, a relay would keep one endorsement per key, one attestation per key, and so on. With it,
    events with different content never share an address, and identical content (the same meaning)
    does. Nothing here reads the tag, so events from before this change still parse."""
    if not any(len(t) >= 2 and t[0] == "d" for t in tags):
        tags = [*tags, ["d", hashlib.sha256(content.encode()).hexdigest()[:32]]]
    return sign_event(secret, kind, tags, content, created_at)


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
    return _signed(secret, IDENTITY, tags, _dump(body), _now(created_at))


def build_delegation(secret: bytes, subject: str, scope, *, not_before: int = 0, expires: int | None = None,
                     redelegable: bool = False, max_events_per_day: int | None = None,
                     max_bytes_per_day: int | None = None, created_at: int | None = None) -> dict:
    body = {
        "v": 1, "subject": _key(subject), "scope": _scopes(scope), "not_before": int(not_before),
        "expires": None if expires is None else int(expires), "redelegable": bool(redelegable),
        "limits": {"max_events_per_day": max_events_per_day, "max_bytes_per_day": max_bytes_per_day},
    }
    return _signed(secret, DELEGATION, [["p", subject]], _dump(body), _now(created_at))


def build_endorsement(secret: bytes, subject: str, scope, weight: float, *, delegable: bool = False,
                      expires: int | None = None, created_at: int | None = None) -> dict:
    if isinstance(weight, bool) or not (0 < weight <= 1):
        raise ValueError("weight must be in (0, 1]")
    body = {
        "v": 1, "subject": _key(subject), "scope": _scopes(scope), "weight": float(weight),
        "delegable": bool(delegable), "expires": None if expires is None else int(expires),
    }
    return _signed(secret, ENDORSEMENT, [["p", subject]], _dump(body), _now(created_at))


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
    return _signed(secret, REVOCATION, tags, _dump(body), _now(created_at))


def build_derivation(secret: bytes, inputs: list[str], outputs: list[dict], tool: str, *, tool_x: str | None = None,
                     args: dict | None = None, data_origin: str = "unknown", synthetic_depth: int = 0,
                     licences: dict | None = None, created_at: int | None = None) -> dict:
    """`outputs` is a list of {"x": sha256, "i": infohash or None, "size": bytes or None}."""
    args = args or {}
    licences = licences or {}
    ins = sorted(set(inputs))
    if not 1 <= len(ins) <= MAX_DERIVATION_REFS or not all(HEX64.match(x) for x in ins):
        raise ValueError(f"inputs: 1 to {MAX_DERIVATION_REFS} sha256 values")
    if not 1 <= len(outputs) <= MAX_DERIVATION_REFS:
        raise ValueError(f"outputs: 1 to {MAX_DERIVATION_REFS} entries")
    outs, seen = [], set()
    for o in outputs:
        x, i, size = o["x"], o.get("i"), o.get("size")
        if not HEX64.match(x) or x in seen:
            raise ValueError("each output needs its own sha256")
        if x in ins:
            raise ValueError("an output cannot also be an input")
        if i is not None and not INFOHASH_RE.match(i):
            raise ValueError("bad infohash")
        _opt_int(size)
        seen.add(x)
        outs.append({"x": x, "i": i, "size": size})
    outs.sort(key=lambda o: o["x"])
    if not tool or len(tool) > 100:
        raise ValueError("tool needs a name of up to 100 characters")
    if tool_x is not None and not HEX64.match(tool_x):
        raise ValueError("tool_x must be 64 hex characters")
    if data_origin not in DATA_ORIGINS:
        raise ValueError(f"data_origin must be one of {DATA_ORIGINS}")
    if isinstance(synthetic_depth, bool) or not isinstance(synthetic_depth, int) or not 0 <= synthetic_depth <= MAX_SYNTHETIC_DEPTH:
        raise ValueError(f"synthetic_depth must be 0 to {MAX_SYNTHETIC_DEPTH}")
    if len(_dump(args)) > MAX_ARGS_BYTES:
        raise ValueError(f"args are over {MAX_ARGS_BYTES} bytes")
    lic_in = {x: str(v)[:100] for x, v in (licences.get("inputs") or {}).items() if x in ins}
    body = {"v": 1, "inputs": [{"x": x} for x in ins], "outputs": outs,
            "recipe": {"tool": tool, "tool_x": tool_x, "args": args}, "data_origin": data_origin,
            "synthetic_depth": synthetic_depth, "licences": {"inputs": lic_in, "output": str(licences.get("output", ""))[:100]}}
    tags = [["x", x, "input"] for x in ins] + [["x", o["x"], "output"] for o in outs]
    tags += [["i", o["i"]] for o in outs if o["i"]]
    return _signed(secret, DERIVATION, tags, _dump(body), _now(created_at))


def build_request(secret: bytes, task: str, inputs: list[str], *, args: dict | None = None, spec_x: str | None = None,
                  deadline: int, want: str = "attestation", reward: str | None = None, created_at: int | None = None) -> dict:
    ts = _now(created_at)
    if not isinstance(task, str) or not TASK_RE.match(task):
        raise ValueError("task: lowercase letters, digits and _ . : - , up to 64")
    ins = sorted(set(inputs))
    if len(ins) > MAX_REQUEST_INPUTS or not all(isinstance(x, str) and HEX64.match(x) for x in ins):
        raise ValueError(f"inputs: up to {MAX_REQUEST_INPUTS} sha256 values")
    args = args or {}
    if not isinstance(args, dict) or len(_dump(args)) > MAX_ARGS_BYTES:
        raise ValueError(f"args must be an object under {MAX_ARGS_BYTES} bytes")
    if spec_x is not None and not HEX64.match(spec_x):
        raise ValueError("spec_x must be 64 hex characters")
    if isinstance(deadline, bool) or not isinstance(deadline, int) or not ts < deadline <= ts + MAX_DEADLINE_SECONDS:
        raise ValueError(f"deadline must be after the request and within {MAX_DEADLINE_SECONDS // 86400} days of it")
    if want not in WANTS:
        raise ValueError(f"want must be one of {WANTS}")
    if reward is not None and (not isinstance(reward, str) or len(reward) > MAX_REWARD_LEN):
        raise ValueError(f"reward is an opaque string of up to {MAX_REWARD_LEN} characters")
    body = {"v": 1, "task": task, "inputs": [{"x": x} for x in ins], "spec": {"args": args, "spec_x": spec_x},
            "deadline": deadline, "reward": reward, "want": want}
    tags = [["task", task]] + [["x", x, "input"] for x in ins]
    return _signed(secret, REQUEST, tags, _dump(body), ts)


def build_claim(secret: bytes, request_id: str, *, expires: int, created_at: int | None = None) -> dict:
    ts = _now(created_at)
    if not HEX64.match(request_id):
        raise ValueError("request id must be 64 hex characters")
    if isinstance(expires, bool) or not isinstance(expires, int) or expires <= ts:
        raise ValueError("expires must be after the claim")
    return _signed(secret, CLAIM, [["e", request_id, "request"]], _dump({"v": 1, "request": request_id, "expires": expires}), ts)


def build_result(secret: bytes, request_id: str, status: str = "done", *, attestations: list[str] | None = None,
                 outputs: list[dict] | None = None, derivation: str | None = None, note: str = "",
                 created_at: int | None = None) -> dict:
    if not HEX64.match(request_id):
        raise ValueError("request id must be 64 hex characters")
    if status not in RESULT_STATUSES:
        raise ValueError(f"status must be one of {RESULT_STATUSES}")
    atts = sorted(set(attestations or []))
    outs = sorted(({"x": o["x"], "i": o.get("i"), "size": o.get("size")} for o in (outputs or [])), key=lambda o: o["x"])
    if len(atts) > MAX_REQUEST_INPUTS or len(outs) > MAX_DERIVATION_REFS or not all(HEX64.match(a) for a in atts):
        raise ValueError("too many or malformed attestations or outputs")
    for o in outs:
        if not HEX64.match(o["x"]) or (o["i"] is not None and not INFOHASH_RE.match(o["i"])):
            raise ValueError("malformed output")
        _opt_int(o["size"])
    if derivation is not None and not HEX64.match(derivation):
        raise ValueError("derivation must be an event id")
    if status != "done" and (atts or outs):
        raise ValueError("only a done result carries attestations or outputs")
    body = {"v": 1, "request": request_id, "status": status, "attestations": atts, "outputs": outs,
            "derivation": derivation, "note": note[:500]}
    tags = [["e", request_id, "request"]] + [["e", a, "attestation"] for a in atts] + [["x", o["x"], "output"] for o in outs]
    if derivation:
        tags.append(["e", derivation, "derivation"])
    return _signed(secret, RESULT, tags, _dump(body), _now(created_at))


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
    return _signed(secret, ATTESTATION, [[subject_kind, subject], ["claim", claim]], _dump(body), _now(created_at))


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
        if kind == DERIVATION:
            return _parse_derivation(ev, body, eid, pub, ts)
        if kind in (REQUEST, CLAIM, RESULT):
            return _parse_work(kind, ev, body, eid, pub, ts)
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


def _parse_derivation(ev: dict, body: dict, eid: str, pub: str, ts: int) -> Derivation:
    ins = body["inputs"]
    outs = body["outputs"]
    if not (isinstance(ins, list) and isinstance(outs, list) and 1 <= len(ins) <= MAX_DERIVATION_REFS
            and 1 <= len(outs) <= MAX_DERIVATION_REFS):
        raise ValueError("bad inputs or outputs")
    in_x = [i["x"] for i in ins]
    out_rows = []
    for o in outs:
        x, i, size = o["x"], o.get("i"), _opt_int(o.get("size"))
        if i is not None and not (isinstance(i, str) and INFOHASH_RE.match(i)):
            raise ValueError("bad infohash")
        out_rows.append((x, i, size))
    out_x = [r[0] for r in out_rows]
    if not all(isinstance(x, str) and HEX64.match(x) for x in in_x + out_x):
        raise ValueError("bad sha256")
    if len(set(in_x)) != len(in_x) or len(set(out_x)) != len(out_x) or set(in_x) & set(out_x):
        raise ValueError("inputs and outputs must be distinct")
    rec = body["recipe"]
    tool, tool_x, args = rec["tool"], rec.get("tool_x"), rec.get("args") or {}
    if not isinstance(tool, str) or not 0 < len(tool) <= 100:
        raise ValueError("bad tool")
    if tool_x is not None and not (isinstance(tool_x, str) and HEX64.match(tool_x)):
        raise ValueError("bad tool_x")
    if not isinstance(args, dict) or len(_dump(args)) > MAX_ARGS_BYTES:
        raise ValueError("bad args")
    origin, depth = body["data_origin"], body["synthetic_depth"]
    if origin not in DATA_ORIGINS:
        raise ValueError("bad data_origin")
    if isinstance(depth, bool) or not isinstance(depth, int) or not 0 <= depth <= MAX_SYNTHETIC_DEPTH:
        raise ValueError("bad synthetic_depth")
    lic = body.get("licences") or {}
    lic_in = lic.get("inputs") or {}
    if not isinstance(lic_in, dict) or not all(k in in_x and isinstance(v, str) for k, v in lic_in.items()):
        raise ValueError("bad licences")
    for x in in_x:
        _check_tag(ev, "x", x)
    for x, i, _ in out_rows:
        _check_tag(ev, "x", x)
        if i:
            _check_tag(ev, "i", i)
    return Derivation(eid, pub, ts, tuple(sorted(in_x)), tuple(sorted(out_rows, key=lambda r: r[0])), tool, tool_x, args,
                      origin, depth, {"inputs": {k: v[:100] for k, v in lic_in.items()}, "output": str(lic.get("output", ""))[:100]})


def _parse_work(kind: int, ev: dict, body: dict, eid: str, pub: str, ts: int):
    if kind == REQUEST:
        task, want, deadline = body["task"], body["want"], body["deadline"]
        if not isinstance(task, str) or not TASK_RE.match(task) or want not in WANTS:
            raise ValueError("bad task or want")
        if isinstance(deadline, bool) or not isinstance(deadline, int) or not ts < deadline <= ts + MAX_DEADLINE_SECONDS:
            raise ValueError("bad deadline")
        ins = [i["x"] for i in body["inputs"]]
        if len(ins) > MAX_REQUEST_INPUTS or len(set(ins)) != len(ins) or not all(isinstance(x, str) and HEX64.match(x) for x in ins):
            raise ValueError("bad inputs")
        spec = body.get("spec") or {}
        args, spec_x = spec.get("args") or {}, spec.get("spec_x")
        if not isinstance(args, dict) or len(_dump(args)) > MAX_ARGS_BYTES or (spec_x is not None and not (isinstance(spec_x, str) and HEX64.match(spec_x))):
            raise ValueError("bad spec")
        reward = body.get("reward")
        if reward is not None and (not isinstance(reward, str) or len(reward) > MAX_REWARD_LEN):
            raise ValueError("bad reward")
        _check_tag(ev, "task", task)
        for x in ins:
            _check_tag(ev, "x", x)
        return Request(eid, pub, ts, task, tuple(sorted(ins)), args, spec_x, deadline, reward, want)
    rid = body["request"]
    if not isinstance(rid, str) or not HEX64.match(rid):
        raise ValueError("bad request id")
    _check_tag(ev, "e", rid)
    if kind == CLAIM:
        exp = body["expires"]
        if isinstance(exp, bool) or not isinstance(exp, int) or exp <= ts:
            raise ValueError("bad expires")
        return Claim(eid, pub, ts, rid, exp)
    status = body["status"]
    if status not in RESULT_STATUSES:
        raise ValueError("bad status")
    atts = body.get("attestations") or []
    outs_raw = body.get("outputs") or []
    if not (isinstance(atts, list) and isinstance(outs_raw, list)) or len(atts) > MAX_REQUEST_INPUTS or len(outs_raw) > MAX_DERIVATION_REFS:
        raise ValueError("bad attestations or outputs")
    if not all(isinstance(a, str) and HEX64.match(a) for a in atts):
        raise ValueError("bad attestation id")
    outs = []
    for o in outs_raw:
        x, i, size = o["x"], o.get("i"), _opt_int(o.get("size"))
        if not (isinstance(x, str) and HEX64.match(x)) or (i is not None and not (isinstance(i, str) and INFOHASH_RE.match(i))):
            raise ValueError("bad output")
        outs.append((x, i, size))
    if status != "done" and (atts or outs):
        raise ValueError("only a done result carries attestations or outputs")
    der = body.get("derivation")
    if der is not None and not (isinstance(der, str) and HEX64.match(der)):
        raise ValueError("bad derivation id")
    for a in atts:
        _check_tag(ev, "e", a)
    for x, _, _ in outs:
        _check_tag(ev, "x", x)
    if der:
        _check_tag(ev, "e", der)
    return Result(eid, pub, ts, rid, status, tuple(sorted(atts)), tuple(sorted(outs, key=lambda o: o[0])), der, str(body.get("note", ""))[:500])


def _check_tag(ev: dict, name: str, value: str) -> None:
    if not any(len(t) >= 2 and t[0] == name and t[1] == value for t in ev["tags"]):
        raise ValueError(f"missing {name} tag that matches the signed content")
