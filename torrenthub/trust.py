"""Local trust: who does a consumer believe, starting only from keys it pins itself.

Two different things, kept apart (PROTOCOL.md sections 3.3, 3.4, 5):

  * Delegation: "this key acts as me for these scopes". A fact anyone can check from the root.
    delegation_chain() finds a chain of unexpired, unrevoked delegations from a root to a signer.
  * Endorsement: "I think this key is reliable for these scopes". An opinion, weighed. trust()
    returns the largest product of weights over any path from a root, within a hop limit.

Everything is computed from a set of events and a time `now`, with no state kept between calls,
so the same events give the same answer in any order.

Revocation is applied in two passes so a revoker cannot cut off the very thing that makes it
trusted: first revocations by an event's own issuer (or a key's own recovery key), then, using
the graph that is left, revocations by keys the consumer trusts for scope "revoke".
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, replace

from .events import (
    DELEGATION, ENDORSEMENT, IDENTITY, REVOCATION, Attestation, Delegation, Derivation, Endorsement, EventInvalid, Identity,
    Revocation, parse_event,
)

DEFAULT_HOPS = 3
MAX_DELEGATION_DEPTH = 4
MAX_ROTATIONS = 8  # longest chain of key rotations followed
INDEPENDENT_BUDGET = 200_000  # search steps before independent_ex gives up on exactness
MAX_PATH_SETS = 256  # distinct intermediate-key sets kept per key
DERIVE_SCOPE = "derive"  # a key trusted for this has its derivation (lineage) claims believed
MAX_LINEAGE_DEPTH = 64  # longest chain of derivations followed


def covers(patterns, scope: str | None) -> bool:
    """Does a list of scope patterns cover `scope`? A scope of None means any scope will do."""
    if scope is None:
        return True
    return any(fnmatch.fnmatchcase(scope, p) for p in patterns)


@dataclass(frozen=True)
class Verdict:
    """What the attestations say about one blob and one claim, for one consumer.
    status: "satisfied" (enough independent, trusted attestors said ok), "negative" (a trusted
    attestor said it is not ok), or "unsatisfied" (not enough yet)."""

    status: str
    keys: tuple
    need: int
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "satisfied"


@dataclass(frozen=True)
class Trust:
    value: float
    path: tuple  # ((truster, subject, event_id), ...) from a root to the subject; empty for a root or no trust

    def __bool__(self) -> bool:
        return self.value > 0


NO_TRUST = Trust(0.0, ())


class Graph:
    def __init__(self, events, roots, now: int, hops: int = DEFAULT_HOPS, verified: bool = False):
        """`verified=True` means the events already passed signature checks (they came from the
        store). Structure is still checked."""
        self.roots = frozenset(roots)
        self.now = now
        self.hops = hops
        ids: dict[str, object] = {}
        for ev in events:
            try:
                p = parse_event(ev, check_sig=not verified)
            except EventInvalid:
                continue
            ids[p.id] = p
        self.parsed = ids
        self.identities = {i.pubkey: i for i in self._first_identities()}
        self.revoked_events: set[str] = set()
        self.revoked_keys: set[str] = set()
        self.revoked_x: dict[str, bool] = {}
        self.successors: dict[str, str] = {}
        self._apply_revocations()
        self.endorsements = self._inherit([e for e in ids.values() if isinstance(e, Endorsement) and self._live(e.id, e.issuer, e.expires, 0)])
        self.delegations = self._inherit([d for d in ids.values() if isinstance(d, Delegation)
                                          and self._live(d.id, d.issuer, d.expires, d.not_before)])
        self._edges: dict[str, list[Endorsement]] = {}
        for e in sorted(self.endorsements, key=lambda e: e.id):
            self._edges.setdefault(e.issuer, []).append(e)
        self._dels: dict[str, list[Delegation]] = {}
        for d in sorted(self.delegations, key=lambda d: d.id):
            self._dels.setdefault(d.issuer, []).append(d)
        self._cache: dict = {}
        self._rev = None
        self.derivations = [d for d in ids.values() if isinstance(d, Derivation)
                            and d.id not in self.revoked_events and d.issuer not in self.revoked_keys]
        self.attestations = [a for a in ids.values() if isinstance(a, Attestation)
                             and a.id not in self.revoked_events and a.issuer not in self.revoked_keys]
        self._by_subject: dict[tuple, list[Attestation]] = {}
        for a in sorted(self.attestations, key=lambda a: (a.created_at, a.id)):
            self._by_subject.setdefault((a.subject, a.claim), []).append(a)

    # -------------------------------------------------------------- building
    def _first_identities(self):
        by_key: dict[str, Identity] = {}
        for p in sorted((p for p in self.parsed.values() if isinstance(p, Identity)), key=lambda i: (i.created_at, i.id)):
            by_key.setdefault(p.pubkey, p)  # only the first identity event of a key is taken on trust
        return by_key.values()

    def recovery_of(self, key: str) -> str | None:
        i = self.identities.get(key)
        return i.recovery if i else None

    def successor_of(self, key: str) -> str | None:
        """The key that took over a rotated key's standing, following a chain of rotations. None if
        the key was not rotated, the chain loops, or it ends at a key that is itself revoked."""
        seen = {key}
        cur = self.successors.get(key)
        while cur is not None:
            if cur in seen or len(seen) > MAX_ROTATIONS:
                return None
            seen.add(cur)
            nxt = self.successors.get(cur)
            if nxt is None:
                return None if cur in self.revoked_keys else cur
            cur = nxt
        return None

    def _inherit(self, items):
        """Drop edges that point at a revoked key, except that edges to a rotated key now point at
        its successor. Edges the old key issued stay dead: the successor has to issue its own."""
        out = []
        for it in items:
            if it.subject in self.revoked_keys:
                succ = self.successor_of(it.subject)
                if succ is None or succ in self.revoked_keys:
                    continue
                it = replace(it, subject=succ)
            out.append(it)
        return out

    def _live(self, eid: str, issuer: str, expires, not_before) -> bool:
        if eid in self.revoked_events or issuer in self.revoked_keys:
            return False
        if expires is not None and expires <= self.now:
            return False
        return not_before <= self.now

    def _apply_revocations(self) -> None:
        revs = sorted((p for p in self.parsed.values() if isinstance(p, Revocation)), key=lambda r: (r.created_at, r.id))
        # Pass 1: the issuer of an event, a key itself, or a key's declared recovery key.
        later: list[Revocation] = []
        rotations: dict[str, list[tuple[bool, Revocation]]] = {}
        for r in revs:
            if r.target_kind == "event":
                t = self.parsed.get(r.target)
                if t is not None and getattr(t, "issuer", getattr(t, "pubkey", None)) == r.issuer:
                    self.revoked_events.add(r.target)
                else:
                    later.append(r)
            elif r.target_kind == "key":
                if r.issuer == r.target or self.recovery_of(r.target) == r.issuer:
                    self.revoked_keys.add(r.target)
                    if r.successor:
                        rotations.setdefault(r.target, []).append((r.issuer != r.target, r))
                else:
                    later.append(r)
            else:
                later.append(r)
        # Rotation. If the old key declared a recovery key, only the recovery key can hand its
        # standing on, so a thief holding the old key cannot name itself successor. Otherwise the
        # key can. The earliest valid statement wins. created_at is the signer's own clock, so a
        # thief of an unprotected key can backdate; that case is not fixable here (PROTOCOL.md 3.1).
        for old, cands in rotations.items():
            if self.recovery_of(old):
                cands = [c for c in cands if c[0]]
            if cands:
                self.successors[old] = min((c[1] for c in cands), key=lambda r: (r.created_at, r.id)).successor
        # Pass 2: keys this consumer trusts for the scope "revoke", judged on what pass 1 left.
        if not later:
            return
        base = Graph.__new__(Graph)
        base.roots, base.now, base.hops, base.parsed, base.identities = self.roots, self.now, self.hops, self.parsed, self.identities
        base.revoked_events, base.revoked_keys, base.revoked_x = set(self.revoked_events), set(self.revoked_keys), {}
        base.successors = self.successors
        base.endorsements = base._inherit([e for e in self.parsed.values() if isinstance(e, Endorsement)
                                           and base._live(e.id, e.issuer, e.expires, 0)])
        base._edges = {}
        for e in sorted(base.endorsements, key=lambda e: e.id):
            base._edges.setdefault(e.issuer, []).append(e)
        base._cache = {}
        for r in later:
            if r.issuer not in self.roots and not base.trust(r.issuer, "revoke"):
                continue
            if r.target_kind == "event":
                self.revoked_events.add(r.target)
            elif r.target_kind == "key":
                if r.target not in self.roots:  # a consumer's own roots are only changed by the consumer
                    self.revoked_keys.add(r.target)
            else:
                self.revoked_x[r.target] = self.revoked_x.get(r.target, False) or r.taint
        # Revocations of a blob hash by anyone a consumer trusts for "revoke" are collected above.
        # A revocation of a blob by its publisher goes through the same route, because a publisher
        # that is not trusted for "revoke" simply has no effect on this consumer.

    # ------------------------------------------------------------------ trust
    def _layers(self, scope):
        key = ("layers", scope)
        if key in self._cache:
            return self._cache[key]
        # best[h][node] = (product, pred) for the best path of exactly h edges that may still be
        # extended, so every edge on it is delegable. Roots start at product 1.
        best = [dict() for _ in range(self.hops + 1)]
        for r in sorted(self.roots):
            if r not in self.revoked_keys:
                best[0][r] = (1.0, None)
        for h in range(self.hops):
            for u in sorted(best[h]):
                prod, _ = best[h][u]
                for e in self._edges.get(u, ()):
                    if not covers(e.scope, scope) or not e.delegable:
                        continue
                    cand = prod * e.weight
                    cur = best[h + 1].get(e.subject)
                    if cur is None or cand > cur[0] + 1e-15 or (abs(cand - cur[0]) <= 1e-15 and (u, e.id) < cur[1][:2]):
                        best[h + 1][e.subject] = (cand, (u, e.id, h))
        self._cache[key] = best
        return best

    def trust(self, key: str, scope: str | None = None) -> Trust:
        """Largest product of endorsement weights from a root to `key` covering `scope`, within
        the hop limit. Roots have trust 1. `scope=None` asks whether there is any path at all."""
        if key in self.revoked_keys:
            return NO_TRUST
        if key in self.roots:
            return Trust(1.0, ())
        ck = ("trust", key, scope)
        if ck in self._cache:
            return self._cache[ck]
        best = self._layers(scope)
        result = NO_TRUST
        winner = None
        for h in range(self.hops):
            for u in sorted(best[h]):
                prod, _ = best[h][u]
                for e in self._edges.get(u, ()):
                    if e.subject != key or not covers(e.scope, scope):
                        continue
                    cand = prod * e.weight
                    if winner is None or cand > winner[0] + 1e-15 or (abs(cand - winner[0]) <= 1e-15 and (u, e.id) < winner[1:3]):
                        winner = (cand, u, e.id, h)
        if winner is not None:
            cand, u, eid, h = winner
            path = [(u, key, eid)]
            node, hh = u, h
            while hh > 0:
                _, pred = best[hh][node]
                pu, pe, ph = pred
                path.append((pu, node, pe))
                node, hh = pu, ph
            result = Trust(cand, tuple(reversed(path)))
        self._cache[ck] = result
        return result

    def reachable(self, key: str) -> bool:
        """Is this key in the graph at all: a root, endorsed for something, or a delegate?"""
        if key in self.roots and key not in self.revoked_keys:
            return True
        return bool(self.trust(key, None)) or any(self.delegation_chain(r, key, None) for r in sorted(self.roots))

    def independent(self, keys, scope: str | None, n: int, minimum: float = 0.0) -> list[str]:
        """Up to n keys, each with a trust path above `minimum`, such that the paths can be chosen
        to share no intermediate key and none of the keys sits on another's path. n keys back means
        the requirement is met. See independent_ex for whether the answer is exact."""
        return self.independent_ex(keys, scope, n, minimum)[0]

    def independent_ex(self, keys, scope: str | None, n: int, minimum: float = 0.0) -> tuple[list[str], bool]:
        """Like independent, and says whether the search finished. It looks at every admissible
        path of each key (hop limit, delegable edges, scope and weight all respected), not just the
        best one, and finds the largest set with pairwise disjoint paths by branch and bound. If
        that takes more than INDEPENDENT_BUDGET steps it stops and returns the better of what it
        has and the greedy answer, with exact False. Greedy never beats the exact answer, so the
        exact answer is at least as large as the old one."""
        greedy = self.independent_greedy(keys, scope, n, minimum)
        if len(greedy) >= n:
            return greedy, True  # nothing can beat n
        cands: dict[str, list[frozenset]] = {}
        for k in sorted(set(keys)):
            sets = self._path_sets(k, scope, minimum)
            if sets:
                cands[k] = sets
        order = sorted(cands, key=lambda k: (-self.trust(k, scope).value, k))
        best: list[str] = []
        budget = [INDEPENDENT_BUDGET]
        exact = True

        def rec(i: int, used: frozenset, chosen: list[str]) -> bool:
            """True when the search should stop (n found or budget gone)."""
            nonlocal best, exact
            if len(chosen) > len(best):
                best = chosen[:]
                if len(best) >= n:
                    return True
            if i >= len(order) or len(chosen) + (len(order) - i) <= len(best):
                return False
            budget[0] -= 1
            if budget[0] <= 0:
                exact = False
                return True
            k = order[i]
            for mids in cands[k]:
                mine = mids | {k}
                if not (mine & used):
                    chosen.append(k)
                    stop = rec(i + 1, used | mine, chosen)
                    chosen.pop()
                    if stop:
                        return True
            return rec(i + 1, used, chosen)  # or leave this key out

        rec(0, frozenset(), [])
        if len(greedy) > len(best):
            best = greedy
        return best[:n], exact

    def independent_greedy(self, keys, scope: str | None, n: int, minimum: float = 0.0) -> list[str]:
        """Best trust first, each key's single best path. A lower bound on independent()."""
        scored = []
        for k in sorted(set(keys)):
            t = self.trust(k, scope)
            if t.value > minimum:
                scored.append((-t.value, k, t))
        scored.sort(key=lambda x: (x[0], x[1]))
        chosen: list[str] = []
        used: set[str] = set()
        for _, k, t in scored:
            mids = {s for (_, s, _) in t.path[:-1]}
            mine = mids | {k}
            if mine & used:
                continue
            chosen.append(k)
            used |= mine
            if len(chosen) == n:
                break
        return chosen

    def _path_sets(self, key: str, scope: str | None, minimum: float) -> list[frozenset]:
        """The intermediate keys of every admissible root-to-`key` path, smallest first, dropping
        any set that contains another (it can only be worse). Admissible means what trust() means:
        within the hop limit, every edge covers the scope, every edge but the last is delegable,
        and the product of weights is above `minimum`."""
        ck = ("paths", key, scope, minimum)
        if ck in self._cache:
            return self._cache[ck]
        if self._rev is None:
            rev: dict[str, list[Endorsement]] = {}
            for e in self.endorsements:
                rev.setdefault(e.subject, []).append(e)
            self._rev = rev
        found: set[frozenset] = set()

        def back(node: str, prod: float, depth: int, mids: frozenset, first: bool) -> None:
            for e in self._rev.get(node, ()):
                if not covers(e.scope, scope) or (not first and not e.delegable):
                    continue
                p = prod * e.weight
                if p <= minimum:
                    continue
                u = e.issuer
                if u in self.roots:
                    if u not in self.revoked_keys:
                        found.add(mids)
                    continue
                if depth + 1 < self.hops and u != key and u not in mids:
                    back(u, p, depth + 1, mids | {u}, False)

        if key in self.roots:
            found.add(frozenset()) if key not in self.revoked_keys else None
        elif key not in self.revoked_keys:
            back(key, 1.0, 0, frozenset(), True)
        out: list[frozenset] = []
        for m in sorted(found, key=lambda m: (len(m), sorted(m))):
            if not any(o <= m for o in out):
                out.append(m)
        out = out[:MAX_PATH_SETS]
        self._cache[ck] = out
        return out

    # ------------------------------------------------------------- delegation
    def delegation_chain(self, root: str, signer: str, scope: str | None):
        """A chain of delegations from `root` to `signer` that covers `scope`, or None. The root
        may sign for itself. Every link must cover the scope, be in date and unrevoked, and every
        link except the last must be redelegable."""
        if root in self.revoked_keys or signer in self.revoked_keys:
            return None
        if root == signer:
            return ()
        ck = ("chain", root, signer, scope)
        if ck in self._cache:
            return self._cache[ck]
        found = None
        frontier = [(root, ())]
        seen = {root}
        for _ in range(MAX_DELEGATION_DEPTH):
            nxt = []
            for node, chain in frontier:
                for d in self._dels.get(node, ()):
                    if not covers(d.scope, scope):
                        continue
                    if d.subject == signer:
                        found = chain + (d,)
                        break
                    if d.redelegable and d.subject not in seen:
                        seen.add(d.subject)
                        nxt.append((d.subject, chain + (d,)))
                if found:
                    break
            if found or not nxt:
                break
            frontier = nxt
        self._cache[ck] = found
        return found

    def may_sign(self, roots, signer: str, scope: str):
        """For a rule like `signed:ROOT`: is `signer` one of `roots`, or a delegate of one for `scope`?"""
        for r in sorted(roots):
            c = self.delegation_chain(r, signer, scope)
            if c is not None:
                return r, c
        return None

    # --------------------------------------------------------------- revoked
    def blob_status(self, x: str) -> str | None:
        """None if nothing trusted revoked this blob, "revoked" if it was, "tainted" if it was
        revoked with taint (so things derived from it are affected too), "descended" if it was
        not revoked but a trusted derivation says it came from a blob that was revoked with taint."""
        if x in self.revoked_x:
            return "tainted" if self.revoked_x[x] else "revoked"
        if x in self.tainted_descendants():
            return "descended"
        return None

    # --------------------------------------------------------------- lineage
    def trusted_derivations(self, min_trust: float = 0.0) -> list[Derivation]:
        """Derivations whose issuer is a root or is trusted for scope "derive". Anyone can publish
        a derivation event, and a false one could taint an innocent blob or hide a bad ancestor,
        so lineage counts only from keys this consumer already trusts for it."""
        ck = ("derivs", min_trust)
        if ck not in self._cache:
            ok: dict[str, bool] = {}
            out = []
            for d in sorted(self.derivations, key=lambda d: (d.created_at, d.id)):
                if d.issuer not in ok:
                    ok[d.issuer] = d.issuer in self.roots or self.trust(d.issuer, DERIVE_SCOPE).value > min_trust
                if ok[d.issuer]:
                    out.append(d)
            self._cache[ck] = out
        return self._cache[ck]

    def _lineage_index(self, min_trust: float = 0.0):
        ck = ("lineage", min_trust)
        if ck not in self._cache:
            by_out: dict[str, list[Derivation]] = {}
            by_in: dict[str, list[Derivation]] = {}
            for d in self.trusted_derivations(min_trust):
                for x, _, _ in d.outputs:
                    by_out.setdefault(x, []).append(d)
                for x in d.inputs:
                    by_in.setdefault(x, []).append(d)
            self._cache[ck] = (by_out, by_in)
        return self._cache[ck]

    def parents(self, x: str, min_trust: float = 0.0) -> list[Derivation]:
        """Trusted derivations that list `x` as an output."""
        return list(self._lineage_index(min_trust)[0].get(x, ()))

    def children(self, x: str, min_trust: float = 0.0) -> list[Derivation]:
        """Trusted derivations that list `x` as an input."""
        return list(self._lineage_index(min_trust)[1].get(x, ()))

    def ancestors(self, x: str, min_trust: float = 0.0) -> set[str]:
        by_out = self._lineage_index(min_trust)[0]
        seen: set[str] = set()
        todo = [x]
        while todo:
            for d in by_out.get(todo.pop(), ()):
                for i in d.inputs:
                    if i not in seen and i != x:
                        seen.add(i)
                        todo.append(i)
        return seen

    def tainted_descendants(self, min_trust: float = 0.0) -> dict[str, str]:
        """Every blob that trusted lineage says descends from a blob revoked with taint, mapped to
        the revoked blob it descends from (one of them, the lowest hash, if several)."""
        ck = ("tainted", min_trust)
        if ck in self._cache:
            return self._cache[ck]
        by_in = self._lineage_index(min_trust)[1]
        out: dict[str, str] = {}
        for src in sorted(x for x, t in self.revoked_x.items() if t):
            todo = [src]
            seen = {src}
            while todo:
                for d in by_in.get(todo.pop(), ()):
                    for x, _, _ in d.outputs:
                        if x not in seen:
                            seen.add(x)
                            todo.append(x)
                            if x not in self.revoked_x:
                                out.setdefault(x, src)
        self._cache[ck] = out
        return out

    def synthetic_depth(self, x: str, min_trust: float = 0.0) -> int:
        """A lower bound on how many generations of synthetic data lie behind `x`: the largest
        depth any trusted derivation declares for it, or one more than an input's depth when the
        derivation says its data is synthetic or mixed. Undeclared synthetic data cannot be seen."""
        by_out = self._lineage_index(min_trust)[0]
        memo: dict[str, int] = {}

        def depth(blob: str, trail: frozenset) -> int:
            if blob in memo:
                return memo[blob]
            if blob in trail or len(trail) >= MAX_LINEAGE_DEPTH:
                return 0
            best = 0
            for d in by_out.get(blob, ()):
                inner = max((depth(i, trail | {blob}) for i in d.inputs), default=0)
                best = max(best, d.synthetic_depth, inner + (1 if d.data_origin in ("synthetic", "mixed") else 0))
            memo[blob] = best
            return best

        return depth(x, frozenset())

    def derivation_class(self, d: Derivation, trusted_tools) -> str:
        """D if this consumer lists the tool's hash as bit exact, otherwise S (self reported)."""
        return "D" if d.tool_x and d.tool_x in set(trusted_tools) else "S"

    # ----------------------------------------------------------- attestations
    def refuted_attestors(self) -> dict[str, str]:
        """Keys with an attestation that a trusted replicator found does not hold, mapped to the
        replication event that says so. A refuted attestor counts for nothing, for any claim, in
        this consumer's view. The replicator must be trusted for scope attest:replication and must
        not be the attestor itself."""
        if "refuted" in self._cache:
            return self._cache["refuted"]
        out: dict[str, str] = {}
        for r in sorted((a for a in self.attestations if a.claim == "replication" and a.match is False), key=lambda a: (a.created_at, a.id)):
            target = self.parsed.get(r.subject)
            if not isinstance(target, Attestation) or target.issuer == r.issuer:
                continue
            if self.trust(r.issuer, "attest:replication"):
                out.setdefault(target.issuer, r.id)
        self._cache["refuted"] = out
        return out

    def attestors(self, x: str, claim: str, ok: bool = True) -> list[str]:
        bad = self.refuted_attestors()
        return sorted({a.issuer for a in self._by_subject.get((x, claim), ()) if a.ok is ok and a.issuer not in bad})

    def verdict(self, x: str, claim: str, n: int = 1, min_trust: float = 0.0) -> Verdict:
        """Do enough independent, trusted attestors say `claim` holds for blob `x`? One trusted
        attestor saying it does not hold (a failed scan) settles it as negative."""
        scope = f"attest:{claim}"
        floor = max(min_trust - 1e-12, 0.0)
        negatives = [k for k in self.attestors(x, claim, ok=False) if self.trust(k, scope).value > floor]
        if negatives:
            return Verdict("negative", tuple(negatives), n, f"{len(negatives)} trusted attestor(s) report a failed {claim}")
        chosen = self.independent(self.attestors(x, claim, ok=True), scope, n, minimum=floor)
        if len(chosen) >= n:
            return Verdict("satisfied", tuple(chosen), n)
        return Verdict("unsatisfied", tuple(chosen), n, f"{len(chosen)} of {n} independent trusted attestors for {claim}")

