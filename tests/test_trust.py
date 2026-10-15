"""Trust: the properties PROTOCOL.md section 5 promises, each as a test. No network."""

from __future__ import annotations

import random

import pytest

from torrenthub import events as E
from torrenthub import signing as sg
from torrenthub.trust import Graph

NOW = 1_000_000


def key(n: int) -> bytes:
    return n.to_bytes(32, "big")


def pub(n: int) -> str:
    return sg.public_key(key(n)).hex()


ROOT, A, B, C, D, X, Y, Z = (pub(i) for i in (1, 2, 3, 4, 5, 6, 7, 8))
R = 1  # secret index for the root


def endorse(frm, to, scope="*", w=0.9, delegable=True, expires=None, at=100):
    return E.build_endorsement(key(frm), pub(to), [scope], w, delegable=delegable, expires=expires, created_at=at)


def delegate(frm, to, scope="publish:acme/*", **kw):
    return E.build_delegation(key(frm), pub(to), [scope], created_at=kw.pop("at", 100), **kw)


def graph(events, roots=(ROOT,), hops=3, now=NOW):
    return Graph(events, roots, now, hops)


# ---------------------------------------------------------------- basics

def test_roots_are_trusted_and_strangers_are_not():
    g = graph([])
    assert g.trust(ROOT).value == 1.0
    assert g.trust(A).value == 0.0 and not g.trust(A)


def test_weights_multiply_along_a_path_and_the_path_explains_it():
    evs = [endorse(1, 2, w=0.8), endorse(2, 3, w=0.5), endorse(3, 4, w=0.5, delegable=False)]
    g = graph(evs)
    assert g.trust(A).value == pytest.approx(0.8)
    assert g.trust(B).value == pytest.approx(0.4)
    t = g.trust(C)
    assert t.value == pytest.approx(0.2)
    assert [(a, b) for a, b, _ in t.path] == [(ROOT, A), (A, B), (B, C)]


def test_a_non_delegable_endorsement_does_not_pass_trust_on():
    evs = [endorse(1, 2, delegable=False), endorse(2, 3)]
    g = graph(evs)
    assert g.trust(A).value > 0
    assert g.trust(B).value == 0


def test_hop_limit():
    chain = [endorse(1, 2), endorse(2, 3), endorse(3, 4), endorse(4, 5)]
    assert graph(chain, hops=3).trust(C).value > 0
    assert graph(chain, hops=3).trust(D).value == 0
    assert graph(chain, hops=4).trust(D).value > 0


def test_scopes():
    evs = [endorse(1, 2, scope="eval:*"), endorse(1, 3, scope="*")]
    g = graph(evs)
    assert g.trust(A, "eval:perplexity").value > 0
    assert g.trust(A, "publish:acme/x").value == 0
    assert g.trust(A, None).value > 0  # any path at all
    assert g.trust(B, "anything").value > 0


def test_the_best_path_wins():
    evs = [endorse(1, 2, w=0.9), endorse(2, 4, w=0.9), endorse(1, 3, w=0.5), endorse(3, 4, w=1.0)]
    t = graph(evs).trust(C)
    assert t.value == pytest.approx(0.81)
    assert t.path[0][1] == A


def test_expiry():
    e = endorse(1, 2, expires=NOW + 10)
    assert graph([e], now=NOW).trust(A).value > 0
    assert graph([e], now=NOW + 10).trust(A).value == 0


# ------------------------------------------------------- sybils and collusion

def test_a_swarm_of_keys_vouching_for_each_other_has_no_trust():
    sybils = list(range(100, 110))
    evs = [endorse(a, b, w=1.0) for a in sybils for b in sybils if a != b]
    g = graph(evs)
    assert all(g.trust(pub(s)).value == 0 for s in sybils)
    assert not g.reachable(pub(100))


def test_a_cluster_behind_one_honest_endorsement_is_capped_and_never_independent():
    evs = [endorse(1, 2, w=0.7)] + [endorse(2, n, w=1.0, delegable=False) for n in range(100, 105)]
    g = graph(evs, hops=3)
    cluster = [pub(n) for n in range(100, 105)]
    assert all(g.trust(k).value <= 0.7 + 1e-9 for k in cluster)
    assert len(g.independent(cluster, None, 2)) == 1


def test_attestors_reached_by_separate_paths_are_independent():
    evs = [endorse(1, 2, w=0.9), endorse(1, 3, w=0.9), endorse(2, 6, w=0.9, delegable=False), endorse(3, 7, w=0.9, delegable=False)]
    g = graph(evs)
    assert sorted(g.independent([X, Y], None, 2)) == sorted([X, Y])


def test_an_attestor_on_another_attestors_path_is_not_independent():
    evs = [endorse(1, 2, w=0.9), endorse(2, 6, w=0.9, delegable=False)]
    g = graph(evs)
    assert len(g.independent([A, X], None, 2)) == 1


def test_min_trust_filters_attestors():
    evs = [endorse(1, 2, w=0.3, delegable=False), endorse(1, 3, w=0.9, delegable=False)]
    g = graph(evs)
    assert g.independent([A, B], None, 2, minimum=0.5) == [B]


# ------------------------------------------------------------- revocation

def test_revoking_one_edge_removes_what_depended_on_it_and_nothing_else():
    e1, e2 = endorse(1, 2, w=0.9), endorse(2, 4, w=0.9, delegable=False)
    e3, e4 = endorse(1, 3, w=0.9), endorse(3, 5, w=0.9, delegable=False)
    rev = E.build_revocation(key(2), "event", e2["id"], created_at=200)
    g = graph([e1, e2, e3, e4, rev])
    assert g.trust(C).value == 0
    assert g.trust(A).value > 0 and g.trust(B).value > 0 and g.trust(D).value > 0


def test_only_the_issuer_can_revoke_an_event():
    e = endorse(1, 2)
    stranger = E.build_revocation(key(99), "event", e["id"], created_at=200)
    assert graph([e, stranger]).trust(A).value > 0
    issuer = E.build_revocation(key(R), "event", e["id"], created_at=200)
    assert graph([e, issuer]).trust(A).value == 0


def test_a_key_can_revoke_itself_and_so_can_its_declared_recovery_key():
    e1, e2 = endorse(1, 2), endorse(2, 3, delegable=False)
    self_rev = E.build_revocation(key(2), "key", A, created_at=200)
    g = graph([e1, e2, self_rev])
    assert g.trust(A).value == 0 and g.trust(B).value == 0  # its edges go with it

    ident = E.build_identity(key(2), "agent", recovery=D, created_at=50)
    by_recovery = E.build_revocation(key(5), "key", A, created_at=200)
    assert graph([e1, e2, ident, by_recovery]).trust(A).value == 0
    assert graph([e1, e2, by_recovery]).trust(A).value > 0, "no declared recovery key, no effect"


def test_only_the_first_identity_event_names_the_recovery_key():
    e1 = endorse(1, 2)
    first = E.build_identity(key(2), "agent", recovery=D, created_at=50)
    later = E.build_identity(key(2), "agent", recovery=Z, created_at=60)
    by_late = E.build_revocation(key(8), "key", A, created_at=200)
    assert graph([e1, first, later, by_late]).trust(A).value > 0


def test_a_key_trusted_for_revoke_can_revoke_other_peoples_events():
    e1 = endorse(1, 2, w=0.9)
    e_bad = endorse(2, 3, w=0.9, delegable=False)
    mod = endorse(1, 4, scope="revoke", w=0.9, delegable=False)
    rev = E.build_revocation(key(4), "event", e_bad["id"], created_at=200)
    assert graph([e1, e_bad, mod, rev]).trust(B).value == 0
    assert graph([e1, e_bad, rev]).trust(B).value > 0, "an untrusted revoker has no effect"


def test_a_consumers_own_root_cannot_be_revoked_by_someone_else():
    mod = endorse(1, 4, scope="revoke", w=0.9, delegable=False)
    rev = E.build_revocation(key(4), "key", ROOT, created_at=200)
    assert graph([mod, rev]).trust(ROOT).value == 1.0


def test_blob_revocation_with_and_without_taint():
    mod = endorse(1, 4, scope="revoke", w=0.9, delegable=False)
    x1, x2 = "ab" * 32, "cd" * 32
    revs = [E.build_revocation(key(4), "x", x1, created_at=200), E.build_revocation(key(4), "x", x2, taint=True, created_at=200)]
    g = graph([mod, *revs])
    assert g.blob_status(x1) == "revoked" and g.blob_status(x2) == "tainted" and g.blob_status("ef" * 32) is None
    stranger = E.build_revocation(key(99), "x", x1, created_at=200)
    assert graph([stranger]).blob_status(x1) is None


# -------------------------------------------------------------- delegation

def test_a_delegate_may_sign_for_its_scope_only():
    g = graph([delegate(1, 2)])
    assert g.may_sign([ROOT], A, "publish:acme/model") is not None
    assert g.may_sign([ROOT], A, "publish:other/model") is None
    assert g.may_sign([ROOT], ROOT, "publish:anything") is not None  # a root signs for itself


def test_delegation_is_not_passed_on_unless_allowed():
    d1, d2 = delegate(1, 2), delegate(2, 3)
    assert graph([d1, d2]).may_sign([ROOT], B, "publish:acme/m") is None
    d1r = delegate(1, 2, redelegable=True)
    chain = graph([d1r, d2]).may_sign([ROOT], B, "publish:acme/m")
    assert chain is not None and len(chain[1]) == 2


def test_delegation_dates_and_revocation():
    d = delegate(1, 2, expires=NOW + 5, not_before=NOW - 5)
    assert graph([d], now=NOW).may_sign([ROOT], A, "publish:acme/m")
    assert not graph([d], now=NOW + 5).may_sign([ROOT], A, "publish:acme/m")
    assert not graph([d], now=NOW - 6).may_sign([ROOT], A, "publish:acme/m")
    rev = E.build_revocation(key(1), "event", d["id"], created_at=NOW - 1)
    assert not graph([d, rev]).may_sign([ROOT], A, "publish:acme/m")


def test_revoking_a_middle_delegation_cuts_the_rest_of_the_chain():
    d1, d2 = delegate(1, 2, redelegable=True), delegate(2, 3)
    rev = E.build_revocation(key(2), "event", d2["id"], created_at=300)
    assert not graph([d1, d2, rev]).may_sign([ROOT], B, "publish:acme/m")
    assert graph([d1, d2, rev]).may_sign([ROOT], A, "publish:acme/m")


def test_delegates_are_members_of_the_graph():
    g = graph([delegate(1, 2)])
    assert g.reachable(A) and not g.reachable(B)


# ------------------------------------------------------- order independence

def _universe():
    evs = [
        endorse(1, 2, w=0.9), endorse(2, 3, w=0.8), endorse(1, 4, w=0.6), endorse(4, 3, w=0.95, delegable=False),
        endorse(3, 5, w=0.7, delegable=False), endorse(9, 10, w=1.0), endorse(2, 6, scope="eval:*", w=0.5, delegable=False),
        delegate(1, 2, redelegable=True), delegate(2, 7),
        E.build_identity(key(3), "agent", recovery=pub(20), created_at=10),
    ]
    evs.append(E.build_revocation(key(4), "event", evs[3]["id"], created_at=500))
    evs.append(E.build_revocation(key(99), "event", evs[0]["id"], created_at=500))  # a stranger's: no effect
    return evs


def _answers(g):
    keys = [pub(i) for i in range(1, 12)] + [pub(20)]
    return (
        [(g.trust(k, None).value, g.trust(k, "eval:x").value, g.reachable(k)) for k in keys],
        [bool(g.may_sign([ROOT], k, "publish:acme/m")) for k in keys],
    )


def test_the_same_events_give_the_same_answers_in_any_order():
    evs = _universe()
    want = _answers(graph(evs))
    rng = random.Random(7)
    for _ in range(40):
        shuffled = evs[:]
        rng.shuffle(shuffled)
        assert _answers(graph(shuffled)) == want


def test_duplicates_change_nothing():
    evs = _universe()
    assert _answers(graph(evs + evs)) == _answers(graph(evs))


def test_adding_events_only_adds_paths_or_applicable_revocations():
    evs = _universe()
    base = graph(evs)
    extra = [endorse(30, 31), endorse(31, 32), E.build_identity(key(40), "human", created_at=5)]  # all outside the graph
    more = graph(evs + extra)
    assert _answers(more) == _answers(base)


# ----------------------------------------------------------------- parsing

def test_malformed_events_are_ignored_not_fatal():
    good = endorse(1, 2)
    bad_sig = dict(good, sig="00" * 64)
    tampered = dict(good, content=good["content"].replace("0.9", "1.0"))
    junk = {"kind": 36780}
    g = graph([bad_sig, tampered, junk, "nope", good])
    assert g.trust(A).value == pytest.approx(0.9)


@pytest.mark.parametrize("w", [0, -0.1, 1.5, True])
def test_bad_weights_cannot_be_built(w):
    with pytest.raises(ValueError):
        E.build_endorsement(key(1), A, ["*"], w)


def test_bad_weights_in_a_signed_event_are_rejected_on_parse():
    from torrenthub.signing import sign_event

    body = '{"delegable":true,"expires":null,"scope":["*"],"subject":"%s","v":1,"weight":2}' % A
    ev = sign_event(key(1), E.ENDORSEMENT, [["p", A]], body, 100)
    with pytest.raises(E.EventInvalid):
        E.parse_event(ev)


def test_signed_content_must_match_its_tags():
    from torrenthub.signing import sign_event

    body = '{"delegable":true,"expires":null,"scope":["*"],"subject":"%s","v":1,"weight":0.5}' % A
    ev = sign_event(key(1), E.ENDORSEMENT, [["p", B]], body, 100)
    with pytest.raises(E.EventInvalid):
        E.parse_event(ev)


def test_no_self_endorsement_or_delegation_and_scopes_are_checked():
    with pytest.raises(E.EventInvalid):
        E.parse_event(E.build_endorsement(key(1), ROOT, ["*"], 0.5))
    with pytest.raises(E.EventInvalid):
        E.parse_event(E.build_delegation(key(1), ROOT, ["publish:x"]))
    with pytest.raises(ValueError):
        E.build_endorsement(key(1), A, ["has space"], 0.5)
    with pytest.raises(ValueError):
        E.build_endorsement(key(1), A, [], 0.5)
    with pytest.raises(ValueError):
        E.build_endorsement(key(1), "nothex", ["*"], 0.5)


def test_oversized_events_are_rejected():
    ident = E.build_identity(key(1), "agent", note="x" * 500)
    assert E.parse_event(ident)
    huge = dict(ident, content=ident["content"] + " " * (E.MAX_EVENT_BYTES + 1))
    with pytest.raises(E.EventInvalid):
        E.parse_event(huge)


def _fake_endorsement(i, frm, to, w):
    """An unsigned stand in, for timing the graph only. Graph(verified=True) does not check signatures."""
    import json

    body = json.dumps({"v": 1, "subject": to, "scope": ["*"], "weight": w, "delegable": True, "expires": None})
    return {"id": f"{i:064x}", "pubkey": frm, "created_at": 100, "kind": E.ENDORSEMENT, "tags": [["p", to]], "content": body, "sig": ""}


def test_a_large_graph_is_quick():
    import time

    keys = [pub(i) for i in range(100, 3100)]
    evs, n = [_fake_endorsement(0, ROOT, keys[0], 0.9)], 1
    for i in range(60, len(keys), 60):  # the root vouches for 50 keys spread through the graph
        evs.append(_fake_endorsement(n, ROOT, keys[i], 0.9))
        n += 1
    for i, k in enumerate(keys):
        for j in (1, 5, 13):
            if i + j < len(keys):
                evs.append(_fake_endorsement(n, k, keys[i + j], 0.9))
                n += 1
    t = time.monotonic()
    g = Graph(evs, [ROOT], NOW, 3, verified=True)  # about 9000 distinct events
    trusted = sum(1 for k in keys if g.trust(k).value > 0)
    assert len(evs) > 8000 and trusted > 100, (len(evs), trusted)
    assert time.monotonic() - t < 10


# ---------------------------------------------------------- key rotation

def test_rotation_hands_incoming_trust_to_the_successor():
    e1 = endorse(1, 2, w=0.8)  # ROOT endorses A
    rot = E.build_revocation(key(2), "key", A, successor=B, created_at=200)
    g = graph([e1, rot])
    assert g.trust(A).value == 0, "the old key is revoked"
    assert g.trust(B).value == pytest.approx(0.8), "the new key inherits"
    assert g.successor_of(A) == B
    assert [(a, b) for a, b, _ in g.trust(B).path] == [(ROOT, B)]


def test_rotation_does_not_hand_over_what_the_old_key_issued():
    evs = [endorse(1, 2, w=0.9), endorse(2, 6, w=0.9, delegable=False), E.build_revocation(key(2), "key", A, successor=B, created_at=200)]
    g = graph(evs)
    assert g.trust(X).value == 0, "A's own endorsement of X stays dead; B must issue its own"


def test_rotation_carries_delegations_too():
    d = delegate(1, 2, "publish:acme/*")
    rot = E.build_revocation(key(2), "key", A, successor=B, created_at=200)
    g = graph([d, rot])
    assert g.may_sign([ROOT], B, "publish:acme/m")
    assert not g.may_sign([ROOT], A, "publish:acme/m")


def test_with_a_recovery_key_only_the_recovery_key_can_name_the_successor():
    ident = E.build_identity(key(2), "agent", recovery=D, created_at=50)
    e1 = endorse(1, 2, w=0.8)
    thief = E.build_revocation(key(2), "key", A, successor=Z, created_at=200)  # signed by the old key itself
    real = E.build_revocation(key(5), "key", A, successor=B, created_at=300)  # signed by the recovery key
    g = graph([ident, e1, thief, real])
    assert g.trust(Z).value == 0 and g.trust(B).value == pytest.approx(0.8)
    assert g.trust(A).value == 0, "the thief's statement still revokes the old key"
    assert graph([ident, e1, thief]).trust(Z).value == 0, "and without the recovery key's answer nobody inherits"


def test_the_earliest_valid_rotation_wins():
    e1 = endorse(1, 2, w=0.8)
    first = E.build_revocation(key(2), "key", A, successor=B, created_at=200)
    later = E.build_revocation(key(2), "key", A, successor=Z, created_at=300)
    g = graph([e1, later, first])
    assert g.trust(B).value > 0 and g.trust(Z).value == 0


def test_rotations_chain_and_loops_are_ignored():
    e1 = endorse(1, 2, w=0.8)
    a_to_b = E.build_revocation(key(2), "key", A, successor=B, created_at=200)
    b_to_c = E.build_revocation(key(3), "key", B, successor=C, created_at=300)
    g = graph([e1, a_to_b, b_to_c])
    assert g.trust(C).value == pytest.approx(0.8) and g.successor_of(A) == C
    c_to_a = E.build_revocation(key(4), "key", C, successor=A, created_at=400)
    g = graph([e1, a_to_b, b_to_c, c_to_a])
    assert all(g.trust(k).value == 0 for k in (A, B, C))


def test_a_revoked_successor_inherits_nothing():
    e1 = endorse(1, 2, w=0.8)
    rot = E.build_revocation(key(2), "key", A, successor=B, created_at=200)
    kill = E.build_revocation(key(3), "key", B, created_at=250)
    assert graph([e1, rot, kill]).trust(B).value == 0


def test_a_consumers_root_is_not_replaced_by_a_rotation():
    rot = E.build_revocation(key(1), "key", ROOT, successor=A, created_at=200)
    g = graph([rot])
    assert A not in g.roots and g.trust(A).value == 0


def test_rotation_is_order_independent():
    evs = [endorse(1, 2, w=0.8), E.build_revocation(key(2), "key", A, successor=B, created_at=200),
           E.build_revocation(key(3), "key", B, successor=C, created_at=300), endorse(1, 5, w=0.5)]
    want = {k: graph(evs).trust(k).value for k in (A, B, C, D)}
    rng = random.Random(7)
    for _ in range(10):
        shuffled = evs[:]
        rng.shuffle(shuffled)
        assert {k: graph(shuffled).trust(k).value for k in (A, B, C, D)} == want


def test_successor_is_checked_when_parsing():
    ev = E.build_revocation(key(2), "key", A, successor=B, created_at=200)
    assert E.parse_event(ev).successor == B
    with pytest.raises(ValueError):
        E.build_revocation(key(2), "event", "ab" * 32, successor=B)
    with pytest.raises(ValueError):
        E.build_revocation(key(2), "key", A, successor=A)
    forged = dict(ev)
    forged["tags"] = [t for t in ev["tags"] if len(t) < 3]
    forged = sg.sign_event(key(2), ev["kind"], forged["tags"], ev["content"], ev["created_at"])
    with pytest.raises(E.EventInvalid):
        E.parse_event(forged)


# ------------------------------------------------------ exact independence

def test_exact_independence_beats_greedy_when_the_best_paths_collide():
    # X's best path and Y's only path both go through A, but X has a second route through B.
    evs = [endorse(1, 2, w=0.9), endorse(1, 3, w=0.5), endorse(2, 6, w=0.9, delegable=False),
           endorse(3, 6, w=0.9, delegable=False), endorse(2, 7, w=0.5, delegable=False)]
    g = graph(evs)
    assert len(g.independent_greedy([X, Y], None, 2)) == 1
    got, exact = g.independent_ex([X, Y], None, 2)
    assert exact and sorted(got) == sorted([X, Y])


def test_exact_independence_still_refuses_a_real_cluster():
    evs = [endorse(1, 2, w=0.7)] + [endorse(2, n, w=1.0, delegable=False) for n in range(100, 105)]
    g = graph(evs)
    got, exact = g.independent_ex([pub(n) for n in range(100, 105)], None, 2)
    assert exact and len(got) == 1


def test_exact_independence_respects_hops_scope_delegable_and_minimum():
    evs = [endorse(1, 2, w=0.9), endorse(2, 3, w=0.9), endorse(3, 6, w=0.9, delegable=False)]
    assert graph(evs, hops=3).independent_ex([X], None, 1)[0] == [X]
    assert graph(evs, hops=2).independent_ex([X], None, 1)[0] == []  # three edges needed
    assert graph(evs, hops=3).independent_ex([X], None, 1, minimum=0.8)[0] == []  # 0.729 is not above 0.8
    notdel = [endorse(1, 2, w=0.9, delegable=False), endorse(2, 6, w=0.9, delegable=False)]
    assert graph(notdel).independent_ex([X], None, 1)[0] == []
    scoped = [endorse(1, 6, scope="attest:format_scan", delegable=False)]
    assert graph(scoped).independent_ex([X], "attest:format_scan", 1)[0] == [X]
    assert graph(scoped).independent_ex([X], "attest:eval", 1)[0] == []


def test_exact_independence_gives_up_cleanly_when_the_search_is_too_big(monkeypatch):
    from torrenthub import trust as T

    monkeypatch.setattr(T, "INDEPENDENT_BUDGET", 3)
    # Ten keys that all share one voucher and one backup route each: needs real search to prove 4 is impossible.
    evs = [endorse(1, 2, w=0.9), endorse(1, 3, w=0.9)] + [endorse(2, n, w=0.9, delegable=False) for n in range(20, 30)]
    evs += [endorse(3, n, w=0.8, delegable=False) for n in range(20, 30)]
    got, exact = graph(evs).independent_ex([pub(n) for n in range(20, 30)], None, 4)
    assert not exact and 1 <= len(got) <= 2


def _brute_best(g, keys, scope, minimum):
    """Reference answer by plain enumeration, written separately from the implementation."""
    paths = {}
    for k in keys:
        out = []

        def walk(node, prod, edges, mids):
            # node is where the path currently ends, walking forward from a root
            if node == k:
                if prod > minimum:
                    out.append(frozenset(mids))
                return
            if len(edges) >= g.hops:
                return
            for e in g.endorsements:
                if e.issuer != node or e.subject in mids or not T_covers(e.scope, scope):
                    continue
                nxt_last = e.subject == k
                if not nxt_last and not e.delegable:
                    continue
                walk(e.subject, prod * e.weight, edges + [e.id], mids | ({e.subject} if not nxt_last else set()))

        if k in g.roots:
            out.append(frozenset())
        else:
            for r in sorted(g.roots):
                walk(r, 1.0, [], set())
        paths[k] = out

    best = 0

    def pick(i, used, count):
        nonlocal best
        best = max(best, count)
        if i == len(keys):
            return
        pick(i + 1, used, count)
        for m in paths[keys[i]]:
            mine = m | {keys[i]}
            if not (mine & used):
                pick(i + 1, used | mine, count + 1)

    pick(0, frozenset(), 0)
    return best


def T_covers(patterns, scope):
    from torrenthub.trust import covers

    return covers(patterns, scope)


@pytest.mark.parametrize("seed", range(25))
def test_exact_independence_matches_brute_force_on_random_graphs(seed):
    rng = random.Random(seed)
    nodes = list(range(2, 10))
    evs = []
    for _ in range(rng.randint(8, 20)):
        a, b = rng.choice([1] + nodes), rng.choice(nodes)
        if a != b:
            evs.append(endorse(a, b, w=rng.choice([0.4, 0.7, 0.9]), delegable=rng.random() < 0.7, at=100 + len(evs)))
    g = graph(evs, hops=rng.choice([2, 3]))
    keys = sorted(pub(n) for n in nodes)
    minimum = rng.choice([0.0, 0.3])
    want = _brute_best(g, keys, None, minimum)
    got, exact = g.independent_ex(keys, None, len(keys), minimum)
    assert exact
    assert len(got) == want, f"seed {seed}: exact {len(got)}, brute force {want}"
    assert len(got) >= len(g.independent_greedy(keys, None, len(keys), minimum))
