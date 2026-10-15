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
