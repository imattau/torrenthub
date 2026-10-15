"""Requests, claims and results: the events, and how a consumer judges where a request stands."""

from __future__ import annotations

import random

import pytest

from tests.test_trust import A, B, C, D, ROOT, X, Y, Z, endorse, key, pub
from torrenthub import events as E
from torrenthub import signing as sg
from torrenthub.trust import Graph

NOW = 1_000_000
DEADLINE = NOW + 600
H1, H2 = "aa" * 32, "bb" * 32


def graph(evs, now=NOW, roots=(ROOT,)):
    return Graph(evs, roots, now, 3)


def request(by=1, inputs=(H1,), task="hash_verified", deadline=DEADLINE, at=NOW - 100, want="attestation", **kw):
    return E.build_request(key(by), task, list(inputs), deadline=deadline, want=want, created_at=at, **kw)


def claim(req, by, expires=NOW + 300, at=NOW - 50):
    return E.build_claim(key(by), req["id"], expires=expires, created_at=at)


def att(by, x=H1, claim_="hash_verified", ok=True, at=NOW - 40):
    return E.build_attestation(key(by), claim_, "x", x, ok=ok, detail="d", created_at=at)


def result(req, by, atts=(), status="done", outputs=(), at=NOW - 30, **kw):
    return E.build_result(key(by), req["id"], status, attestations=[a["id"] for a in atts], outputs=list(outputs), created_at=at, **kw)


def works(n, task="hash_verified", w=0.9):
    """The root vouches for key n as a worker for this task."""
    return endorse(1, n, scope=f"work:{task}", w=w, delegable=False)


def answered_by(req, by, ok=True, x=H1, at=NOW - 30):
    a = att(by, x=x, ok=ok, at=at - 5)
    return [a, result(req, by, [a], at=at)]


# ------------------------------------------------------------------- the events

def test_request_claim_and_result_round_trip():
    r = request(args={"filename": "m.safetensors"}, reward="invoice:7")
    p = E.parse_event(r)
    assert (p.task, p.inputs, p.deadline, p.want, p.reward, p.args) == ("hash_verified", (H1,), DEADLINE, "attestation", "invoice:7", {"filename": "m.safetensors"})
    c = E.parse_event(claim(r, 2))
    assert (c.request, c.expires) == (r["id"], NOW + 300)
    a = att(2)
    res = E.parse_event(result(r, 2, [a], note="fine"))
    assert (res.request, res.status, res.attestations, res.note) == (r["id"], "done", (a["id"],), "fine")
    art = E.parse_event(E.build_result(key(2), r["id"], "done", outputs=[{"x": H2, "i": "ab" * 20, "size": 5}], derivation="cd" * 32, created_at=NOW))
    assert art.outputs == ((H2, "ab" * 20, 5),) and art.derivation == "cd" * 32


@pytest.mark.parametrize("kw", [
    dict(task="Has Space"), dict(task=""), dict(inputs=["zz"]), dict(inputs=[format(i, "064x") for i in range(17)]),
    dict(deadline=NOW - 100), dict(deadline=NOW - 100 + 31 * 86400), dict(want="money"), dict(reward="x" * 300),
    dict(args={"a": "x" * 3000}), dict(spec_x="nothex"),
])
def test_bad_requests_cannot_be_built(kw):
    base = dict(task="hash_verified", inputs=[H1], deadline=DEADLINE, created_at=NOW - 100)
    base.update(kw)
    with pytest.raises(ValueError):
        E.build_request(key(1), base.pop("task"), base.pop("inputs"), **base)


def test_bad_claims_and_results_cannot_be_built_and_forged_tags_are_rejected():
    r = request()
    with pytest.raises(ValueError):
        E.build_claim(key(2), r["id"], expires=NOW - 200, created_at=NOW - 100)
    with pytest.raises(ValueError):
        E.build_result(key(2), r["id"], "maybe")
    with pytest.raises(ValueError):
        E.build_result(key(2), r["id"], "failed", attestations=["cc" * 32])
    forged = sg.sign_event(key(2), E.CLAIM, [["e", "dd" * 32, "request"]], claim(r, 2)["content"], NOW - 50)
    with pytest.raises(E.EventInvalid):
        E.parse_event(forged)


# --------------------------------------------------------------------- status

def test_a_request_goes_open_claimed_answered_accepted():
    r = request()
    base = [works(2), r]
    assert graph(base).request_status(r["id"]).state == "open"
    st = graph(base + [claim(r, 2)]).request_status(r["id"])
    assert st.state == "claimed" and st.claimants == (pub(2),)
    done = graph(base + [claim(r, 2)] + answered_by(r, 2)).request_status(r["id"])
    assert done.state == "accepted" and done.accepted_by == (pub(2),) and done.outcome == ("attestation", ((H1, True),))


def test_a_claim_lapses_and_changes_nothing_by_itself():
    r = request()
    old = claim(r, 2, expires=NOW - 10, at=NOW - 90)
    assert graph([works(2), r, old]).request_status(r["id"]).state == "open", "an expired claim does not hold the request"
    assert graph([works(2), r, claim(r, 2)]).request_status(r["id"]).claimants == (pub(2),)


def test_an_untrusted_worker_can_answer_but_is_not_believed():
    r = request()
    st = graph([r] + answered_by(r, 9)).request_status(r["id"])
    assert st.state == "answered" and st.results == 1 and st.accepted_by == ()
    wrong_scope = graph([endorse(1, 2, scope="attest:hash_verified", delegable=False), r] + answered_by(r, 2)).request_status(r["id"])
    assert wrong_scope.state == "answered", "trusted to attest is not trusted to work this task"
    other_task = graph([works(2, task="format_scan"), r] + answered_by(r, 2)).request_status(r["id"])
    assert other_task.state == "answered"


def test_n_independent_workers_must_agree():
    r = request()
    two_ways = [endorse(1, 2, scope="work:*", w=0.9), endorse(1, 3, scope="work:*", w=0.9)]
    one = graph(two_ways + [r] + answered_by(r, 2))
    assert one.request_status(r["id"], n=2).state == "answered"
    both = graph(two_ways + [r] + answered_by(r, 2) + answered_by(r, 3))
    st = both.request_status(r["id"], n=2)
    assert st.state == "accepted" and sorted(st.accepted_by) == sorted([pub(2), pub(3)])


def test_workers_behind_one_voucher_are_not_independent():
    r = request()
    voucher = endorse(1, 2, scope="work:*", w=0.9)
    under = [endorse(2, 6, scope="work:*", w=0.9, delegable=False), endorse(2, 7, scope="work:*", w=0.9, delegable=False)]
    g = graph([voucher, *under, r] + answered_by(r, 6) + answered_by(r, 7))
    assert g.request_status(r["id"], n=2).state == "answered", "both owe their standing to the same key"
    assert g.request_status(r["id"], n=1).state == "accepted"


def test_two_different_answers_are_a_dispute_not_a_pick():
    r = request()
    evs = [works(2), works(3), r] + answered_by(r, 2, ok=True) + answered_by(r, 3, ok=False)
    st = graph(evs).request_status(r["id"])
    assert st.state == "disputed" and "different answers" in st.detail


def test_the_answer_must_hold_up():
    r = request()
    base = [works(2), r]
    # a result pointing at an attestation someone else signed
    theirs = att(3)
    assert graph(base + [theirs, result(r, 2, [theirs])]).request_status(r["id"]).state == "answered"
    # an attestation about another blob
    other = att(2, x=H2)
    assert graph(base + [other, result(r, 2, [other])]).request_status(r["id"]).state == "answered"
    # the wrong claim
    wrong = att(2, claim_="format_scan")
    assert graph(base + [wrong, result(r, 2, [wrong])]).request_status(r["id"]).state == "answered"
    # an attestation id that does not exist
    ghost = E.build_result(key(2), r["id"], "done", attestations=["ee" * 32], created_at=NOW - 30)
    assert graph(base + [ghost]).request_status(r["id"]).state == "answered"
    # a failed or declined result is not an answer
    fail = E.build_result(key(2), r["id"], "failed", note="could not fetch", created_at=NOW - 30)
    assert graph(base + [fail]).request_status(r["id"]).state == "open"
    # every input must be covered
    r2 = request(inputs=(H1, H2), at=NOW - 90)
    half = att(2, x=H1)
    assert graph([works(2), r2, half, result(r2, 2, [half])]).request_status(r2["id"]).state == "answered"
    both = [att(2, x=H1), att(2, x=H2)]
    assert graph([works(2), r2, *both, result(r2, 2, both)]).request_status(r2["id"]).state == "accepted"


def test_a_late_result_does_not_count_and_the_request_expires():
    r = request()
    late = answered_by(r, 2, at=DEADLINE + 50)
    st = graph([works(2), r] + late, now=DEADLINE + 100).request_status(r["id"])
    assert st.state == "expired" and st.results == 0
    assert graph([works(2), r], now=DEADLINE + 1).request_status(r["id"]).state == "expired"
    on_time = answered_by(r, 2, at=DEADLINE - 5)
    assert graph([works(2), r] + on_time, now=DEADLINE + 100).request_status(r["id"]).state == "accepted", "accepted stays accepted"


def test_a_refuted_worker_counts_for_nothing_and_a_revoked_request_is_gone():
    r = request()
    evs = [works(2), endorse(1, 5, scope="attest:replication", delegable=False), r] + answered_by(r, 2)
    bad = [e for e in evs if E.parse_event(e).__class__ is E.Attestation][0]
    refute = E.build_attestation(key(5), "replication", "e", bad["id"], match=False, detail="I get otherwise", created_at=NOW - 10)
    assert graph(evs).request_status(r["id"]).state == "accepted"
    assert graph(evs + [refute]).request_status(r["id"]).state == "answered"
    gone = E.build_revocation(key(1), "event", r["id"], created_at=NOW - 5)
    assert graph(evs + [gone]).request_status(r["id"]).state == "unknown"
    assert graph([]).request_status("ff" * 32).state == "unknown"


def test_artifact_requests_are_accepted_when_independent_workers_make_the_same_blobs():
    r = request(task="derive:bf16_cast", want="artifact")
    mk = lambda by, outs: E.build_result(key(by), r["id"], "done", outputs=[{"x": o, "i": None, "size": 3} for o in outs], created_at=NOW - 20)
    voucher = [endorse(1, 2, scope="work:*", w=0.9), endorse(1, 3, scope="work:*", w=0.9)]
    same = graph(voucher + [r, mk(2, [H2]), mk(3, [H2])]).request_status(r["id"], n=2)
    assert same.state == "accepted" and same.outcome == ("artifact", (H2,))
    differ = graph(voucher + [r, mk(2, [H2]), mk(3, [H1])]).request_status(r["id"], n=1)
    assert differ.state == "disputed"
    assert graph(voucher + [r, mk(2, [H2]), mk(3, [H1])]).request_status(r["id"], n=2).state == "answered"


def test_status_does_not_depend_on_event_order():
    r = request()
    evs = [works(2), works(3), r, claim(r, 2)] + answered_by(r, 2) + answered_by(r, 3)
    want = graph(evs).request_status(r["id"], n=2)
    rng = random.Random(4)
    for _ in range(8):
        s = evs[:]
        rng.shuffle(s)
        assert graph(s).request_status(r["id"], n=2) == want


def test_requests_list_is_newest_first_and_includes_every_state():
    r1, r2 = request(at=NOW - 300), request(inputs=(H2,), at=NOW - 100)
    assert [x.id for x in graph([r1, r2]).requests_list()] == [r2["id"], r1["id"]]


# ------------------------------------------------------------------- freshness

def test_a_verdict_can_require_a_recent_look():
    old = att(2, at=NOW - 10_000)
    evs = [endorse(1, 2, scope="attest:hash_verified", delegable=False), old]
    g = graph(evs)
    assert g.verdict(H1, "hash_verified").status == "satisfied"
    assert g.verdict(H1, "hash_verified", max_age=100_000).status == "satisfied"
    v = g.verdict(H1, "hash_verified", max_age=3600)
    assert v.status == "unsatisfied" and "within the last 3600s" in v.detail
    fresh = att(2, at=NOW - 60)
    assert graph(evs + [fresh]).verdict(H1, "hash_verified", max_age=3600).status == "satisfied"


def test_an_old_failed_scan_stops_blocking_under_a_freshness_window_but_a_new_one_still_does():
    evs = [endorse(1, 2, scope="attest:hash_verified", delegable=False), att(2, ok=False, at=NOW - 10_000)]
    assert graph(evs).verdict(H1, "hash_verified").status == "negative"
    assert graph(evs).verdict(H1, "hash_verified", max_age=3600).status == "unsatisfied"
    assert graph(evs + [att(2, ok=False, at=NOW - 30)]).verdict(H1, "hash_verified", max_age=3600).status == "negative"


# ----------------------------------------------------------- the freshness policy

def test_durations_parse_and_bad_ones_are_refused():
    from torrenthub.policy import PolicyError, parse_duration

    assert parse_duration("90m", "x") == 5400 and parse_duration("12h", "x") == 43200 and parse_duration("30d", "x") == 30 * 86400
    assert parse_duration("2w", "x") == 14 * 86400 and parse_duration(3600, "x") == 3600 and parse_duration("1.5h", "x") == 5400
    for bad in ("", "d", "abc", "-5d", "0", 0, -1, True, None, "5y", "1e9s", 10 ** 12):
        with pytest.raises(PolicyError):
            parse_duration(bad, "x")


def test_a_rule_can_demand_recent_attestations():
    from torrenthub.policy import check_file, parse_policy

    evs = [endorse(1, 2, scope="attest:hash_verified", delegable=False), att(2, at=NOW - 10_000)]
    g = graph(evs)
    assert check_file(parse_policy("[[file]]\nclaim='hash_verified'"), g, "o/m", "w.bin", H1).allowed
    assert check_file(parse_policy("[[file]]\nclaim='hash_verified'\nmax_age='7d'"), g, "o/m", "w.bin", H1).allowed
    d = check_file(parse_policy("[[file]]\nclaim='hash_verified'\nmax_age='1h'"), g, "o/m", "w.bin", H1)
    assert not d.allowed and "within the last 3600s" in d.reason
    with pytest.raises(Exception):
        parse_policy("[[file]]\nclaim='hash_verified'\nmax_age='soon'")


def test_the_freshness_section_is_parsed_and_checked():
    from torrenthub.policy import PolicyError, parse_policy

    assert parse_policy("[freshness]\nmanifest_max_age='30d'").freshness.manifest_max_age == 30 * 86400
    assert parse_policy("").freshness.manifest_max_age is None
    for bad in ("[freshness]\nmanifest_max_age='eventually'", "[freshness]\nother=1", "[freshness]\nmanifest_max_age=0"):
        with pytest.raises(PolicyError):
            parse_policy(bad)
