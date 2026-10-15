"""Derivation events: lineage, taint reaching descendants, synthetic depth, and the policy that uses them."""

from __future__ import annotations

import hashlib
import random

import httpx
import pytest

from tests.conftest import Server, free_port
from tests.fake_upstream import REPO, build_app
from tests.test_trust import A, B, C, ROOT, endorse, key, pub
from torrenthub import events as E
from torrenthub import signing as sg
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.policy import PolicyError, check_file, parse_policy
from torrenthub.trust import Graph

NOW = 1_000_000


def h(n: int) -> str:
    return hashlib.sha256(b"blob%d" % n).hexdigest()


X1, X2, X3, X4, X5 = (h(i) for i in range(1, 6))
TOOL = "ab" * 32


def derive(by, ins, outs, tool="cast@1", tool_x=TOOL, origin="unknown", depth=0, at=200, **kw):
    return E.build_derivation(key(by), ins, [{"x": o, "i": None, "size": 10} for o in outs], tool, tool_x=tool_x,
                              data_origin=origin, synthetic_depth=depth, created_at=at, **kw)


def vouch_derive(n=2, w=0.9):
    """ROOT trusts key n for scope derive."""
    return E.build_endorsement(key(1), pub(n), ["derive"], w, created_at=100)


def revoke_blob(by, x, taint=True, at=300):
    return E.build_revocation(key(by), "x", x, taint=taint, created_at=at)


def graph(evs, roots=(ROOT,)):
    return Graph(evs, roots, NOW, 3)


TRUSTED_REVOKER = E.build_endorsement(key(1), pub(9), ["revoke"], 0.9, created_at=100)


# ------------------------------------------------------------------ the event

def test_a_derivation_round_trips_and_is_checked():
    ev = derive(2, [X1, X2], [X3], origin="synthetic", depth=1, args={"to": "bf16"}, licences={"inputs": {X1: "MIT"}, "output": "MIT"})
    d = E.parse_event(ev)
    assert d.inputs == tuple(sorted([X1, X2])) and d.outputs[0][0] == X3
    assert (d.tool, d.tool_x, d.data_origin, d.synthetic_depth, d.args) == ("cast@1", TOOL, "synthetic", 1, {"to": "bf16"})
    assert d.licences == {"inputs": {X1: "MIT"}, "output": "MIT"}


@pytest.mark.parametrize("kw", [
    dict(ins=[], outs=[X3]), dict(ins=[X1], outs=[]), dict(ins=[X1], outs=[X1]), dict(ins=[X1], outs=["zz"]),
    dict(ins=[X1], outs=[X3], origin="alien"), dict(ins=[X1], outs=[X3], depth=-1), dict(ins=[X1], outs=[X3], depth=99),
    dict(ins=[X1], outs=[X3], tool=""), dict(ins=[X1], outs=[X3], tool_x="short"), dict(ins=[X1], outs=[X3], args={"a": "x" * 3000}),
])
def test_bad_derivations_cannot_be_built(kw):
    with pytest.raises(ValueError):
        derive(2, kw["ins"], kw["outs"], **{k: v for k, v in kw.items() if k not in ("ins", "outs")})


def test_a_derivation_whose_tags_do_not_match_its_content_is_rejected():
    ev = derive(2, [X1], [X3])
    forged = sg.sign_event(key(2), ev["kind"], [t for t in ev["tags"] if t[1] != X1], ev["content"], ev["created_at"])
    with pytest.raises(E.EventInvalid):
        E.parse_event(forged)


def test_derivations_can_be_found_by_the_blobs_they_mention(tmp_path):
    from torrenthub.admission import Admission, Limits
    from torrenthub.eventstore import EventStore

    adm = Admission(EventStore(tmp_path / "ev"), [ROOT], Limits())
    assert adm.admit(derive(1, [X1], [X2], at=NOW), NOW).status == "accepted"  # the root's own claim
    assert [e["id"] for e in adm.store.query([E.DERIVATION], tags={"x": [X1]})] and adm.store.query([E.DERIVATION], tags={"x": [X2]})
    assert not adm.store.query([E.DERIVATION], tags={"x": [X3]})


# --------------------------------------------------------------------- lineage

def test_only_derivations_from_trusted_keys_count():
    d = derive(2, [X1], [X2])
    assert graph([d]).parents(X2) == [], "a stranger's claim is not lineage"
    assert graph([vouch_derive(), d]).parents(X2)[0].id == d["id"]
    assert graph([endorse(1, 2, scope="attest:*"), d]).parents(X2) == [], "trusted for something else is not enough"
    assert graph([derive(1, [X1], [X2])], roots=(ROOT,)).parents(X2), "a root's own claims count"


def test_ancestors_and_children_follow_the_chain_and_survive_cycles():
    evs = [vouch_derive(), derive(2, [X1], [X2]), derive(2, [X2], [X3]), derive(2, [X3], [X1], at=210)]  # a loop
    g = graph(evs)
    assert g.ancestors(X3) == {X1, X2}
    assert [d.outputs[0][0] for d in g.children(X2)] == [X3]


def test_a_revoked_derivation_or_a_revoked_issuer_stops_counting():
    d = derive(2, [X1], [X2])
    own = E.build_revocation(key(2), "event", d["id"], created_at=250)
    assert graph([vouch_derive(), d, own]).parents(X2) == []
    gone = E.build_revocation(key(2), "key", pub(2), created_at=250)
    assert graph([vouch_derive(), d, gone]).parents(X2) == []


# ------------------------------------------------------------------------ taint

def chain(origin="unknown"):
    return [vouch_derive(), TRUSTED_REVOKER, derive(2, [X1], [X2]), derive(2, [X2], [X3], at=210), derive(2, [X4], [X5], at=220)]


def test_taint_reaches_every_descendant_and_only_them():
    g = graph(chain() + [revoke_blob(9, X1, taint=True)])
    assert g.blob_status(X1) == "tainted"
    assert g.blob_status(X2) == "descended" and g.blob_status(X3) == "descended"
    assert g.blob_status(X4) is None and g.blob_status(X5) is None
    assert g.tainted_descendants()[X3] == X1


def test_revocation_without_taint_does_not_reach_descendants():
    g = graph(chain() + [revoke_blob(9, X1, taint=False)])
    assert g.blob_status(X1) == "revoked" and g.blob_status(X2) is None and g.blob_status(X3) is None


def test_a_stranger_cannot_taint_an_innocent_blob_by_claiming_it_descends_from_a_bad_one():
    lie = derive(7, [X1], [X4])  # key 7 is nobody
    g = graph(chain() + [lie, revoke_blob(9, X1, taint=True)])
    assert g.blob_status(X4) is None


def test_a_stranger_cannot_untaint_by_hiding_lineage_but_a_trusted_key_can_add_it_later():
    g = graph([TRUSTED_REVOKER, revoke_blob(9, X1)])
    assert g.blob_status(X2) is None, "no lineage published, nothing to follow (the limit of what can be seen)"
    g2 = graph([TRUSTED_REVOKER, vouch_derive(), revoke_blob(9, X1), derive(2, [X1], [X2])])
    assert g2.blob_status(X2) == "descended"


def test_lineage_answers_do_not_depend_on_event_order():
    evs = chain() + [revoke_blob(9, X1), derive(2, [X3], [X4], origin="synthetic", depth=1, at=230)]
    want = {x: (graph(evs).blob_status(x), graph(evs).synthetic_depth(x)) for x in (X1, X2, X3, X4, X5)}
    rng = random.Random(3)
    for _ in range(8):
        s = evs[:]
        rng.shuffle(s)
        assert {x: (graph(s).blob_status(x), graph(s).synthetic_depth(x)) for x in want} == want


# --------------------------------------------------------------- synthetic depth

def test_synthetic_depth_is_a_lower_bound_that_grows_along_synthetic_steps():
    evs = [vouch_derive(), derive(2, [X1], [X2], origin="synthetic"), derive(2, [X2], [X3], origin="synthetic", at=210),
           derive(2, [X3], [X4], origin="human", at=220)]
    g = graph(evs)
    assert (g.synthetic_depth(X1), g.synthetic_depth(X2), g.synthetic_depth(X3), g.synthetic_depth(X4)) == (0, 1, 2, 2)


def test_a_declared_depth_counts_even_without_a_chain_and_the_larger_number_wins():
    g = graph([vouch_derive(), derive(2, [X1], [X2], origin="synthetic", depth=5)])
    assert g.synthetic_depth(X2) == 5


def test_untrusted_depth_claims_are_ignored_and_loops_terminate():
    assert graph([derive(7, [X1], [X2], origin="synthetic", depth=9)]).synthetic_depth(X2) == 0
    loop = [vouch_derive(), derive(2, [X1], [X2], origin="synthetic"), derive(2, [X2], [X1], origin="synthetic", at=210)]
    assert graph(loop).synthetic_depth(X2) >= 1


def test_derivation_class_is_d_only_for_listed_tools():
    d = graph([vouch_derive(), derive(2, [X1], [X2])]).parents(X2)[0]
    g = graph([])
    assert g.derivation_class(d, []) == "S" and g.derivation_class(d, [TOOL]) == "D" and g.derivation_class(d, ["cd" * 32]) == "S"
    nohash = graph([vouch_derive(), derive(2, [X1], [X3], tool_x=None)]).parents(X3)[0]
    assert g.derivation_class(nohash, [TOOL]) == "S", "no tool hash, nothing to list"


# ------------------------------------------------------------------------ policy

def test_the_lineage_section_is_parsed_and_checked():
    r = parse_policy(f'[lineage]\non_tainted="warn"\nmax_synthetic_depth=2\nmin_trust=0.3\ntrusted_tools=["{TOOL}"]')
    assert (r.lineage.on_tainted, r.lineage.max_synthetic_depth, r.lineage.min_trust, r.lineage.trusted_tools) == ("warn", 2, 0.3, (TOOL,))
    assert parse_policy("") == [] and parse_policy("").lineage.on_tainted == "refuse"
    for bad in ['[lineage]\non_tainted="maybe"', "[lineage]\nmax_synthetic_depth=-1", "[lineage]\nmax_synthetic_depth=true",
                "[lineage]\nmin_trust=2", '[lineage]\ntrusted_tools=["abc"]', "[lineage]\nfoo=1", '[lineage]\ntrusted_tools="x"']:
        with pytest.raises(PolicyError):
            parse_policy(bad)


def test_policy_refuses_descendants_of_tainted_blobs_or_only_warns():
    g = graph(chain() + [revoke_blob(9, X1)])
    d = check_file(parse_policy(""), g, "o/m", "w.bin", X3)
    assert not d.allowed and d.code == "Tainted" and X1[:12] in d.reason
    warn = check_file(parse_policy('[lineage]\non_tainted="warn"'), g, "o/m", "w.bin", X3)
    assert warn.allowed and warn.notes and "descends" in warn.notes[0]
    assert check_file(parse_policy(""), g, "o/m", "w.bin", X4).allowed
    assert check_file(parse_policy("[[file]]\naction='allow'"), g, "o/m", "w.bin", X3).allowed is False, "no rule overrides a taint"
    assert check_file(parse_policy(""), g, "o/m", "w.bin", X1).code == "Revoked"


def test_policy_caps_synthetic_depth():
    g = graph([vouch_derive(), derive(2, [X1], [X2], origin="synthetic"), derive(2, [X2], [X3], origin="synthetic", at=210)])
    rules = parse_policy("[lineage]\nmax_synthetic_depth=1")
    assert check_file(rules, g, "o/m", "w", X2).allowed
    d = check_file(rules, g, "o/m", "w", X3)
    assert not d.allowed and d.code == "SyntheticDepth" and "2 generations" in d.reason
    assert check_file(parse_policy(""), g, "o/m", "w", X3).allowed, "no cap, no refusal"


# ------------------------------------------------------------ a real gateway

FILES = {"config.json": b'{"a": 1}\n', "clean.bin": b"c" * 1_300_000, "child.bin": b"d" * 1_300_000, "bad.bin": b"b" * 1_300_000}
SHA = {p: hashlib.sha256(d).hexdigest() for p, d in FILES.items()}


@pytest.fixture()
def gw(tmp_path):
    up = Server(build_app(dict(FILES)), free_port()).start()
    pol = tmp_path / "policy.toml"
    pol.write_text(f'[lineage]\nmax_synthetic_depth = 1\ntrusted_tools = ["{TOOL}"]\n')
    port = free_port()
    s = Settings(data_dir=tmp_path / "g", upstream=up.url, public_url=f"http://127.0.0.1:{port}", roots=[ROOT], anchor="", policy=str(pol))
    srv = Server(create_app(s), port).start()
    yield srv
    srv.stop()
    up.stop()


def post(gw, ev):
    r = httpx.post(f"{gw.url}/api/thub/events", json=ev, timeout=30)
    assert r.status_code in (200, 202), r.text


def fetch(gw, path):
    return httpx.get(f"{gw.url}/{REPO}/resolve/main/{path}", timeout=60)


def test_gateway_refuses_a_descendant_of_a_tainted_blob_and_reports_lineage(gw):
    assert fetch(gw, "child.bin").status_code == 200
    for ev in (vouch_derive(), TRUSTED_REVOKER,
               derive(2, [SHA["bad.bin"]], [SHA["child.bin"]]),
               revoke_blob(9, SHA["bad.bin"])):
        post(gw, ev)
    r = fetch(gw, "child.bin")
    assert r.status_code == 403 and r.headers["x-error-code"] == "Tainted"
    assert fetch(gw, "clean.bin").status_code == 200
    lin = httpx.get(f"{gw.url}/api/thub/lineage/{SHA['child.bin']}", timeout=30).json()
    assert lin["status"] == "descended" and lin["descends_from_revoked"] == SHA["bad.bin"]
    assert lin["made_by"][0]["class"] == "D" and lin["made_by"][0]["tool_x"] == TOOL, "the policy lists this tool as bit exact"


def test_gateway_enforces_the_synthetic_depth_cap(gw):
    post(gw, vouch_derive())
    post(gw, derive(2, [SHA["bad.bin"]], [SHA["clean.bin"]], origin="synthetic"))
    post(gw, derive(2, [SHA["clean.bin"]], [SHA["child.bin"]], origin="synthetic", at=210))
    assert fetch(gw, "clean.bin").status_code == 200
    r = fetch(gw, "child.bin")
    assert r.status_code == 403 and r.headers["x-error-code"] == "SyntheticDepth"
