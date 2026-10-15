"""The relay adapter: events go out to a relay and come back, checked again on the way in."""

from __future__ import annotations

import asyncio
import json
import time

import pytest

pytest.importorskip("websockets")

from tests.fake_relay import FakeRelay  # noqa: E402
from tests.test_trust import A, B, ROOT, endorse, key, pub  # noqa: E402
from torrenthub import events as E  # noqa: E402
from torrenthub import relay as R  # noqa: E402
from torrenthub import relay_sync as RS  # noqa: E402
from torrenthub import signing as sg  # noqa: E402
from torrenthub.admission import Admission, Limits  # noqa: E402
from torrenthub.eventstore import EventStore  # noqa: E402
from torrenthub.manifest import build_manifest  # noqa: E402
from torrenthub.store import Store  # noqa: E402

NOW = int(time.time())
H = "ab" * 32


def run(coro):
    return asyncio.run(coro)


@pytest.fixture()
def relay():
    r = FakeRelay().start()
    yield r
    r.stop()


def hub_adm(tmp_path, name="hub"):
    return Admission(EventStore(tmp_path / name), [ROOT], Limits())


def populate(adm):
    """Several events of the same kind from the same key: what a relay must not collapse."""
    evs = [endorse(1, n, scope="work:*", at=NOW - 100 + n) for n in (2, 3, 4, 5, 6)]
    evs += [E.build_identity(key(2), "agent", created_at=NOW - 50)]
    evs += [E.build_attestation(key(2), "hash_verified", "x", f"{i:064x}", ok=True, detail="d", created_at=NOW - 40 + i) for i in range(4)]
    req = E.build_request(key(2), "hash_verified", [H], deadline=NOW + 600, created_at=NOW - 30)
    evs += [req, E.build_claim(key(2), req["id"], expires=NOW + 300, created_at=NOW - 20),
            E.build_result(key(2), req["id"], "failed", note="n", created_at=NOW - 10)]
    for ev in evs:
        assert adm.admit(ev, NOW).status == "accepted", ev["kind"]
    return evs


# --------------------------------------------------------------------- the d tag

def test_every_event_kind_carries_a_content_derived_d_tag():
    sk = key(9)
    req = E.build_request(sk, "hash_verified", [H], deadline=NOW + 100, created_at=NOW)
    made = [E.build_identity(sk, "agent", created_at=NOW), E.build_delegation(sk, pub(2), ["publish:a/b"], created_at=NOW),
            endorse(9, 2), E.build_revocation(sk, "x", H, created_at=NOW),
            E.build_attestation(sk, "hash_verified", "x", H, ok=True, created_at=NOW),
            E.build_derivation(sk, [H], [{"x": "cd" * 32, "i": None, "size": 1}], "t@1", created_at=NOW),
            req, E.build_claim(sk, req["id"], expires=NOW + 50, created_at=NOW), E.build_result(sk, req["id"], "failed", created_at=NOW)]
    for ev in made:
        ds = [t[1] for t in ev["tags"] if t[0] == "d"]
        assert len(ds) == 1 and len(ds[0]) == 32, ev["kind"]
        E.parse_event(ev)  # and they still parse and verify
    assert len({ev["tags"][-1][1] for ev in made}) == len(made), "different events never share an address"
    same = [E.build_identity(sk, "agent", created_at=NOW), E.build_identity(sk, "agent", created_at=NOW + 5)]
    assert same[0]["tags"][-1] == same[1]["tags"][-1] and same[0]["id"] != same[1]["id"], "identical meaning shares one"


def test_old_events_without_a_d_tag_still_parse():
    old = sg.sign_event(key(1), E.ENDORSEMENT, [["p", pub(2)]], json.dumps({"v": 1, "subject": pub(2), "scope": ["*"], "weight": 0.5, "delegable": False, "expires": None}, sort_keys=True, separators=(",", ":")), NOW)
    assert E.parse_event(old).subject == pub(2)


def test_a_strict_relay_keeps_all_our_events_but_would_collapse_ones_without_d(relay, tmp_path):
    sk = key(7)
    dless = [sg.sign_event(sk, E.ENDORSEMENT, [["p", pub(n)]], json.dumps({"n": n}), NOW + n) for n in (1, 2, 3)]
    ours = [E.build_endorsement(sk, pub(n), ["work:*"], 0.5, created_at=NOW + n) for n in (1, 2, 3)]
    res = run(R.publish_all(relay.url, dless + ours))
    assert all(r.accepted for r in res)
    held = [e for e in relay.events.values() if e["kind"] == E.ENDORSEMENT]
    assert {e["id"] for e in held} >= {e["id"] for e in ours}, "ours are all kept"
    assert sum(1 for e in held if e["id"] in {d["id"] for d in dless}) == 1, "without d, the relay keeps one of three"


# --------------------------------------------------------------------- round trip

def test_events_round_trip_through_a_relay_into_another_store(relay, tmp_path):
    src = hub_adm(tmp_path, "src")
    sent = populate(src)
    out = run(RS.push(src, relay.url))
    assert out["accepted"] == len(sent) and out["skipped"] == 0 and out["refused"] == {}
    assert len(relay.events) == len(sent), "the relay kept every one"
    dst = hub_adm(tmp_path, "dst")
    got = run(RS.pull(dst, relay.url))
    assert got["fetched"] == len(sent) and got.get("accepted") == len(sent)
    assert {e["id"] for e in dst.store.query(list(E.KINDS), limit=500)} == {e["id"] for e in sent}
    g = dst.graph(NOW)
    assert g.trust(pub(3)).value > 0 and g.verdict(f"{0:064x}", "hash_verified").status in ("satisfied", "unsatisfied")
    again = run(RS.pull(dst, relay.url))
    assert again.get("already") == len(sent) and "accepted" not in again, "a second pull changes nothing"
    dup = run(RS.push(src, relay.url))
    assert dup["accepted"] == 0 and dup["duplicate"] == len(sent)


def test_a_relay_is_not_trusted_for_anything(relay, tmp_path):
    src = hub_adm(tmp_path, "src")
    good = endorse(1, 2, at=NOW - 10)
    assert src.admit(good, NOW).status == "accepted"
    stranger = E.build_endorsement(key(9), pub(3), ["*"], 1.0, created_at=NOW)
    forged = dict(good, sig="00" * 64)
    forged["id"] = "ff" * 32
    for ev in (good, stranger):
        relay.events[ev["id"]] = ev
    relay.events[forged["id"]] = forged
    dst = hub_adm(tmp_path, "dst")
    got = run(RS.pull(dst, relay.url))
    assert got["fetched"] == 3 and got.get("accepted") == 1 and got.get("quarantined") == 1 and got.get("rejected") == 1
    assert dst.graph(NOW).trust(pub(3)).value == 0, "a stranger's endorsement changes nothing"


def test_only_the_main_tier_goes_out(relay, tmp_path):
    adm = hub_adm(tmp_path)
    adm.admit(endorse(1, 2, at=NOW - 10), NOW)
    stranger = E.build_identity(key(9), "agent", created_at=NOW)
    assert adm.admit(stranger, NOW).status == "quarantined"
    run(RS.push(adm, relay.url))
    assert stranger["id"] not in relay.events and len(relay.events) == 1


def test_filters_by_kind_author_and_time(relay, tmp_path):
    src = hub_adm(tmp_path, "src")
    sent = populate(src)
    run(RS.push(src, relay.url))
    dst = hub_adm(tmp_path, "dst")
    run(RS.pull(dst, relay.url, [E.ENDORSEMENT], authors=[pub(1)]))
    assert {e["kind"] for e in dst.store.query(limit=500)} == {E.ENDORSEMENT}
    only = run(R.fetch_all(relay.url, R.to_filter(kinds=[E.ATTESTATION], tags={"x": [f"{2:064x}"]})))[0]
    assert len(only) == 1 and only[0]["kind"] == E.ATTESTATION
    with pytest.raises(ValueError):
        R.to_filter(tags={"xx": ["a"]})


def test_paging_reads_more_than_one_page(relay):
    sk = key(7)
    for i in range(12):
        ev = E.build_endorsement(sk, pub(20 + i), ["work:*"], 0.5, created_at=NOW - 1000 + i * 7)
        relay.events[ev["id"]] = ev
    evs, note = run(R.fetch_all(relay.url, R.to_filter(kinds=[E.ENDORSEMENT]), page=5))
    assert len(evs) == 12 and note == ""


# ------------------------------------------------------------------------ limits

def test_nip11_limits_are_read_and_events_are_checked_against_them(tmp_path):
    r = FakeRelay(max_message_length=4000, max_content_length=2000, max_event_tags=20).start()
    try:
        doc = run(R.info(r.url))
        lim = doc["limitation"]
        assert lim["max_message_length"] == 4000 and doc["supported_nips"][0] == 1
        small = endorse(1, 2)
        assert R.check_fits(small, lim) == []
        big = E.build_derivation(key(1), [f"{i:064x}" for i in range(20)], [{"x": f"{i + 99:064x}", "i": None, "size": 1} for i in range(20)], "t@1", created_at=NOW)
        why = R.check_fits(big, lim)
        assert why and "bytes" in why[0]
        adm = hub_adm(tmp_path)
        adm.admit(endorse(1, 2, at=NOW - 10), NOW)
        adm.admit(E.build_derivation(key(1), [f"{i:064x}" for i in range(20)], [{"x": f"{i + 99:064x}", "i": None, "size": 1} for i in range(20)], "t@1", created_at=NOW - 5), NOW)
        out = run(RS.push(adm, r.url))
        assert out["accepted"] == 1 and out["skipped"] == 1 and "kind 36783" in out["skip_reasons"][0]
        assert len(r.events) == 1
    finally:
        r.stop()


def test_a_relay_without_nip11_is_still_usable():
    r = FakeRelay(nip11=False).start()
    try:
        assert run(R.info(r.url)) == {}
        assert run(R.publish_all(r.url, [endorse(1, 2)]))[0].accepted
    finally:
        r.stop()


def test_check_fits_covers_each_published_limit():
    ev = endorse(1, 2)
    assert R.check_fits(ev, {}) == [] and R.check_fits(ev, None) == []
    assert R.check_fits(ev, {"max_content_length": 5})
    assert R.check_fits(ev, {"max_event_tags": 1})
    assert R.check_fits(ev, {"min_pow_difficulty": 20})
    old = endorse(1, 2, at=NOW - 10_000)
    assert R.check_fits(old, {"created_at_lower_limit": 60})
    future = endorse(1, 2, at=NOW + 10_000)
    assert R.check_fits(future, {"created_at_upper_limit": 60})


def test_a_v2_manifest_with_a_table_blob_fits_where_an_inline_one_does_not(tmp_path):
    info = {"sha": "ab" * 20, "siblings": [{"rfilename": f"part-{i:04d}.bin", "size": 10, "lfs": {"size": 10, "sha256": f"{i:064x}"}} for i in range(190)]}
    inline = build_manifest(key(1), "acme/m", info, ["main"], seq=1, table_blob=False, created_at=NOW)
    blob = build_manifest(key(1), "acme/m", info, ["main"], seq=1, table_blob=True, created_at=NOW)
    lim = {"max_message_length": 16384}
    assert R.check_fits(inline, lim) and R.check_fits(blob, lim) == []
    assert len(json.dumps(blob)) < 2000 < len(json.dumps(inline))


# ---------------------------------------------------------------- relay behaviour

def test_rate_limited_events_are_retried_and_get_through(tmp_path):
    r = FakeRelay(rate_limit_every=2).start()
    try:
        evs = [endorse(1, n, at=NOW - 100 + n) for n in range(2, 8)]
        res = run(R.publish_all(r.url, evs))
        assert all(x.accepted for x in res) and r.rate_limited >= 1
    finally:
        r.stop()


def test_a_relay_that_demands_authentication_is_answered_when_there_is_a_key(tmp_path):
    r = FakeRelay(auth_required=True).start()
    try:
        ev = endorse(1, 2)
        no_key = run(R.publish_all(r.url, [ev]))[0]
        assert not no_key.accepted and no_key.prefix == "auth-required"
        with_key = run(R.publish_all(r.url, [ev], auth_secret=key(5)))[0]
        assert with_key.accepted
        evs, note = run(R.fetch_all(r.url, {"kinds": [E.ENDORSEMENT]}))
        assert evs == [] and note.startswith("auth-required")
        evs, note = run(R.fetch_all(r.url, {"kinds": [E.ENDORSEMENT]}, auth_secret=key(5)))
        assert [e["id"] for e in evs] == [ev["id"]] and note == ""
    finally:
        r.stop()


def test_a_relay_that_refuses_kinds_is_reported_not_crashed_on(tmp_path):
    r = FakeRelay(kinds={E.ENDORSEMENT}).start()
    try:
        adm = hub_adm(tmp_path)
        total = len(populate(adm))
        out = run(RS.push(adm, r.url))
        assert out["accepted"] == 5 and out["refused"] == {"blocked": total - 5}
    finally:
        r.stop()


def test_a_dead_relay_gives_a_clear_error():
    with pytest.raises(R.RelayError, match="cannot connect"):
        run(R.publish_all("ws://127.0.0.1:9", [endorse(1, 2)], timeout=3))
    with pytest.raises(R.RelayError):
        run(R.publish_all("http://example.org", [endorse(1, 2)]))


# ------------------------------------------------------------------- manifests

def test_manifests_travel_and_only_named_signers_are_taken(relay, tmp_path):
    info = {"sha": "ab" * 20, "siblings": [{"rfilename": "a.bin", "size": 3, "lfs": {"size": 3, "sha256": H}}]}
    mine = build_manifest(key(1), "acme/m", info, ["main"], seq=1, created_at=NOW)
    theirs = build_manifest(key(9), "acme/m", info, ["main"], seq=2, created_at=NOW)
    other_repo = build_manifest(key(1), "acme/other", info, ["main"], seq=1, created_at=NOW)
    src = Store(tmp_path / "src")
    for ev in (mine, other_repo):
        src.add_manifest(ev)
    out = run(RS.push_manifests(src, relay.url, ["acme/m"]))
    assert out["accepted"] == 1
    relay.events[theirs["id"]] = theirs
    dst = Store(tmp_path / "dst")
    got = run(RS.pull_manifests(dst, relay.url, {pub(1)}, ["acme/m"]))
    assert got["stored"] == 1 and [m["id"] for m in dst.list_manifests("acme/m")] == [mine["id"]]
    assert dst.list_manifests("acme/other") == []


# -------------------------------------------------------------------- the probe

def test_the_probe_finds_a_strict_relays_limits_and_behaviour():
    r = FakeRelay(max_message_length=20_000, max_event_tags=100, kinds=set(range(36778, 36787)) | {5}).start()
    try:
        pr = run(R.probe(r.url, max_bytes=256 * 1024))
        assert pr.connected and pr.nip11["limitation"]["max_message_length"] == 20_000
        assert pr.kinds[E.ENDORSEMENT] == "ok" and pr.kinds[36777].startswith("blocked")
        assert pr.keeps_both_with_d is True and pr.keeps_both_dless is False, "this relay collapses events with no d tag"
        assert pr.first_refused_bytes and 14_000 < pr.max_event_bytes <= 20_000
        assert pr.first_refused_tags and 0 < pr.max_tags < 100 + 1 + 2 and pr.first_refused_tags > 100
        assert pr.rtt_ms is not None
        assert not [e for e in r.events.values() if e["kind"] != 5 and any(t == ["t", "torrenthub-probe"] for t in e["tags"])], "the probe cleaned up"
    finally:
        r.stop()


def test_the_probe_can_leave_its_events_for_inspection():
    r = FakeRelay().start()
    try:
        pr = run(R.probe(r.url, max_bytes=8192, delete=False))
        assert pr.max_event_bytes and pr.first_refused_bytes is None and any("probe's own cap" in n for n in pr.notes)
        assert any(any(t == ["t", "torrenthub-probe"] for t in e["tags"]) for e in r.events.values())
    finally:
        r.stop()


def test_events_over_the_common_cap_are_skipped_even_when_nip11_allows_them(tmp_path):
    """strfry's NIP-11 says 131072 for messages but it refuses events over 65536. The default guard follows the latter."""
    from torrenthub.relay import COMMON_MAX_EVENT_BYTES

    info = {"sha": "ab" * 20, "siblings": [{"rfilename": f"part-{i:05d}.safetensors", "size": 10, "lfs": {"size": 10, "sha256": f"{i:064x}"}} for i in range(700)]}
    big = build_manifest(key(1), "acme/m", info, ["main"], created_at=NOW)  # v1, 700 rows inline
    size = len(json.dumps(big))
    assert COMMON_MAX_EVENT_BYTES < size < 131_072, size
    lim = {"max_message_length": 131_072}
    assert R.check_fits(big, lim) and "commonly refuse" in R.check_fits(big, lim)[0]
    assert R.check_fits(big, lim, max_event_bytes=None) == [], "the guard can be turned off"
    assert R.check_fits(big, lim, max_event_bytes=200_000) == []


def test_following_the_trust_graph_pulls_what_trust_reaches_and_never_a_strangers(relay, tmp_path):
    src = hub_adm(tmp_path, "src")
    populate(src)  # ROOT endorses keys 2..6; key 2 issues identity, attestations, a request, a claim and a result
    stranger = [E.build_attestation(key(9), "hash_verified", "x", f"{i:064x}", ok=True, detail="spam", created_at=NOW - 5) for i in range(3)]
    for ev in stranger:
        relay.events[ev["id"]] = ev
    run(RS.push(src, relay.url))
    dst = hub_adm(tmp_path, "dst")
    out = run(RS.pull_following(dst, relay.url))
    assert out["rounds"] == 2 and out["accepted"] == 13, out  # the root's five endorsements, then key 2's eight events
    assert out["authors_asked"] == 6, "the root and the five keys it endorsed, and nobody else"
    ids = {e["id"] for e in dst.store.query(list(E.KINDS), limit=500, include_quarantine=True)}
    assert not ids & {e["id"] for e in stranger}, "a stranger's events were never even requested"
    assert run(RS.pull_following(dst, relay.url)).get("accepted", 0) == 0, "a second run finds nothing new"


def test_following_from_a_store_that_trusts_nobody_asks_for_nobody(relay, tmp_path):
    relay.events["ff" * 32] = {"id": "ff" * 32}
    empty = hub_adm(tmp_path, "empty")
    empty.roots = set()
    out = run(RS.pull_following(empty, relay.url))
    assert out["rounds"] == 0 and out["fetched"] == 0
