"""Admission, the event store and API, the CLI, and delegation feeding the signed mode."""

from __future__ import annotations

import json
import os
import subprocess
import sys

import httpx
import pytest

from tests.conftest import Server, free_port
from tests.test_trust import A, B, C, D, ROOT, X, endorse, key, pub
from torrenthub import events as E
from torrenthub.admission import Admission, Limits
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.eventstore import EventStore

NOW = 2_000_000


def adm(tmp_path, **lim):
    return Admission(EventStore(tmp_path / "ev"), [ROOT], Limits(**lim))


def ident(n, note="", at=NOW):
    return E.build_identity(key(n), "agent", note=note, created_at=at)


# -------------------------------------------------------------- admission

def test_members_go_to_main_and_strangers_to_quarantine(tmp_path):
    a = adm(tmp_path)
    assert a.admit(endorse(1, 2, at=NOW), NOW).status == "accepted"
    assert a.admit(ident(2), NOW).status == "accepted"  # endorsed by the root, so a member
    r = a.admit(ident(9), NOW)
    assert (r.status, r.tier, r.http) == ("quarantined", "quarantine", 202)
    assert [e["pubkey"] for e in a.store.query([E.IDENTITY])] == [A]
    assert len(a.store.query([E.IDENTITY], include_quarantine=True)) == 2


def test_a_strangers_events_do_not_change_what_the_hub_believes(tmp_path):
    a = adm(tmp_path)
    a.admit(endorse(1, 2, at=NOW), NOW)
    for n in range(20, 24):
        a.admit(endorse(n, 3, at=NOW), NOW)  # strangers vouching for B
        a.admit(E.build_revocation(key(n), "event", endorse(1, 2, at=NOW)["id"], created_at=NOW), NOW)
    g = a.graph(NOW)
    assert g.trust(A).value > 0 and g.trust(B).value == 0


def test_bad_events_are_rejected_with_the_right_codes(tmp_path):
    a = adm(tmp_path)
    good = ident(1)
    bad_sig = dict(good, sig="00" * 64)
    assert a.admit(bad_sig, NOW).http == 400
    assert a.admit({"kind": 1}, NOW).http == 400
    assert a.admit("x", NOW).http == 400
    assert a.admit(dict(good, kind=1), NOW).http == 400
    huge = dict(good, content=good["content"] + " " * E.MAX_EVENT_BYTES)
    assert a.admit(huge, NOW).http == 413
    future = E.build_identity(key(1), "agent", created_at=NOW + 3600)
    r = a.admit(future, NOW)
    assert r.http == 400 and "future" in r.reason
    assert a.store.counts() == {}


def test_duplicates_are_harmless(tmp_path):
    a = adm(tmp_path)
    ev = ident(1)
    assert a.admit(ev, NOW).status == "accepted"
    assert a.admit(ev, NOW).status == "duplicate"
    assert a.store.counts() == {"main": 1}


def test_strangers_are_rate_limited_and_capped(tmp_path):
    a = adm(tmp_path, stranger_burst=3, stranger_per_minute=0.0, stranger_stored=100)
    codes = [a.admit(ident(9, note=str(i)), NOW).http for i in range(5)]
    assert codes == [202, 202, 202, 429, 429]
    b = adm(tmp_path / "b", stranger_burst=100, stranger_stored=4)
    codes = [b.admit(ident(9, note=str(i)), NOW).http for i in range(6)]
    assert codes == [202] * 4 + [429, 429]


def test_the_bucket_refills(tmp_path):
    a = adm(tmp_path, stranger_burst=1, stranger_per_minute=60.0, stranger_stored=100)
    assert a.admit(ident(9, "1"), NOW).http == 202
    assert a.admit(ident(9, "2"), NOW).http == 429
    assert a.admit(ident(9, "3"), NOW + 2).http == 202


def test_a_noisy_stranger_does_not_use_up_a_members_allowance(tmp_path):
    a = adm(tmp_path, stranger_burst=1, stranger_per_minute=0.0)
    for i in range(10):
        a.admit(ident(9, str(i)), NOW)
    assert a.admit(ident(1, "root"), NOW).status == "accepted"


def test_quarantine_expires(tmp_path):
    a = adm(tmp_path, quarantine_ttl=3600)
    a.admit(ident(9), NOW)
    a.admit(ident(1), NOW)
    assert a.purge(NOW + 3599) == 0
    assert a.purge(NOW + 3601) == 1
    assert a.store.counts() == {"main": 1}
    assert a.store.db.execute("SELECT COUNT(*) FROM tags").fetchone()[0] == 0


def test_a_delegation_limit_lowers_the_daily_allowance(tmp_path):
    a = adm(tmp_path)
    a.admit(E.build_delegation(key(1), pub(2), ["publish:acme/*"], max_events_per_day=2, created_at=NOW), NOW)
    codes = [a.admit(ident(2, str(i)), NOW + i).http for i in range(4)]
    assert codes == [200, 200, 429, 429]
    # the root itself is not held to that limit
    assert all(a.admit(ident(1, str(i)), NOW + i).http == 200 for i in range(3))


def test_events_that_arrive_before_their_authors_are_vouched_for_are_not_lost(tmp_path):
    """B posts an endorsement while still a stranger. The root vouches for B afterwards. Either
    order must leave the same events in main."""
    e_b = endorse(3, 4, at=NOW)           # B endorses C, held back at first
    e_root = endorse(1, 3, at=NOW)        # root endorses B
    first = adm(tmp_path / "1")
    assert first.admit(e_b, NOW).status == "quarantined"
    assert first.admit(e_root, NOW).status == "accepted"
    second = adm(tmp_path / "2")
    second.admit(e_root, NOW)
    second.admit(e_b, NOW)
    for a in (first, second):
        assert {e["id"] for e in a.store.query()} == {e_b["id"], e_root["id"]}
        assert a.graph(NOW).trust(C).value > 0
    assert first.store.counts() == {"main": 2}


def test_promotion_follows_a_chain_of_waiting_authors(tmp_path):
    a = adm(tmp_path)
    e3, e2, e1 = endorse(3, 4, at=NOW), endorse(2, 3, at=NOW), endorse(1, 2, at=NOW)
    a.admit(e3, NOW)
    a.admit(e2, NOW)
    assert a.store.counts() == {"quarantine": 2}
    a.admit(e1, NOW)
    assert a.store.counts() == {"main": 3}


def test_the_graph_is_rebuilt_when_main_changes(tmp_path):
    a = adm(tmp_path)
    assert a.graph(NOW).trust(A).value == 0
    a.admit(endorse(1, 2, at=NOW), NOW)
    assert a.graph(NOW).trust(A).value > 0


# ------------------------------------------------------------------- HTTP

@pytest.fixture()
def hub(tmp_path):
    port = free_port()
    s = Settings(data_dir=tmp_path / "data", upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}",
                 roots=[ROOT], anchor="")
    srv = Server(create_app(s), port).start()
    yield srv
    srv.stop()


def post(hub, ev):
    return httpx.post(f"{hub.url}/api/thub/events", json=ev, timeout=30)


def test_post_and_get(hub):
    r = post(hub, endorse(1, 2, at=1))
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert post(hub, ident(2, at=1)).json()["tier"] == "main"
    s = post(hub, ident(9, at=1))
    assert s.status_code == 202 and s.json()["status"] == "quarantined"

    got = httpx.get(f"{hub.url}/api/thub/events", params={"kinds": f"{E.IDENTITY}"}).json()["events"]
    assert [e["pubkey"] for e in got] == [A]
    by_p = httpx.get(f"{hub.url}/api/thub/events", params={"p": A}).json()["events"]
    assert [e["kind"] for e in by_p] == [E.ENDORSEMENT]
    by_author = httpx.get(f"{hub.url}/api/thub/events", params={"authors": ROOT}).json()["events"]
    assert len(by_author) == 1
    q = httpx.get(f"{hub.url}/api/thub/events", params={"quarantine": "1", "limit": "1"}).json()["events"]
    assert len(q) == 1
    assert httpx.get(f"{hub.url}/api/thub/events", params={"since": "abc"}).status_code == 400
    assert post(hub, {"event": ident(2, "wrapped", at=1)}).status_code == 200
    assert httpx.post(f"{hub.url}/api/thub/events", content=b"not json").status_code == 400


def test_trust_endpoint_explains_itself(hub):
    post(hub, endorse(1, 2, w=0.8, at=1))
    post(hub, endorse(2, 3, w=0.5, at=1))
    d = httpx.get(f"{hub.url}/api/thub/trust/{B}").json()
    assert d["trust"] == pytest.approx(0.4) and d["member"] and not d["root"]
    assert [(p["from"], p["to"]) for p in d["path"]] == [(ROOT, A), (A, B)]
    assert httpx.get(f"{hub.url}/api/thub/trust/{X}").json()["trust"] == 0
    assert httpx.get(f"{hub.url}/api/thub/trust/{ROOT}").json()["root"] is True


# -------------------------------------------------------------------- CLI

def run_cli(tmp_path, *args, env=None):
    e = dict(os.environ, THUB_DATA=str(tmp_path / "cli"), THUB_ROOTS=ROOT, **(env or {}))
    p = subprocess.run([sys.executable, "-m", "torrenthub", *args], capture_output=True, text=True, env=e, timeout=60)
    return p


def test_cli_round_trip(tmp_path):
    kf = tmp_path / "root.key"
    kf.write_text(key(1).hex())
    out = tmp_path / "e.json"
    p = run_cli(tmp_path, "endorse", "--key-file", str(kf), "--subject", A, "--scope", "*", "--weight", "0.75", "--delegable", "--out", str(out))
    assert p.returncode == 0, p.stderr
    p = run_cli(tmp_path, "events-add", str(out))
    assert json.loads(p.stdout)["status"] == "accepted"
    p = run_cli(tmp_path, "trust", A)
    d = json.loads(p.stdout)
    assert d["trust"] == 0.75 and d["member"]
    # a delegation, then a revocation of the endorsement
    out2 = tmp_path / "d.json"
    assert run_cli(tmp_path, "delegate", "--key-file", str(kf), "--subject", A, "--scope", "publish:acme/*", "--expires-in", "3600", "--out", str(out2)).returncode == 0
    assert json.loads(run_cli(tmp_path, "events-add", str(out2)).stdout)["status"] == "accepted"
    ev_id = json.loads(out.read_text())["id"]
    out3 = tmp_path / "r.json"
    assert run_cli(tmp_path, "revoke", "--key-file", str(kf), "--kind", "event", "--target", ev_id, "--out", str(out3)).returncode == 0
    run_cli(tmp_path, "events-add", str(out3))
    assert json.loads(run_cli(tmp_path, "trust", A).stdout)["trust"] == 0
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(dict(json.loads(out.read_text()), sig="00" * 64)))
    assert run_cli(tmp_path, "events-add", str(bad)).returncode == 1
    listing = run_cli(tmp_path, "events")
    assert listing.stdout.count("\n") == 3
    p = run_cli(tmp_path, "endorse", "--key-file", str(kf), "--subject", A, "--scope", "*", "--weight", "2")
    assert p.returncode != 0


def test_pull_from_another_gateway(hub, tmp_path):
    post(hub, endorse(1, 2, at=1))
    post(hub, ident(9, at=1))
    p = run_cli(tmp_path, "events-pull", hub.url)
    assert p.returncode == 0, p.stderr
    tally = json.loads(p.stdout)
    assert tally == {"accepted": 1}, "only main events are served by default, and they re-check cleanly here"
    assert json.loads(run_cli(tmp_path, "trust", A).stdout)["trust"] > 0
