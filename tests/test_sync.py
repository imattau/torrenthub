"""Event sync between hubs: pull, push, paging, and not believing what a peer says."""

from __future__ import annotations

import time

import httpx
import pytest

from tests.conftest import Server, free_port
from tests.test_trust import A, B, ROOT, endorse, key, pub
from torrenthub import events as E
from torrenthub import eventstore
from torrenthub.admission import Admission, Limits
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.eventstore import EventStore
from torrenthub.sync import sync

NOW = int(time.time())


def make_hub(tmp_path, name):
    port = free_port()
    s = Settings(data_dir=tmp_path / name, upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}",
                 roots=[ROOT], anchor="")
    return Server(create_app(s), port).start()


@pytest.fixture()
def two(tmp_path):
    a, b = make_hub(tmp_path, "a"), make_hub(tmp_path, "b")
    yield a, b
    a.stop()
    b.stop()


def post(hub, ev):
    return httpx.post(f"{hub.url}/api/thub/events", json=ev, timeout=30)


def local(tmp_path, name="local"):
    return Admission(EventStore(tmp_path / name), [ROOT], Limits())


def ids(hub):
    r = httpx.get(f"{hub.url}/api/thub/events", params={"kinds": ",".join(map(str, E.KINDS)), "limit": 500}, timeout=30)
    return {e["id"] for e in r.json()["events"]}


def test_pull_brings_in_what_the_peer_has(two, tmp_path):
    hub, _ = two
    evs = [endorse(1, 2, at=NOW), E.build_identity(key(2), "agent", created_at=NOW)]
    for ev in evs:
        assert post(hub, ev).status_code == 200
    adm = local(tmp_path)
    out = sync(adm, hub.url, pull=True, push=False)
    assert out["pulled"] == {"accepted": 2}
    assert {e["id"] for e in evs} == {e["id"] for e in adm.store.query(list(E.KINDS))}
    assert sync(adm, hub.url, push=False)["pulled"] == {}, "second run has nothing new"


def test_push_sends_what_the_peer_lacks_and_pull_only_does_not(two, tmp_path):
    hub, _ = two
    adm = local(tmp_path)
    ev = endorse(1, 2, at=NOW)
    adm.admit(ev, NOW)
    assert sync(adm, hub.url, pull=True, push=False)["pushed"] == {}
    assert ev["id"] not in ids(hub)
    out = sync(adm, hub.url)
    assert out["pushed"] == {"accepted": 1}
    assert ev["id"] in ids(hub)


def test_two_hubs_end_up_with_the_same_events(two, tmp_path):
    a, b = two
    for ev in (endorse(1, 2, at=NOW), E.build_identity(key(2), "agent", created_at=NOW)):
        post(a, ev)
    for ev in (endorse(1, 3, at=NOW), endorse(2, 4, at=NOW + 1)):
        post(b, ev)
    adm = local(tmp_path, "mid")
    # b holds an event by key 2, who is only a member once a's endorsement of it reaches b, so
    # b's event is quarantined (and not served) until then. Rounds settle it.
    for _ in range(4):
        sync(adm, a.url)
        sync(adm, b.url)
        if ids(a) == ids(b) and len(ids(a)) == 4:
            break
    assert ids(a) == ids(b) and len(ids(a)) == 4


def test_a_peer_cannot_make_us_believe_what_admission_would_refuse(two, tmp_path):
    hub, _ = two
    stranger = E.build_endorsement(key(9), pub(3), ["*"], 1.0, created_at=NOW)  # nobody we trust
    assert post(hub, stranger).status_code == 202  # the peer parked it in quarantine
    adm = local(tmp_path)
    out = sync(adm, hub.url, push=False)
    assert out["pulled"] == {}, "quarantined events are not served to a plain pull"
    # Force one through the way a hostile peer would: it simply lists a stranger's event as ordinary.
    adm.admit(stranger, NOW)
    assert adm.graph(NOW).trust(pub(3)).value == 0


def test_a_forged_event_from_a_peer_is_rejected(tmp_path, monkeypatch):
    adm = local(tmp_path)
    good = endorse(1, 2, at=NOW)
    forged = dict(good, sig="00" * 64)

    class Fake:
        def get(self, url, params=None):
            class R:
                status_code = 200

                def raise_for_status(self):
                    pass

                def json(self):
                    return {"events": [forged]}
            return R()

        def close(self):
            pass

    out = sync(adm, "http://peer", push=False, client=Fake())
    assert out["pulled"] == {"rejected": 1}
    assert adm.store.query(list(E.KINDS)) == []


def test_paging_walks_past_the_page_limit(two, tmp_path, monkeypatch):
    hub, _ = two
    for i in range(7):
        post(hub, endorse(1, 20 + i, at=NOW - i * 10))  # distinct seconds
    monkeypatch.setattr("torrenthub.sync.MAX_LIMIT", 3)
    adm = local(tmp_path)
    out = sync(adm, hub.url, push=False)
    assert out["pulled"] == {"accepted": 7} and out["remote_events"] == 7


def test_attestations_travel_too(two, tmp_path):
    hub, _ = two
    post(hub, endorse(1, 2, scope="attest:*", at=NOW))
    att = E.build_attestation(key(2), "hash_verified", "x", "ab" * 32, ok=True, created_at=NOW)
    assert post(hub, att).status_code == 200
    adm = local(tmp_path)
    assert sync(adm, hub.url, push=False)["pulled"] == {"accepted": 2}
    assert [e["kind"] for e in adm.store.query([E.ATTESTATION])] == [E.ATTESTATION]


def test_cli_sync_and_rotate(two, tmp_path):
    import json
    import os
    import subprocess
    import sys

    hub, _ = two
    root_kf, a_kf = tmp_path / "root.key", tmp_path / "a.key"
    root_kf.write_text(key(1).hex())
    a_kf.write_text(key(2).hex())

    def cli(*args):
        env = dict(os.environ, THUB_DATA=str(tmp_path / "cli"), THUB_ROOTS=ROOT)
        return subprocess.run([sys.executable, "-m", "torrenthub", *args], capture_output=True, text=True, env=env, timeout=60)

    # Root endorses A; A rotates to B. Both statements go to the hub, then the CLI syncs from it.
    endorsement, rotation = tmp_path / "e.json", tmp_path / "r.json"
    assert cli("endorse", "--key-file", str(root_kf), "--subject", A, "--scope", "*", "--weight", "0.8", "--out", str(endorsement)).returncode == 0
    p = cli("revoke", "--key-file", str(a_kf), "--kind", "key", "--target", A, "--successor", B, "--out", str(rotation))
    assert p.returncode == 0, p.stderr
    for f in (endorsement, rotation):
        assert post(hub, json.loads(f.read_text())).status_code == 200
    p = cli("events-sync", hub.url, "--pull-only")
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["pulled"] == {"accepted": 2}
    t = json.loads(cli("trust", B).stdout)
    assert t["trust"] == pytest.approx(0.8) and t["member"]
    assert json.loads(cli("trust", A).stdout)["trust"] == 0
