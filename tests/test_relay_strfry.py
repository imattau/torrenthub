"""Round trips through strfry, the relay most large public relays run. Opt in:

    podman run -d --name thub-strfry -p 127.0.0.1:7777:7777 -v thub-strfry-db:/app/strfry-db \\
        -v ./strfry.conf:/etc/strfry.conf:ro docker.io/dockurr/strfry:latest
    THUB_STRFRY_URL=ws://127.0.0.1:7777 python -m pytest tests/test_relay_strfry.py -s

The image ships a config that only accepts events from a whitelist of keys. These tests need that
plugin switched off (`writePolicy.plugin = ""` in strfry.conf) so the relay behaves like an open one.
Every other setting is strfry's default. Events are signed by throwaway keys, and the tests only
read back what they wrote.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time

import pytest

pytest.importorskip("websockets")
URL = os.environ.get("THUB_STRFRY_URL")
pytestmark = pytest.mark.skipif(not URL, reason="set THUB_STRFRY_URL to a local strfry to run these")

from torrenthub import events as E  # noqa: E402
from torrenthub import relay as R  # noqa: E402
from torrenthub import relay_sync as RS  # noqa: E402
from torrenthub import signing as sg  # noqa: E402
from torrenthub.manifest import build_manifest  # noqa: E402
from torrenthub.store import Store  # noqa: E402

NAK = shutil.which("nak") or shutil.which("nak", path="/home/lostcause/go/bin")


def run(coro):
    return asyncio.run(coro)


def fresh_world(tmp_path, name="src"):
    """A hub store with a root and a worker, all keys new for this run so earlier runs cannot interfere."""
    root, worker = os.urandom(32), os.urandom(32)
    from torrenthub.admission import Admission, Limits
    from torrenthub.eventstore import EventStore

    adm = Admission(EventStore(tmp_path / name), [sg.public_key(root).hex()], Limits())
    now = int(time.time())
    wpk = sg.public_key(worker).hex()
    evs = [E.build_endorsement(root, sg.public_key(os.urandom(32)).hex(), ["work:*"], 0.5, created_at=now - 100 + i) for i in range(5)]
    evs.append(E.build_endorsement(root, wpk, ["work:*", "attest:*"], 0.9, created_at=now - 90))
    evs += [E.build_attestation(worker, "hash_verified", "x", f"{i:064x}", ok=True, detail="d", created_at=now - 60 + i) for i in range(4)]
    req = E.build_request(worker, "hash_verified", ["ab" * 32], deadline=now + 600, created_at=now - 30)
    evs += [req, E.build_claim(worker, req["id"], expires=now + 300, created_at=now - 20), E.build_result(worker, req["id"], "failed", note="n", created_at=now - 10)]
    for ev in evs:
        assert adm.admit(ev, now).status == "accepted"
    return adm, evs, root, worker


def test_every_kind_round_trips_through_strfry_and_nothing_collapses(tmp_path):
    src, sent, root, _ = fresh_world(tmp_path)
    out = run(RS.push(src, URL))
    assert out["accepted"] + out["duplicate"] == len(sent) and out["refused"] == {} and out["skipped"] == 0, out
    from torrenthub.admission import Admission, Limits
    from torrenthub.eventstore import EventStore

    dst = Admission(EventStore(tmp_path / "dst2"), [sg.public_key(root).hex()], Limits())
    got = run(RS.pull(dst, URL, authors=sorted({e["pubkey"] for e in sent})))
    assert got["fetched"] == len(sent) and got.get("accepted") == len(sent), got
    assert {e["id"] for e in dst.store.query(list(E.KINDS), limit=500)} == {e["id"] for e in sent}


def test_strfry_collapses_events_with_no_d_tag_and_keeps_ours():
    sk = os.urandom(32)
    now = int(time.time())
    dless = [sg.sign_event(sk, E.ENDORSEMENT, [["p", sg.public_key(os.urandom(32)).hex()]], json.dumps({"n": i}), now - 5 + i) for i in range(3)]
    ours = [E.build_endorsement(sk, sg.public_key(os.urandom(32)).hex(), ["work:*"], 0.5, created_at=now - 2 + i) for i in range(3)]
    run(R.publish_all(URL, dless))
    run(R.publish_all(URL, ours))
    evs, _ = run(R.fetch_all(URL, {"kinds": [E.ENDORSEMENT], "authors": [sg.public_key(sk).hex()]}))
    ids = {e["id"] for e in evs}
    assert {e["id"] for e in ours} <= ids, "all of ours are kept"
    assert sum(1 for d in dless if d["id"] in ids) == 1, "of three events with no d tag, strfry keeps one"


def test_the_published_message_limit_is_not_the_event_limit():
    lim = run(R.info(URL)).get("limitation", {})
    assert lim.get("max_message_length") == 131072
    sk = os.urandom(32)
    pad = lambda n: sg.sign_event(sk, E.ATTESTATION, [["d", os.urandom(4).hex()]], "x" * n, int(time.time()))
    assert run(R.publish_all(URL, [pad(60_000)]))[0].accepted
    refused = run(R.publish_all(URL, [pad(70_000)]))[0]
    assert not refused.accepted and refused.prefix == "invalid" and "too large" in refused.message
    assert len(json.dumps(["EVENT", pad(70_000)])) < lim["max_message_length"], "it fits the published limit and is refused anyway"


def test_the_default_guard_keeps_an_oversize_manifest_off_the_relay(tmp_path):
    sk = os.urandom(32)
    info = {"sha": "ab" * 20, "siblings": [{"rfilename": f"part-{i:05d}.safetensors", "size": 10, "lfs": {"size": 10, "sha256": f"{i:064x}"}} for i in range(700)]}
    big = build_manifest(sk, "acme/big", info, ["main"], created_at=int(time.time()))
    store = Store(tmp_path / "s")
    store.add_manifest(big)
    guarded = run(RS.push_manifests(store, URL, ["acme/big"]))
    assert guarded["skipped"] == 1 and guarded["accepted"] == 0
    unguarded = run(RS.push_manifests(store, URL, ["acme/big"], max_event_bytes=None))
    assert unguarded["refused"] == {"invalid": 1}, "without the guard the relay says no"
    small = build_manifest(sk, "acme/small", info, ["main"], seq=1, table_blob=True, created_at=int(time.time()))
    store.add_manifest(small)
    assert run(RS.push_manifests(store, URL, ["acme/small"]))["accepted"] == 1


def test_manifests_round_trip_and_only_the_named_signer_is_taken(tmp_path):
    sk, other = os.urandom(32), os.urandom(32)
    info = {"sha": "cd" * 20, "siblings": [{"rfilename": "a.bin", "size": 3, "lfs": {"size": 3, "sha256": "ef" * 32}}]}
    mine = build_manifest(sk, "acme/rt", info, ["main"], seq=1, created_at=int(time.time()))
    theirs = build_manifest(other, "acme/rt", info, ["main"], seq=2, created_at=int(time.time()))
    run(R.publish_all(URL, [mine, theirs]))
    dst = Store(tmp_path / "dst")
    got = run(RS.pull_manifests(dst, URL, {sg.public_key(sk).hex()}, ["acme/rt"]))
    assert got["stored"] == 1 and [m["id"] for m in dst.list_manifests("acme/rt")] == [mine["id"]]


@pytest.mark.skipif(NAK is None, reason="nak is not installed")
def test_nak_reads_back_what_we_sent_to_strfry(tmp_path):
    src, sent, _, worker = fresh_world(tmp_path, "nk")
    run(RS.push(src, URL))
    wpk = sg.public_key(worker).hex()
    r = subprocess.run([NAK, "req", "-k", str(E.ATTESTATION), "-a", wpk, URL], capture_output=True, text=True, timeout=30)
    theirs = [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]
    assert {e["id"] for e in theirs} == {e["id"] for e in sent if e["kind"] == E.ATTESTATION} and len(theirs) == 4


def test_the_probe_agrees_with_strfrys_configuration():
    pr = run(R.probe(URL, max_bytes=1024 * 1024))
    assert all(v == "ok" for v in pr.kinds.values()) and pr.keeps_both_with_d is True and pr.keeps_both_dless is False
    assert 65_000 < pr.max_event_bytes <= 65_600 and pr.first_refused_bytes > 65_536
    assert pr.max_tags >= 1000 and pr.first_refused_tags and "too many tags" in pr.tag_refusal
