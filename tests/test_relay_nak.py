"""Round trips through a relay we did not write: `nak serve` (an in-memory relay built on khatru).
Skipped when `nak` is not installed."""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
import subprocess
import time

import pytest

pytest.importorskip("websockets")
NAK = shutil.which("nak") or shutil.which("nak", path="/home/lostcause/go/bin")
pytestmark = pytest.mark.skipif(NAK is None, reason="nak is not installed")

from tests.conftest import free_port  # noqa: E402
from tests.test_relay import NOW, hub_adm, populate  # noqa: E402
from torrenthub import events as E  # noqa: E402
from torrenthub import relay as R  # noqa: E402
from torrenthub import relay_sync as RS  # noqa: E402


@pytest.fixture()
def nak_relay():
    port = free_port()
    p = subprocess.Popen([NAK, "serve", "--port", str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.time() + 25
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    else:
        p.kill()
        pytest.skip("nak serve did not start")
    yield f"ws://127.0.0.1:{port}"
    p.terminate()
    p.wait(5)


def test_events_round_trip_through_nak_serve_and_nak_agrees(nak_relay, tmp_path):
    src = hub_adm(tmp_path, "src")
    sent = populate(src)
    out = asyncio.run(RS.push(src, nak_relay))
    assert out["accepted"] == len(sent) and out["refused"] == {}
    dst = hub_adm(tmp_path, "dst")
    got = asyncio.run(RS.pull(dst, nak_relay))
    assert got["fetched"] == len(sent) and got.get("accepted") == len(sent)
    assert {e["id"] for e in dst.store.query(list(E.KINDS), limit=500)} == {e["id"] for e in sent}
    # nak reads the same relay with its own code and sees what we sent, event for event
    r = subprocess.run([NAK, "req", "-k", str(E.ENDORSEMENT), nak_relay], capture_output=True, text=True, timeout=30)
    theirs = [json.loads(line) for line in r.stdout.splitlines() if line.startswith("{")]
    assert {e["id"] for e in theirs} == {e["id"] for e in sent if e["kind"] == E.ENDORSEMENT} and len(theirs) == 5
    assert all(any(t[0] == "d" for t in e["tags"]) for e in theirs)


def test_nak_can_verify_what_we_publish_and_we_can_read_what_nak_publishes(nak_relay):
    ev = E.build_identity((7).to_bytes(32, "big"), "agent", created_at=NOW)
    assert asyncio.run(R.publish_all(nak_relay, [ev]))[0].accepted
    v = subprocess.run([NAK, "verify"], input=json.dumps(ev), capture_output=True, text=True, timeout=30)
    assert v.returncode == 0, v.stderr
    theirs = subprocess.run([NAK, "event", "--sec", "00" * 31 + "09", "-k", "1", "-c", "hello from nak", nak_relay], capture_output=True, text=True, timeout=30)
    assert theirs.returncode == 0, theirs.stderr
    evs, note = asyncio.run(R.fetch_all(nak_relay, {"kinds": [1]}))
    assert [e["content"] for e in evs] == ["hello from nak"] and note == ""


def test_probe_against_nak_serve(nak_relay):
    pr = asyncio.run(R.probe(nak_relay, max_bytes=256 * 1024))
    assert pr.connected and all(v == "ok" for v in pr.kinds.values()), pr.kinds
    assert pr.keeps_both_with_d is True
    print("\nnak serve:", pr.asdict())
