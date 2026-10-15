"""A request cycle between two agents and a hub, over real HTTP, with no human step in it."""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import struct
import subprocess
import sys
import threading
import time
from collections import OrderedDict

import httpx
import pytest

from tests.conftest import Server, free_port
from tests.fake_upstream import REPO, build_app
from tests.test_trust import ROOT, key, pub
from torrenthub import events as E
from torrenthub.app import create_app
from torrenthub.config import Settings
from torrenthub.workflow import Participant, Worker, make_request, wait_for_answer

REQ, W1, W2, STRANGER = 3, 4, 5, 9


class Evil:
    def __reduce__(self):
        return (os.system, ("true",))


def safetensors_bytes() -> bytes:
    n = 300 * 1000
    header = json.dumps({"w": {"dtype": "F32", "shape": [300, 1000], "data_offsets": [0, n * 4]}}).encode()
    return struct.pack("<Q", len(header)) + header + b"\0" * (n * 4)


FILES = {
    "config.json": b'{"a": 1}\n',
    "good.safetensors": safetensors_bytes(),
    "benign.bin": pickle.dumps(OrderedDict(w=b"x" * 1_300_000), protocol=4),
    "evil.bin": pickle.dumps([Evil(), b"y" * 1_300_000], protocol=4),
}
SHA = {p: hashlib.sha256(d).hexdigest() for p, d in FILES.items()}


@pytest.fixture()
def world(tmp_path):
    up = Server(build_app(dict(FILES)), free_port()).start()
    port = free_port()
    s = Settings(data_dir=tmp_path / "hub", upstream=up.url, public_url=f"http://127.0.0.1:{port}", roots=[ROOT], anchor="")
    hub = Server(create_app(s), port).start()
    for p in FILES:  # the hub holds the bytes
        assert httpx.get(f"{hub.url}/{REPO}/resolve/main/{p}", timeout=60).status_code == 200
    now = int(time.time()) - 60

    def vouch(*evs):
        for ev in evs:
            r = httpx.post(f"{hub.url}/api/thub/events", json=ev, timeout=30)
            assert r.status_code == 200, r.text

    vouch(
        E.build_endorsement(key(1), pub(W1), ["work:*", "attest:*"], 0.9, delegable=False, created_at=now),
        E.build_endorsement(key(1), pub(W2), ["work:*", "attest:*"], 0.9, delegable=False, created_at=now),
        E.build_endorsement(key(1), pub(REQ), ["request:*"], 0.9, delegable=False, created_at=now),
        E.build_endorsement(key(1), pub(STRANGER), ["request:*"], 0.9, delegable=False, created_at=now),
    )

    def agent(name, secret, roots=(ROOT,)):
        return Participant(tmp_path / name, roots, hub.url, key(secret))

    yield type("W", (), {"hub": hub, "agent": staticmethod(agent), "vouch": staticmethod(vouch), "tmp": tmp_path})
    hub.stop()
    up.stop()


def serve_in_thread(worker, **kw):
    out = []
    t = threading.Thread(target=lambda: out.extend(worker.run(poll=0.2, **kw)), daemon=True)
    t.start()
    return t, out


# ------------------------------------------------------------------ the cycle

def test_two_agents_complete_a_request_cycle_with_nobody_in_the_loop(world):
    requester, worker = world.agent("q", REQ), Worker(world.agent("w1", W1))
    t, out = serve_in_thread(worker, max_requests=1, idle_exit=30)
    req = make_request(requester, "hash_verified", [SHA["good.safetensors"]], deadline_in=120)
    st = wait_for_answer(requester, req["id"], timeout=30, poll=0.3)
    t.join(10)
    assert st.state == "accepted", st
    assert st.accepted_by == (pub(W1),) and st.outcome == ("attestation", ((SHA["good.safetensors"], True),))
    assert [o.action for o in out] == ["answered"]
    # the hub holds the whole trail, and an ordinary verdict by the operator's roots now says the hash was verified
    kinds = {e["kind"] for e in httpx.get(f"{world.hub.url}/api/thub/events", params={"kinds": ",".join(map(str, E.KINDS)), "limit": 500}, timeout=30).json()["events"]}
    assert {E.REQUEST, E.CLAIM, E.RESULT, E.ATTESTATION} <= kinds
    assert requester.graph().verdict(SHA["good.safetensors"], "hash_verified").status == "satisfied"


def test_a_failed_check_is_still_an_accepted_answer(world):
    requester, worker = world.agent("q", REQ), Worker(world.agent("w1", W1))
    t, _ = serve_in_thread(worker, max_requests=1, idle_exit=30)
    req = make_request(requester, "format_scan", [SHA["evil.bin"]], args={"filename": "evil.bin"}, deadline_in=120)
    st = wait_for_answer(requester, req["id"], timeout=30, poll=0.3)
    t.join(10)
    assert st.state == "accepted" and st.outcome == ("attestation", ((SHA["evil.bin"], False),)), "the answer is: this file failed the scan"


def test_the_requester_can_demand_two_independent_workers(world):
    requester = world.agent("q", REQ)
    w1, w2 = Worker(world.agent("w1", W1)), Worker(world.agent("w2", W2))
    t1, _ = serve_in_thread(w1, max_requests=1, idle_exit=30)
    req = make_request(requester, "hash_verified", [SHA["benign.bin"]], deadline_in=120)
    mid = wait_for_answer(requester, req["id"], n=2, timeout=5, poll=0.3)
    assert mid.state == "answered", "one worker is not two"
    t2, _ = serve_in_thread(w2, max_requests=1, idle_exit=30)
    st = wait_for_answer(requester, req["id"], n=2, timeout=30, poll=0.3)
    t1.join(10)
    t2.join(10)
    assert st.state == "accepted" and sorted(st.accepted_by) == sorted([pub(W1), pub(W2)])


def test_a_worker_nobody_vouched_for_cannot_get_an_answer_accepted(world):
    requester = world.agent("q", REQ)
    rogue = Worker(world.agent("rogue", STRANGER))
    t, out = serve_in_thread(rogue, max_requests=1, idle_exit=30)
    req = make_request(requester, "hash_verified", [SHA["good.safetensors"]], deadline_in=120)
    st = wait_for_answer(requester, req["id"], timeout=6, poll=0.3)
    t.join(10)
    assert st.state in ("open", "claimed", "answered") and st.accepted_by == ()


def test_a_worker_only_serves_requesters_it_trusts(world):
    # key 10 is a member (vouched for something else) but nobody vouched for it to ask for work
    world.vouch(E.build_endorsement(key(1), pub(10), ["attest:other"], 0.9, delegable=False, created_at=int(time.time()) - 60))
    outsider = world.agent("o", 10)
    worker = Worker(world.agent("w1", W1))
    req = make_request(outsider, "hash_verified", [SHA["good.safetensors"]], deadline_in=100)
    worker.p.pull()
    g = worker.p.graph()
    assert req["id"] in g.requests, "the worker can see the request"
    assert worker.serveable(g, g.requests[req["id"]], time.time()) == "the requester is not trusted for request:hash_verified"
    assert worker.step() == [], "and does not act on it"
    assert not g.results_for(req["id"]) and not g.claims_for(req["id"])


def test_a_worker_declines_what_it_cannot_do_and_that_is_not_an_answer(world):
    requester, worker = world.agent("q", REQ), Worker(world.agent("w1", W1))
    t, out = serve_in_thread(worker, max_requests=1, idle_exit=30)
    req = make_request(requester, "format_scan", [SHA["good.safetensors"]], deadline_in=120)  # no filename: no scanner can be chosen
    st = wait_for_answer(requester, req["id"], timeout=8, poll=0.3)
    t.join(10)
    assert [o.action for o in out] == ["declined"] and st.state != "accepted"


def test_a_worker_reports_failure_when_the_hub_does_not_hold_the_blob(world):
    requester, worker = world.agent("q", REQ), Worker(world.agent("w1", W1))
    t, out = serve_in_thread(worker, max_requests=1, idle_exit=30)
    req = make_request(requester, "hash_verified", ["ab" * 32], deadline_in=120)
    st = wait_for_answer(requester, req["id"], timeout=8, poll=0.3)
    t.join(10)
    assert [o.action for o in out] == ["failed"] and st.state != "accepted"


def test_an_expired_request_is_not_served_and_expires_for_the_requester(world):
    requester, worker = world.agent("q", REQ), Worker(world.agent("w1", W1))
    now = int(time.time())
    old = E.build_request(key(REQ), "hash_verified", [SHA["good.safetensors"]], deadline=now - 30, created_at=now - 100)
    assert requester.post(old) == "accepted"
    assert worker.step() == [], "a request past its deadline is not picked up"
    requester.pull()  # bring in the endorsements that make this agent a member of its own view
    assert requester.graph().request_status(old["id"], now=now).state == "expired"


def test_the_hub_lists_open_requests(world):
    requester = world.agent("q", REQ)
    req = make_request(requester, "hash_verified", [SHA["good.safetensors"]], deadline_in=120)
    r = httpx.get(f"{world.hub.url}/api/thub/requests", timeout=30).json()["requests"]
    assert [q["id"] for q in r] == [req["id"]] and r[0]["state"] == "open" and r[0]["task"] == "hash_verified"
    assert httpx.get(f"{world.hub.url}/api/thub/requests", params={"task": "format_scan"}, timeout=30).json()["requests"] == []


def test_the_requests_of_a_stranger_stay_out_of_the_hubs_list(world):
    nobody = world.agent("n", 8)
    ev = E.build_request(key(8), "hash_verified", [SHA["good.safetensors"]], deadline=int(time.time()) + 100, created_at=int(time.time()))
    assert nobody.post(ev) == "quarantined"
    assert httpx.get(f"{world.hub.url}/api/thub/requests", timeout=30).json()["requests"] == []


# --------------------------------------------------------------------- the CLI

def test_the_command_line_does_the_same_cycle(world):
    def cli(name, *args, **kw):
        env = dict(os.environ, THUB_DATA=str(world.tmp / name), THUB_ROOTS=ROOT)
        return subprocess.Popen([sys.executable, "-m", "torrenthub", *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    for n, sk in (("rk", REQ), ("wk", W1)):
        (world.tmp / f"{n}.key").write_text(key(sk).hex())
    wk = cli("w", "work", "--hub", world.hub.url, "--key-file", str(world.tmp / "wk.key"), "--poll", "0.3", "--max", "1", "--idle-exit", "40")
    rq = cli("q", "request", "--hub", world.hub.url, "--key-file", str(world.tmp / "rk.key"), "--task", "hash_verified",
             "--input", SHA["good.safetensors"], "--wait", "40", "--deadline-in", "120")
    out, err = rq.communicate(timeout=90)
    wout, werr = wk.communicate(timeout=60)
    assert rq.returncode == 0, (out, err)
    last = json.loads(out.strip().splitlines()[-1])
    assert last["state"] == "accepted" and last["accepted_by"] == [pub(W1)] and last["outcome"][0] == "attestation"
    assert '"answered"' in wout
    lst = subprocess.run([sys.executable, "-m", "torrenthub", "requests", "--hub", world.hub.url, "--all"], capture_output=True, text=True,
                         env=dict(os.environ, THUB_DATA=str(world.tmp / "x")), timeout=30)
    assert "hash_verified" in lst.stdout
