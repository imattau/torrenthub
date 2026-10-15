"""Two agents, one request cycle, no human step.

A requester posts a request to a hub and waits. A worker watches the hub, picks up requests it is
willing to serve, claims them, does the work and posts the answer. The requester then decides, by
its own roots, whether the answer stands. Neither trusts the hub: each pulls the events it needs
into its own store and judges them there.

What "no human step" means here: trust between the two was set up beforehand (the requester's
roots endorse the worker for `work:<task>` and `attest:<claim>`, the worker's roots trust the
requester for `request:<task>`, and the hub knows both as members). Nothing is approved while the
cycle runs.

Work a worker can do today is the checks the verifier already makes: `hash_verified` and
`format_scan` on a blob the hub holds. The answer is the same attestation events anyone could
publish, so a requester that does not trust the worker can still ask a trusted replicator.
"""

from __future__ import annotations

import hashlib
import logging
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import events as E
from .admission import Admission
from .eventstore import EventStore
from .signing import public_key
from .sync import sync
from .trust import Graph, RequestStatus
from .verifier import attest_file_events, scan_file

log = logging.getLogger("torrenthub.workflow")

TASKS = ("hash_verified", "format_scan")  # what workers here can do
LEASE_MARGIN = 5  # seconds before a deadline when a worker stops starting new work


class Participant:
    """One agent's view: its key, its own roots and store, and a hub it talks to."""

    def __init__(self, data_dir: Path, roots, hub: str, secret: bytes, hops: int = 3):
        self.secret = secret
        self.pubkey = public_key(secret).hex()
        self.hub = hub.rstrip("/")
        self.roots = set(roots)
        self.store = EventStore(Path(data_dir))
        self.adm = Admission(self.store, self.roots, hops=hops)

    def pull(self) -> dict:
        """Bring in everything the hub holds. Each event is checked again here, so a lying hub
        gets nothing past this agent's own admission."""
        return sync(self.adm, self.hub, E.KINDS, pull=True, push=False)["pulled"]

    def graph(self, now: float | None = None) -> Graph:
        return self.adm.graph(int(time.time() if now is None else now))

    def post(self, ev: dict) -> str:
        """Send an event to the hub. Returns its answer: accepted, quarantined (the hub does not
        know this key), duplicate, or rejected."""
        r = httpx.post(self.hub + "/api/thub/events", json=ev, timeout=30)
        try:
            st = r.json().get("status", f"http{r.status_code}")
        except ValueError:
            st = f"http{r.status_code}"
        self.adm.admit(ev)  # and into our own store, so we see it without pulling again
        return st


# ------------------------------------------------------------------ the requester

def make_request(p: Participant, task: str, inputs: list[str], *, deadline_in: float = 600, args: dict | None = None,
                 want: str = "attestation", reward: str | None = None) -> dict:
    now = int(time.time())
    ev = E.build_request(p.secret, task, inputs, args=args, deadline=now + int(deadline_in), want=want, reward=reward, created_at=now)
    st = p.post(ev)
    if st not in ("accepted", "duplicate"):
        raise RuntimeError(f"the hub did not take the request ({st}); is this key known to it?")
    return ev


def wait_for_answer(p: Participant, request_id: str, *, n: int = 1, min_trust: float = 0.0, timeout: float = 120, poll: float = 1.0,
                    progress=None) -> RequestStatus:
    """Pull and judge until the request is accepted, disputed or expired, or `timeout` runs out
    (then the last status is returned, which will be open, claimed or answered)."""
    end = time.monotonic() + timeout
    last = None
    while True:
        p.pull()
        st = p.graph().request_status(request_id, n=n, min_trust=min_trust, now=time.time())
        if progress and st.state != last:
            progress(st)
        last = st.state
        if st.done or time.monotonic() >= end:
            return st
        time.sleep(poll)


# -------------------------------------------------------------------- the worker

@dataclass
class Outcome:
    request: str
    action: str  # answered | failed | declined | skipped
    detail: str = ""


@dataclass
class Worker:
    p: Participant
    tasks: tuple = TASKS
    lease: float = 300.0
    max_bytes: int = 8 * 1024**3
    workdir: Path | None = None
    seen: set = field(default_factory=set)

    def serveable(self, g: Graph, req: E.Request, now: float) -> str | None:
        """None if this worker should take the request, else why not."""
        if req.task not in self.tasks:
            return f"does not do {req.task}"
        if now >= req.deadline - LEASE_MARGIN:
            return "too close to its deadline"
        if req.id in self.seen:
            return "already handled"
        mine = [r for r in g.results_for(req.id) if r.issuer == self.p.pubkey]
        if mine:
            return "already answered"
        if req.issuer not in self.p.roots and g.trust(req.issuer, f"request:{req.task}").value <= 0:
            return "the requester is not trusted for request:" + req.task
        return None

    def step(self) -> list[Outcome]:
        """One pass: pull, then serve every request this worker is willing to."""
        self.p.pull()
        now = time.time()
        g = self.p.graph(now)
        out = []
        for req in g.requests_list():
            if self.serveable(g, req, now) is not None:
                continue
            self.seen.add(req.id)
            out.append(self.serve(req))
        return out

    def serve(self, req: E.Request) -> Outcome:
        p = self.p
        now = int(time.time())
        lease_end = min(now + int(self.lease), req.deadline)
        if lease_end > now:
            p.post(E.build_claim(p.secret, req.id, expires=lease_end, created_at=now))
        try:
            atts, note = self._do(req)
        except Exception as e:  # noqa: BLE001
            log.exception("request %s failed", req.id[:12])
            p.post(E.build_result(p.secret, req.id, "failed", note=f"{type(e).__name__}: {e}"[:400]))
            return Outcome(req.id, "failed", str(e))
        if atts is None:
            p.post(E.build_result(p.secret, req.id, "declined", note=note))
            return Outcome(req.id, "declined", note)
        for a in atts:
            st = p.post(a)
            if st not in ("accepted", "duplicate"):
                log.warning("hub answered %s to an attestation; it may not know this worker", st)
        st = p.post(E.build_result(p.secret, req.id, "done", attestations=[a["id"] for a in atts], note=note))
        if st == "quarantined":
            return Outcome(req.id, "answered", "the hub holds the answer in quarantine: this worker is not a member there")
        return Outcome(req.id, "answered", note)

    def _do(self, req: E.Request) -> tuple[list[dict] | None, str]:
        """(attestations, note), or (None, why) when the request cannot be done as asked."""
        names = req.args.get("filename") or req.args.get("filenames") or []
        names = [names] if isinstance(names, str) else list(names)
        atts: list[dict] = []
        with tempfile.TemporaryDirectory(dir=self.workdir) as tmp:
            for x in req.inputs:
                path = Path(tmp) / x
                self._fetch(x, path)
                if req.task == "format_scan" and not any(scan_file(path, n) for n in names):
                    return None, "no scanner for that file type (give args.filename)"
                evs = attest_file_events(self.p.secret, path, x, names)
                mine = [e for e in evs if next(t[1] for t in e["tags"] if t[0] == "claim") == req.task]
                if not mine:
                    return None, f"could not produce a {req.task} attestation"
                atts += mine
                path.unlink(missing_ok=True)
        return atts, "; ".join(f"{E.parse_event(a).subject[:12]} ok={E.parse_event(a).ok}" for a in atts)

    def _fetch(self, x: str, dest: Path) -> None:
        """The bytes of blob `x` from the hub, hashed as they arrive so a lying hub is noticed."""
        h = hashlib.sha256()
        got = 0
        with httpx.stream("GET", f"{self.p.hub}/blobs/{x}", timeout=60, follow_redirects=True) as r:
            if r.status_code != 200:
                raise RuntimeError(f"the hub does not hold blob {x[:12]} ({r.status_code})")
            with open(dest, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    got += len(chunk)
                    if got > self.max_bytes:
                        raise RuntimeError(f"blob {x[:12]} is over the {self.max_bytes}-byte limit")
                    h.update(chunk)
                    f.write(chunk)
        # A mismatch is not an error here: the attestation will say the bytes are not what the name says.

    def run(self, *, poll: float = 5.0, max_requests: int | None = None, once: bool = False, idle_exit: float | None = None) -> list[Outcome]:
        done: list[Outcome] = []
        idle_since = time.monotonic()
        while True:
            got = self.step()
            done += got
            if got:
                idle_since = time.monotonic()
            if once or (max_requests is not None and len(done) >= max_requests):
                return done
            if idle_exit is not None and time.monotonic() - idle_since > idle_exit:
                return done
            time.sleep(poll)
