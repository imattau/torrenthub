"""HF-compatible read-only gateway. Point clients at it with HF_ENDPOINT."""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import mimetypes
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Callable
from urllib.parse import quote, unquote

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse

from .admission import Admission
from .config import Settings
from .eventstore import EventStore
from .metrics import Metrics
from .gaplog import GapLog
from .mirror import Inflight, Mirror
from .policy import check_file, load_policy
from .publish import REPO_NAME, Ingest, PublishError
from .store import Store, valid_key
from .swarm import Swarm, make_swarm
from .torrent import magnet
from .upstream import HubError, Upstream, UpstreamSet, make_upstream

OnBytes = Callable[[int], None]


class RangeNotSatisfiable(Exception):
    pass


class StreamAborted(Exception):
    """Raised inside a response body after headers are sent. The connection is dropped,
    which clients treat as a failed download and retry. It must not be a HubError,
    because the error handler cannot send a second response."""


def parse_range(header: str | None, size: int) -> tuple[int, int] | None:
    """Parse a single 'bytes=a-b' range. Return inclusive (start, end) or None."""
    if not header or not header.startswith("bytes=") or size == 0:
        return None
    spec = header[6:].split(",")[0].strip()
    start_s, _, end_s = spec.partition("-")
    try:
        if start_s == "":
            n = int(end_s)
            if n <= 0:
                raise RangeNotSatisfiable
            start, end = max(size - n, 0), size - 1
        else:
            start = int(start_s)
            end = int(end_s) if end_s else size - 1
    except ValueError:
        raise RangeNotSatisfiable
    end = min(end, size - 1)
    if start > end or start >= size:
        raise RangeNotSatisfiable
    return start, end


# --------------------------------------------------------------------- raw path parsing
# Revisions such as "refs/pr/1" arrive as "refs%2Fpr%2F1". The ASGI `path` is already
# decoded, which makes them look like extra path segments. The raw path keeps the
# encoding, so we split on that and decode each piece afterwards.

def raw_path(request: Request) -> str:
    rp = request.scope.get("raw_path")
    return rp.decode("latin-1") if rp else quote(request.url.path)


def parse_resolve(raw: str) -> tuple[str, str, str]:
    repo, _, rest = raw.lstrip("/").partition("/resolve/")
    rev, _, filename = rest.partition("/")
    return unquote(repo), unquote(rev), unquote(filename)


def parse_revision(raw: str) -> tuple[str, str]:
    repo, _, rev = raw.split("/api/models/", 1)[1].partition("/revision/")
    return unquote(repo), unquote(rev)


def parse_tree(raw: str) -> tuple[str, str, str]:
    repo, _, rest = raw.split("/api/models/", 1)[1].partition("/tree/")
    rev, _, sub = rest.partition("/")
    return unquote(repo), unquote(rev), unquote(sub)


# --------------------------------------------------------------------- responses

def content_disposition(name: str) -> str:
    """A header value that is plain ASCII whatever the file is called: a fallback name with every
    character outside printable ASCII, and every quote or backslash, replaced, and the real name
    after it in the RFC 5987 form that browsers and download tools understand."""
    base = name.rsplit("/", 1)[-1]
    fallback = "".join(c if 0x20 <= ord(c) < 0x7F and c not in '"\\%' else "_" for c in base) or "file"
    return f"inline; filename=\"{fallback}\"; filename*=UTF-8\'\'{quote(base, safe='')}"


def _range_headers(base_headers: dict, rng: tuple[int, int] | None, size: int) -> tuple[dict, int, int, int, int]:
    headers = dict(base_headers)
    headers["Accept-Ranges"] = "bytes"
    if rng:
        start, end = rng
        status = 206
        headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    else:
        start, end, status = 0, size - 1, 200
    length = end - start + 1 if size else 0
    headers["Content-Length"] = str(length)
    return headers, status, start, end, length


def file_response(
    path: Path,
    size: int,
    range_header: str | None,
    base_headers: dict,
    media_type: str,
    head: bool,
    on_bytes: OnBytes | None = None,
) -> Response:
    try:
        rng = parse_range(range_header, size)
    except RangeNotSatisfiable:
        return Response(status_code=416, headers={"Content-Range": f"bytes */{size}"})
    headers, status, start, _end, length = _range_headers(base_headers, rng, size)
    if head:
        return Response(status_code=status, headers=headers, media_type=media_type)

    def body():
        remaining = length
        with open(path, "rb") as f:
            f.seek(start)
            while remaining > 0:
                data = f.read(min(1 << 20, remaining))
                if not data:
                    break
                remaining -= len(data)
                if on_bytes:
                    on_bytes(len(data))
                yield data

    return StreamingResponse(body(), status_code=status, headers=headers, media_type=media_type)


def _read_at(f, pos: int, n: int) -> bytes:
    f.seek(pos)
    return f.read(n)


async def iter_inflight(inf: Inflight, start: int, end: int, on_bytes: OnBytes | None = None):
    """Yield bytes start..end (inclusive) of a download that may still be running.

    Bytes are released only as `Inflight` allows (holdback). When the source is a swarm, every
    piece is also read back from disk and checked against the torrent's SHA-1 hash before any
    of it is sent, so what a client receives never depends on libtorrent's file writes being
    visible yet. A failed check aborts the stream before the bad bytes go out.
    """
    pos = start
    f = None  # opened after the first release: the source file can change before that point
    cached_idx, cached = -1, b""
    gaps = GapLog(f"client {inf.rec.path}", inf.gap_warn)
    outcome = "client left"
    try:
        while pos <= end:
            try:
                limit = await inf.wait_for(pos)  # raises if the download failed verification
            except HubError as e:
                raise StreamAborted(e.message) from e
            except Exception as e:  # noqa: BLE001
                raise StreamAborted(str(e)) from e
            if f is None:
                f = await asyncio.to_thread(inf.open_for_read)
            check = inf.piece_check
            if check is None:
                n = min(1 << 20, end + 1 - pos, limit - pos)
                data = await asyncio.to_thread(_read_at, f, pos, n)
                if len(data) != n:
                    raise StreamAborted("short read from in-flight blob")
            else:
                piece_len, hashes = check
                idx = pos // piece_len
                if idx != cached_idx:
                    p0 = idx * piece_len
                    plen = min(piece_len, inf.rec.size - p0)
                    cached = await asyncio.to_thread(_read_at, f, p0, plen)
                    if len(cached) != plen or hashlib.sha1(cached).digest() != hashes[idx * 20:(idx + 1) * 20]:
                        raise StreamAborted(f"piece {idx} failed verification on read-back")
                    cached_idx = idx
                p0 = idx * piece_len
                n = min(1 << 20, end + 1 - pos, limit - pos, p0 + len(cached) - pos)
                data = cached[pos - p0:pos - p0 + n]
            pos += n
            if on_bytes:
                on_bytes(n)
            gaps.tick(n)
            yield data
        outcome = "ok"
    except StreamAborted:
        outcome = "aborted"
        raise
    finally:
        gaps.done(outcome)
        if f is not None:
            f.close()


def inflight_response(
    inf: Inflight,
    size: int,
    range_header: str | None,
    base_headers: dict,
    media_type: str,
    on_bytes: OnBytes | None = None,
) -> Response:
    """Stream a download that is still in progress. Length is known from the catalogue."""
    try:
        rng = parse_range(range_header, size)
    except RangeNotSatisfiable:
        return Response(status_code=416, headers={"Content-Range": f"bytes */{size}"})
    headers, status, start, end, _length = _range_headers(base_headers, rng, size)
    return StreamingResponse(
        iter_inflight(inf, start, end, on_bytes), status_code=status, headers=headers, media_type=media_type
    )


# ------------------------------------------------------------ request size limits

class _TooLarge(Exception):
    pass


class BodyLimit:
    """Refuse a request body over the limit for its path before it is read into memory.

    Every POST endpoint here parses JSON, and a framework reads the whole body first. Without a cap
    one unauthenticated client can cost the gateway hundreds of megabytes and seconds of CPU per
    request. A declared Content-Length over the limit is refused at once; a body that is streamed
    (chunked, or lying about its length) is cut off when it passes the limit."""

    def __init__(self, app, limits: dict[str, int]):
        self.app, self.limits = app, limits

    async def __call__(self, scope, receive, send):
        limit = None
        if scope["type"] == "http" and scope["method"] in ("POST", "PUT", "PATCH"):
            limit = next((n for prefix, n in self.limits.items() if scope["path"].startswith(prefix)), None)
        if limit is None:
            return await self.app(scope, receive, send)
        declared = next((v for k, v in scope["headers"] if k == b"content-length"), None)
        if declared is not None and declared.isdigit() and int(declared) > limit:
            return await self._refuse(send, limit)
        seen = 0
        started = False

        async def counting_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    raise _TooLarge
            return msg

        async def tracking_send(msg):
            nonlocal started
            started = started or msg["type"] == "http.response.start"
            await send(msg)

        try:
            await self.app(scope, counting_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._refuse(send, limit)

    @staticmethod
    async def _refuse(send, limit: int):
        body = json.dumps({"error": f"request body is over the {limit} byte limit for this endpoint"}).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"x-error-code", b"PayloadTooLarge"), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})


class RateLimit:
    """A token bucket per client address for the POST endpoints, checked before the body is read.

    The address is the one the server reports for the connection. uvicorn takes it from the peer, or
    from X-Forwarded-For when the peer is on the list in FORWARDED_ALLOW_IPS (default: loopback only,
    which suits a reverse proxy on the same machine). Behind a proxy on another machine, set
    FORWARDED_ALLOW_IPS to that proxy's address, or every client will share its bucket. Never list
    addresses you do not control: a client of a listed address can claim to be anyone."""

    def __init__(self, app, rules: dict[str, tuple[int, float]]):
        self.app, self.rules = app, rules
        self.buckets: dict[tuple[str, str], list[float]] = {}

    @staticmethod
    def _who(scope) -> str:
        client = scope.get("client")
        return client[0] if client else "unknown"

    async def __call__(self, scope, receive, send):
        rule = None
        if scope["type"] == "http" and scope["method"] == "POST":
            rule = next(((p, r) for p, r in self.rules.items() if scope["path"].startswith(p) and r[1] > 0), None)
        if rule is None:
            return await self.app(scope, receive, send)
        prefix, (burst, per_minute) = rule
        now = time.monotonic()
        key = (prefix, self._who(scope))
        tokens, last = self.buckets.get(key, [float(burst), now])
        tokens = min(float(burst), tokens + (now - last) * per_minute / 60.0)
        if tokens < 1:
            self.buckets[key] = [tokens, now]
            wait = max(1, int((1 - tokens) * 60.0 / per_minute) + 1)
            body = json.dumps({"error": f"too many requests from this address; try again in {wait}s"}).encode()
            return await send_response(send, 429, body, {b"retry-after": str(wait).encode(), b"x-error-code": b"RateLimited"})
        self.buckets[key] = [tokens - 1, now]
        if len(self.buckets) > 50_000:  # forget addresses that have recovered
            self.buckets = {k: v for k, v in self.buckets.items() if v[0] < burst - 0.5}
        await self.app(scope, receive, send)


async def send_response(send, status: int, body: bytes, extra: dict | None = None):
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), *(extra or {}).items()]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


# --------------------------------------------------------------------- app

def create_app(
    settings: Settings, upstream: Upstream | UpstreamSet | None = None, swarm: Swarm | None = None
) -> FastAPI:
    store = Store(settings.data_dir)
    upstream = upstream or make_upstream(settings)
    swarm = swarm or make_swarm(settings.swarm, settings.listen_port, settings.peers, settings.outgoing_utp)
    metrics = Metrics()
    events = EventStore(settings.data_dir)
    # Keys named in `signed:` rules are roots too: naming a key there already pins it.
    pinned = set(settings.roots)
    for _glob, mode in settings.trust:
        if mode.startswith("signed:"):
            pinned |= set(mode[len("signed:"):].split("+"))
    admission = Admission(events, pinned, hops=settings.trust_hops)
    if isinstance(upstream, UpstreamSet):
        upstream.delegation_check = lambda roots, signer, scope: admission.graph().may_sign(roots, signer, scope) is not None
    policy_rules = load_policy(settings.policy)
    if isinstance(upstream, UpstreamSet) and upstream.manifest_max_age is None:
        upstream.manifest_max_age = policy_rules.freshness.manifest_max_age  # the environment setting wins if both are given
    mirror = Mirror(settings, store, upstream, swarm, metrics)
    ingest = Ingest(settings, store, swarm, pinned, lambda: admission.graph(), metrics)

    def served(n: int) -> None:
        metrics.inc("thub_bytes_served_total", n)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        for b in store.seedable():
            if store.blob_complete(b.key):
                await swarm.seed(store.torrent_path(b.key), store.blob_path(b.key).parent)

        async def janitor():
            """Quarantined events are meant to last a day; nothing else removes them."""
            while True:
                try:
                    admission.purge()
                except Exception:  # noqa: BLE001
                    pass
                await asyncio.sleep(600)

        sweeper = asyncio.create_task(janitor())
        yield
        sweeper.cancel()
        await ingest.aclose()
        await mirror.aclose()
        await swarm.close()
        await upstream.aclose()

    app = FastAPI(title="torrenthub", lifespan=lifespan)
    app.add_middleware(BodyLimit, limits={"/api/thub/events": settings.max_event_body, "/api/thub/publish": settings.publish_max_body})
    # added last, so it runs first: a flooding address is turned away before anything else looks at the request
    app.add_middleware(RateLimit, rules={
        "/api/thub/events": (settings.events_per_ip_burst, settings.events_per_ip_per_minute),
        "/api/thub/publish": (10, settings.publish_per_ip_per_minute)})
    app.state.mirror = mirror
    app.state.ingest = ingest
    app.state.store = store
    app.state.metrics = metrics
    app.state.events = events
    app.state.admission = admission
    app.state.policy = policy_rules

    @app.exception_handler(HubError)
    async def hub_error(_: Request, exc: HubError):
        metrics.inc("thub_errors_total", code=exc.code)
        return JSONResponse(
            {"error": exc.message},
            status_code=exc.status,
            headers={"X-Error-Code": exc.code, "X-Error-Message": exc.message},
        )

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "swarm": await swarm.stats()}

    @app.get("/metrics")
    async def metrics_endpoint():
        gauges = {
            "thub_blobs": store.count_blobs(),
            "thub_disk_bytes": store.disk_usage(),
            "thub_disk_budget_bytes": settings.max_disk_bytes,
            "thub_inflight_downloads": mirror.inflight_count(),
        }
        return PlainTextResponse(metrics.render(gauges), media_type="text/plain; version=0.0.4")

    # ----------------------------------------------------------- model info

    async def _model_info(repo_id: str, revision: str):
        commit = await mirror.resolve_commit(repo_id, revision)
        info = store.get_commit_info(repo_id, commit)
        if info is None:  # ref known but commit body missing: refetch
            commit = await mirror.sync_ref(repo_id, revision)
            info = store.get_commit_info(repo_id, commit)
        info["sha"] = commit
        mirror.prefetch(repo_id, commit)
        headers = {"X-Mirror": "torrenthub"}
        source = store.get_source(repo_id, commit)
        if source:
            headers["X-Thub-Source"] = source
        return JSONResponse(info, headers=headers)

    @app.get("/api/models/{repo_id:path}/revision/{rev:path}")
    async def model_info_rev(repo_id: str, rev: str, request: Request):
        repo, revision = parse_revision(raw_path(request))
        return await _model_info(repo, revision)

    async def _tree(repo_id: str, revision: str, subpath: str, recursive: bool):
        """File listing, built from the stored upstream info. Newer huggingface_hub
        versions call this instead of reading `siblings` from the model info."""
        commit = await mirror.resolve_commit(repo_id, revision)
        info = store.get_commit_info(repo_id, commit) or {}
        prefix = subpath.strip("/")
        prefix = prefix + "/" if prefix else ""
        entries: dict[str, dict] = {}
        for s in info.get("siblings", []):
            p = s["rfilename"]
            if not p.startswith(prefix):
                continue
            rest = p[len(prefix):]
            if "/" in rest and not recursive:
                d = prefix + rest.split("/", 1)[0]
                entries.setdefault(d, {"type": "directory", "oid": "", "size": 0, "path": d})
                continue
            if recursive:  # include intermediate directories too
                parts = rest.split("/")[:-1]
                for i in range(len(parts)):
                    d = prefix + "/".join(parts[: i + 1])
                    entries.setdefault(d, {"type": "directory", "oid": "", "size": 0, "path": d})
            e = {"type": "file", "oid": s.get("blobId", ""), "size": s["size"], "path": p}
            if s.get("lfs"):
                e["lfs"] = {
                    "oid": s["lfs"]["sha256"],
                    "size": s["lfs"]["size"],
                    "pointerSize": s["lfs"].get("pointerSize", 134),
                }
            entries[p] = e
        return JSONResponse(
            sorted(entries.values(), key=lambda e: e["path"]), headers={"X-Mirror": "torrenthub"}
        )

    @app.get("/api/models/{repo_id:path}/tree/{rest:path}")
    async def tree(repo_id: str, rest: str, request: Request, recursive: bool = False):
        repo, revision, sub = parse_tree(raw_path(request))
        return await _tree(repo, revision, sub, recursive)

    @app.get("/api/models/{repo_id:path}")
    async def model_info(repo_id: str):
        return await _model_info(repo_id, "main")

    # ------------------------------------------------------------ participant events

    @app.post("/api/thub/events")
    async def post_event(request: Request):
        try:
            body = await request.json()
        except (ValueError, RecursionError):
            return JSONResponse({"error": "body is not JSON"}, status_code=400)
        ev = body.get("event") if isinstance(body, dict) and "event" in body else body
        res = admission.admit(ev)
        metrics.inc("thub_events_total", result=res.status)
        return JSONResponse(
            {"status": res.status, "reason": res.reason, "tier": res.tier, "id": ev.get("id") if isinstance(ev, dict) else None},
            status_code=res.http,
        )

    @app.get("/api/thub/events")
    async def get_events(request: Request):
        q = request.query_params
        def many(name):
            return [v for raw in q.getlist(name) for v in raw.split(",") if v]
        try:
            kinds = [int(k) for k in many("kinds")]
            limit = int(q.get("limit", "100"))
            since = int(q["since"]) if "since" in q else None
            until = int(q["until"]) if "until" in q else None
        except ValueError:
            return JSONResponse({"error": "kinds, limit, since and until must be integers"}, status_code=400)
        tags = {n: many(n) for n in ("e", "p", "x", "i") if many(n)}
        out = events.query(kinds or None, many("authors") or None, tags, since, until, limit,
                           include_quarantine=q.get("quarantine") == "1")
        return JSONResponse({"events": out}, headers={"X-Mirror": "torrenthub"})

    @app.get("/api/thub/requests")
    async def list_requests(task: str | None = None, state: str = "open", limit: int = 50):
        """Requests this hub holds, with where each stands by THIS hub's roots. Informational: an
        agent that wants an answer it can rely on pulls the events and judges them with its own."""
        g = admission.graph()
        now = time.time()
        out = []
        for r in g.requests_list():
            if task and r.task != task:
                continue
            st = g.request_status(r.id, now=now)
            if state == "open" and st.state not in ("open", "claimed", "answered"):
                continue
            out.append({"id": r.id, "issuer": r.issuer, "task": r.task, "inputs": list(r.inputs), "args": r.args, "want": r.want,
                        "deadline": r.deadline, "reward": r.reward, "created_at": r.created_at, "state": st.state,
                        "claimants": list(st.claimants), "results": st.results})
            if len(out) >= max(1, min(limit, 500)):
                break
        return {"requests": out}

    @app.post("/api/thub/publish")
    async def publish(request: Request):
        """Take in a repo a publisher signed (publish.py). Answers at once; the transfer of big
        files runs in the background and the publisher watches /api/thub/publish/<job>."""
        try:
            body = await request.json()
        except (ValueError, RecursionError):
            raise HubError(400, "BadRequest", "body is not JSON") from None
        try:
            out = await ingest.submit(body)
        except PublishError as e:
            metrics.inc("thub_publish_total", result="refused")
            raise HubError(e.status, e.code, e.message) from None
        return JSONResponse(out, status_code=200 if out.get("already") else 202)

    @app.get("/api/thub/git/{owner}/{name}/refs")
    async def git_refs(owner: str, name: str):
        """Where each branch of a git backed published repo is. A publisher asks before it makes a
        pack, so it sends only what the hub lacks."""
        repo = f"{owner}/{name}"
        if not REPO_NAME.fullmatch(repo):
            raise HubError(400, "BadRequest", "not a repo id")
        return {"repo": repo, "refs": ingest.git_refs(repo)}

    @app.get("/api/thub/publish/{job_id}")
    async def publish_status(job_id: str):
        st = ingest.status(job_id)
        if st is None:
            raise HubError(404, "EntryNotFound", "no such publication (jobs are forgotten when the hub restarts)")
        return st

    @app.get("/api/thub/lineage/{sha256}")
    async def lineage_of(sha256: str):
        """Where a blob came from and what came from it, as far as keys this gateway trusts for
        "derive" say, with each derivation's class under this gateway's trusted tools list."""
        g = admission.graph()
        lin = getattr(policy_rules, "lineage", None)
        tools = lin.trusted_tools if lin else ()
        mt = lin.min_trust if lin else 0.0

        def row(d):
            return {"event": d.id, "issuer": d.issuer, "tool": d.tool, "tool_x": d.tool_x, "class": g.derivation_class(d, tools),
                    "inputs": list(d.inputs), "outputs": [o[0] for o in d.outputs], "data_origin": d.data_origin,
                    "synthetic_depth": d.synthetic_depth, "licences": d.licences}

        return {"x": sha256, "status": g.blob_status(sha256), "synthetic_depth": g.synthetic_depth(sha256, mt),
                "descends_from_revoked": g.tainted_descendants(mt).get(sha256),
                "made_by": [row(d) for d in g.parents(sha256, mt)], "used_by": [row(d) for d in g.children(sha256, mt)]}

    @app.get("/api/thub/trust/{pubkey}")
    async def trust_of(pubkey: str, scope: str | None = None):
        """How much this gateway trusts a key, from its own roots, with the path that explains it."""
        g = admission.graph()
        t = g.trust(pubkey, scope)
        return {
            "key": pubkey, "scope": scope, "trust": t.value,
            "root": pubkey in g.roots, "member": g.reachable(pubkey),
            "path": [{"from": a, "to": b, "event": e} for a, b, e in t.path],
            "roots": sorted(g.roots),
        }

    @app.get("/api/thub/verdict/{sha256}")
    async def verdict(sha256: str, claim: str = "format_scan", n: int = 1, min_trust: float = 0.0):
        """What the attestations held here say about a blob, judged from this gateway's roots."""
        if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
            return JSONResponse({"error": "sha256 must be 64 lowercase hex characters"}, status_code=400)
        g = admission.graph()
        v = g.verdict(sha256, claim, max(1, min(n, 20)), min(max(min_trust, 0.0), 1.0))
        return {
            "sha256": sha256, "claim": claim, "status": v.status, "satisfied": v.ok, "keys": list(v.keys), "need": v.need,
            "detail": v.detail, "revoked": g.blob_status(sha256),
            "ok_attestors": g.attestors(sha256, claim, True), "failed_attestors": g.attestors(sha256, claim, False),
            "refuted_attestors": sorted(g.refuted_attestors()),
        }

    @app.get("/api/thub/manifests/{repo_id:path}")
    async def manifests(repo_id: str):
        """Signed manifests held for a repo. Anyone fetching them verifies the signatures."""
        return JSONResponse({"events": store.list_manifests(repo_id)}, headers={"X-Mirror": "torrenthub"})

    @app.get("/api/thub/policy/{repo_id:path}")
    async def policy(repo_id: str):
        """How this gateway decides what hashes to believe for a repo."""
        up = mirror.upstream
        mode = up.mode_for(repo_id) if hasattr(up, "mode_for") else (
            "anchor" if getattr(up, "is_anchor", False) else "upstream"
        )
        anchor = getattr(getattr(up, "anchor", None), "base_url", None) or (
            up.base_url if getattr(up, "is_anchor", False) else None
        )
        try:
            mirror.check_repo(repo_id)
            allowed = True
        except HubError:
            allowed = False
        return JSONResponse(
            {
                "repo": repo_id,
                "allowed": allowed,
                "hash_source": mode.split(":")[0],
                "signers": mode[len("signed:"):].split("+") if mode.startswith("signed:") else [],
                "anchor": anchor,
                "anchor_required": getattr(up, "anchor_required", None),
                "lockfile_mode": mirror.lock.mode if mirror.lock else None,
                "manifests_held": len(store.list_manifests(repo_id)),
                "file_rules": [
                    {"match": list(r.match), "action": r.action, "claim": r.claim, "independent": r.independent, "min_trust": r.min_trust, "max_age": r.max_age}
                    for r in policy_rules if fnmatch.fnmatchcase(repo_id, r.repo)
                ],
            },
            headers={"X-Mirror": "torrenthub"},
        )

    # ----------------------------------------------------------- swarm side

    @app.get("/api/swarm/{repo_id:path}/revision/{revision}")
    async def swarm_listing(repo_id: str, revision: str):
        commit = await mirror.resolve_commit(repo_id, revision)
        files = []
        for rec in store.list_files(repo_id, commit):
            b = store.get_blob(rec.blob_key)
            if not b or not b.infohash or store.is_blocked(rec.blob_key):
                continue
            seeds = mirror._web_seeds(rec.blob_key, repo_id, commit, rec.path)
            files.append(
                {
                    "path": rec.path,
                    "size": rec.size,
                    "sha256": rec.blob_key,
                    "infohash": b.infohash,
                    "available_here": store.blob_complete(rec.blob_key),
                    "torrent": f"{settings.public_url}/torrents/{rec.blob_key}.torrent",
                    "magnet": magnet(b.infohash, rec.blob_key, settings.trackers, seeds),
                }
            )
        return {"repo": repo_id, "commit": commit, "files": files}

    @app.get("/torrents/{key}.torrent")
    async def torrent_file(key: str):
        if not valid_key(key) or store.is_blocked(key) or not store.torrent_path(key).exists():
            raise HubError(404, "EntryNotFound", "no such torrent")
        p = store.torrent_path(key)
        return FileResponse(p, media_type="application/x-bittorrent")

    @app.api_route("/blobs/{key}", methods=["GET", "HEAD"])
    async def blob(key: str, request: Request):
        """Web seed endpoint (BEP-19). Serves only blobs we already hold."""
        if not valid_key(key) or store.is_blocked(key) or not store.blob_complete(key):
            raise HubError(404, "EntryNotFound", "blob not held here")
        b = store.get_blob(key)
        store.touch_blob(key)
        return file_response(
            store.blob_path(key),
            b.size,
            request.headers.get("range"),
            {},
            "application/octet-stream",
            request.method == "HEAD",
            served,
        )

    # ----------------------------------------------------------- downloads

    @app.api_route("/{repo_id:path}/resolve/{rest:path}", methods=["GET", "HEAD"])
    async def resolve(repo_id: str, rest: str, request: Request):
        repo_id, revision, filename = parse_resolve(raw_path(request))
        commit = await mirror.resolve_commit(repo_id, revision)
        rec = store.get_file(repo_id, commit, filename)
        if rec is None:
            raise HubError(404, "EntryNotFound", f"{filename} not found in {repo_id}@{revision}")
        dec = check_file(policy_rules, admission.graph(), repo_id, filename, rec.sha256)
        if not dec.allowed:
            metrics.inc("thub_policy_total", result="refused")
            raise HubError(403, dec.code, dec.reason)
        headers = {
            "X-Repo-Commit": commit,
            "ETag": f'"{rec.etag}"',
            "Content-Disposition": content_disposition(filename),
        }
        if dec.notes:
            headers["X-Thub-Warning"] = "; ".join(dec.notes)[:500]
            metrics.inc("thub_policy_total", result="warned")
        if dec.attested_by:
            headers["X-Thub-Attested-By"] = str(len(dec.attested_by))
            metrics.inc("thub_policy_total", result="attested")
        if rec.is_lfs:
            headers["X-Linked-Etag"] = f'"{rec.etag}"'
            headers["X-Linked-Size"] = str(rec.size)
        media = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if request.method == "HEAD":
            # Metadata is answered from the catalogue without touching blob bytes.
            return file_response(Path(), rec.size, None, headers, media, True)
        got = await mirror.acquire(repo_id, commit, rec)
        rng = request.headers.get("range")
        if isinstance(got, Inflight):
            metrics.inc("thub_resolve_total", result="miss")
            headers["X-Mirror-Cache"] = "miss"
            return inflight_response(got, rec.size, rng, headers, media, served)
        metrics.inc("thub_resolve_total", result="hit")
        headers["X-Mirror-Cache"] = "hit"
        return file_response(got, rec.size, rng, headers, media, False, served)

    return app
