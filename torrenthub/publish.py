"""Taking in a repo that a publisher made, which exists nowhere else.

The publisher signs a version 2 manifest (manifest.py) and sends it with the torrents of its big
files and the bytes of its small ones. This hub checks everything it can before taking a single
byte of the big files, then joins each file's swarm and lets the publisher connect to it. The
publisher dials out, so it can sit behind NAT with no open port. When the bytes are in, each is
checked against the sha256 the manifest signed, and only then does the repo appear.

Checked before any transfer: the signature, that the signer may publish this repo (it is a root,
or holds a delegation from one for `publish:<repo>`), that `seq` is higher than anything already
held for each branch name, that `valid_until` has not passed, that the commit is the name of the
file table, each torrent against the piece policy and the signed size and hash, and the signer's
quota. After the transfer: the sha256 of every file. A failed publication leaves nothing behind
that a reader can see: refs and commits are written in one step, last.

What this does not do: decide whether the content is any good (attestations and policy do that),
or stop a publisher from filling its own quota with junk.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings
from .manifest import Manifest, ManifestInvalid, content_commit, verify_manifest
from .metrics import Metrics
from .store import BlobRow, FileRec, Store
from .swarm import Swarm
from .torrent import TorrentRejected, bdecode, infohash_from_torrent, validate_torrent, with_webseeds
from .trust import Graph

log = logging.getLogger("torrenthub.publish")

MAX_PATH_LEN = 512
JOBS_KEPT = 200


class PublishError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@dataclass
class Job:
    id: str
    signer: str
    repo: str
    commit: str
    manifest_id: str
    state: str = "pulling"  # pulling | done | failed
    error: str = ""
    reserved: int = 0  # bytes counted against the quota while the transfer runs
    files: dict = field(default_factory=dict)  # sha256 -> {"size", "state", "bytes"}
    started: float = field(default_factory=time.time)
    finished: float = 0.0

    def public(self) -> dict:
        return {"job": self.id, "state": self.state, "error": self.error, "repo": self.repo, "commit": self.commit,
                "manifest": self.manifest_id, "files": self.files, "seconds": round((self.finished or time.time()) - self.started, 1)}


def _b64(s, what: str) -> bytes:
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError, TypeError) as e:
        raise PublishError(400, "BadRequest", f"{what} is not valid base64") from e


def safe_path(p) -> bool:
    return (isinstance(p, str) and 0 < len(p) <= MAX_PATH_LEN and "\0" not in p and not p.startswith("/")
            and "\\" not in p and all(part not in ("", ".", "..") for part in p.split("/")))


def info_from_rows(repo: str, commit: str, rows) -> dict:
    """The model-info document the hub serves for a published commit: every file has an LFS style
    sha256 entry, which is what makes it verifiable end to end."""
    return {"id": repo, "modelId": repo, "sha": commit, "private": False, "disabled": False,
            "siblings": [{"rfilename": p, "size": size, "lfs": {"size": size, "sha256": x, "pointerSize": 134}} for p, size, x, _ in rows]}


class Ingest:
    def __init__(self, settings: Settings, store: Store, swarm: Swarm, roots, graph_fn, metrics: Metrics):
        self.s, self.store, self.swarm, self.roots, self.graph_fn, self.metrics = settings, store, swarm, set(roots), graph_fn, metrics
        self.jobs: dict[str, Job] = {}
        self._tasks: set[asyncio.Task] = set()
        self._locks: dict[str, asyncio.Lock] = {}

    # ------------------------------------------------------------------ checks
    def _authorised(self, graph: Graph, signer: str, repo: str) -> None:
        if signer in graph.revoked_keys or graph.may_sign(self.roots, signer, f"publish:{repo}") is None:
            raise PublishError(403, "NotAuthorised", f"{signer[:12]} may not publish {repo} on this hub")

    def _check_manifest(self, body: dict, now: float) -> tuple[Manifest, bytes | None]:
        ev = body.get("manifest")
        if not isinstance(ev, dict):
            raise PublishError(400, "BadRequest", "manifest is missing")
        repo = next((t[1] for t in ev.get("tags", []) if isinstance(t, list) and len(t) >= 2 and t[0] == "repo"), None)
        if not isinstance(repo, str) or not 3 <= len(repo) <= 200 or repo.count("/") != 1 or not safe_path(repo):
            raise PublishError(400, "BadManifest", "the manifest names no valid repo")
        table = _b64(body["table"], "table") if body.get("table") else None
        try:
            m = verify_manifest(ev, {ev.get("pubkey")}, repo, table=table)
        except ManifestInvalid as e:
            raise PublishError(400, "BadManifest", str(e)) from e
        if m.seq < 1:
            raise PublishError(400, "BadManifest", "publishing needs a version 2 manifest (seq of 1 or more)")
        if m.needs_table:
            raise PublishError(400, "TableMissing", "the manifest keeps its file table in a blob; send it as `table`")
        if m.valid_until is not None and m.valid_until <= now:
            raise PublishError(400, "Expired", "valid_until has already passed")
        if m.created_at > now + 600:
            raise PublishError(400, "BadManifest", "created_at is in the future")
        return m, table

    def _check_rows(self, m: Manifest) -> None:
        rows = m.rows
        if not rows or len(rows) > self.s.publish_max_files:
            raise PublishError(400, "BadManifest", f"a publication holds 1 to {self.s.publish_max_files} files")
        paths = [r[0] for r in rows]
        if len(set(paths)) != len(paths):
            raise PublishError(400, "BadManifest", "duplicate file path")
        for r in rows:
            path, size, x, blob_id = r
            if not safe_path(path):
                raise PublishError(400, "BadManifest", f"unsafe path {path!r}")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0 or not isinstance(x, str) or len(x) != 64 or blob_id is not None:
                raise PublishError(400, "BadManifest", f"{path}: a published file needs a size and a sha256 and no git blob id")
        if m.commit != content_commit(rows):
            raise PublishError(400, "BadManifest", "the commit is not the name of this file table")

    def _check_seq(self, m: Manifest) -> bool:
        """True if this exact manifest is already held (so publishing it again is a no-op)."""
        held = [Manifest_seq(e) for e in self.store.list_manifests(m.repo)]
        if any(e[0] == m.id for e in held):
            return True
        for ref in m.refs:
            top = max((seq for _, seq, refs in held if ref in refs), default=0)
            if m.seq <= top:
                raise PublishError(409, "StaleSeq", f"{ref} already has a manifest with seq {top}; this one has {m.seq}")
        return False

    # ------------------------------------------------------------------ entry
    async def submit(self, body: dict, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        if self.s.publish_quota <= 0:
            raise PublishError(403, "PublishingDisabled", "this hub does not take published repos (THUB_PUBLISH_QUOTA is 0)")
        if not isinstance(body, dict):
            raise PublishError(400, "BadRequest", "body is not an object")
        m, table = self._check_manifest(body, now)
        self._authorised(self.graph_fn(), m.pubkey, m.repo)
        self._check_rows(m)
        async with self._lock(m.repo):
            return await self._start(m, table, body, now)

    def _lock(self, repo: str) -> asyncio.Lock:
        return self._locks.setdefault(repo, asyncio.Lock())

    async def _start(self, m: Manifest, table: bytes | None, body: dict, now: float) -> dict:
        if self._check_seq(m):
            return {"state": "done", "already": True, "repo": m.repo, "commit": m.commit, "swarm": {"port": self.s.listen_port}}
        if sum(1 for j in self.jobs.values() if j.signer == m.pubkey and j.state == "pulling") >= self.s.publish_max_jobs_per_key:
            raise PublishError(429, "TooManyPublications", "this key already has publications in progress")
        inline_raw = body.get("inline") or {}
        torrents_raw = body.get("torrents") or {}
        if not isinstance(inline_raw, dict) or not isinstance(torrents_raw, dict):
            raise PublishError(400, "BadRequest", "inline and torrents must be objects")
        inline = {x: _b64(v, f"inline {x[:12]}") for x, v in inline_raw.items()}
        if sum(len(v) for v in inline.values()) > self.s.publish_inline_max:
            raise PublishError(413, "TooLarge", f"inline files are limited to {self.s.publish_inline_max} bytes in all")
        torrents = {x: _b64(v, f"torrent {x[:12]}") for x, v in torrents_raw.items()}

        need_swarm: dict[str, tuple[bytes, int]] = {}  # sha256 -> (torrent bytes, size)
        have_inline: dict[str, bytes] = {}
        new_bytes = 0
        for path, size, x, _ in m.rows:
            if self.store.blob_complete(x) and not self.store.is_blocked(x):
                continue
            if self.store.is_blocked(x):
                raise PublishError(451, "BlobBlocked", f"{path} is content this hub has removed")
            if x in inline:
                data = inline[x]
                if len(data) != size or hashlib.sha256(data).hexdigest() != x:
                    raise PublishError(400, "ContentMismatch", f"{path}: the bytes sent are not the signed size and sha256")
                have_inline[x] = data
            elif x in torrents:
                if not self.swarm.enabled:
                    raise PublishError(400, "NoSwarm", f"{path} needs a swarm transfer and this hub has no swarm; send it inline if small")
                try:
                    validate_torrent(torrents[x], x, size)
                except TorrentRejected as e:
                    raise PublishError(400, "BadTorrent", f"{path}: {e}") from e
                need_swarm[x] = (torrents[x], size)
            else:
                raise PublishError(400, "MissingContent", f"{path}: send its bytes inline or its torrent")
            new_bytes += size
        if table is not None and m.files_x and not self.store.blob_complete(m.files_x):
            new_bytes += len(table)

        reserved = sum(j.reserved for j in self.jobs.values() if j.signer == m.pubkey and j.state == "pulling")
        used = self.store.charged_bytes(m.pubkey)
        if used + reserved + new_bytes > self.s.publish_quota:
            raise PublishError(413, "QuotaExceeded", f"{used + reserved:,} bytes held or in progress and {new_bytes:,} more would pass the quota of {self.s.publish_quota:,}")

        job = Job(uuid.uuid4().hex[:16], m.pubkey, m.repo, m.commit, m.id, reserved=new_bytes)
        for path, size, x, _ in m.rows:
            job.files[x] = {"path": path, "size": size, "state": "held" if self.store.blob_complete(x) else "waiting", "bytes": 0}
        self.jobs[job.id] = job
        for old in sorted(self.jobs.values(), key=lambda j: j.started)[:-JOBS_KEPT]:
            if old.state != "pulling":
                self.jobs.pop(old.id, None)
        # Small files are taken at once. They can be wrong too, but they were checked above.
        for x, data in have_inline.items():
            self._put_small(x, data)
            job.files[x]["state"] = "stored"
            job.files[x]["bytes"] = len(data)
        for x, (tbytes, size) in need_swarm.items():
            job.files[x]["state"] = "pulling"
        if table is not None and m.files_x and not self.store.blob_complete(m.files_x):
            self._put_small(m.files_x, table)
        task = asyncio.create_task(self._run(job, m, table, need_swarm, have_inline))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        self.metrics.inc("thub_publish_total", result="started")
        return {"job": job.id, "state": job.state, "repo": m.repo, "commit": m.commit, "swarm": {"port": self.s.listen_port},
                "pulling": sorted(need_swarm)}

    # ------------------------------------------------------------------ work
    def _put_small(self, x: str, data: bytes) -> None:
        path = self.store.blob_path(x)
        tmp = self.store.tmp_path(x)
        tmp.write_bytes(data)
        tmp.replace(path)
        self.store.put_blob(BlobRow(x, len(data), x, "complete", None, None, time.time()))

    async def _run(self, job: Job, m: Manifest, table: bytes | None, need: dict, inline: dict) -> None:
        try:
            await asyncio.wait_for(self._pull(job, need), timeout=self.s.publish_timeout)
            self._publish(job, m, table, need, inline)
            job.state = "done"
            self.metrics.inc("thub_publish_total", result="done")
            log.info("published %s@%s for %s: %d files", m.repo, m.commit[:12], m.pubkey[:12], len(m.rows))
        except asyncio.TimeoutError:
            self._fail(job, need, f"not finished within {self.s.publish_timeout:.0f}s")
        except PublishError as e:
            self._fail(job, need, e.message)
        except Exception as e:  # noqa: BLE001
            log.exception("publication %s failed", job.id)
            self._fail(job, need, f"{type(e).__name__}: {e}")
        finally:
            job.reserved = 0
            job.finished = time.time()

    def _fail(self, job: Job, need: dict, why: str) -> None:
        job.state, job.error = "failed", why
        self.metrics.inc("thub_publish_total", result="failed")
        for x in need:
            if not self.store.blob_complete(x):
                self.store.blob_path(x).unlink(missing_ok=True)
                self.store.swarm_torrent_path(x).unlink(missing_ok=True)
        log.warning("publication of %s@%s failed: %s", job.repo, job.commit[:12], why)

    async def _pull(self, job: Job, need: dict) -> None:
        if not need:
            return
        downloads = {}
        for x, (tbytes, size) in need.items():
            working = self.store.swarm_torrent_path(x)
            working.write_bytes(tbytes)
            dl = await self.swarm.start(working, self.store.blob_path(x).parent)
            if dl is None:
                raise PublishError(500, "NoSwarm", "the swarm engine would not start the transfer")
            downloads[x] = dl
        last_move, seen = time.monotonic(), -1
        pending = set(downloads)
        while pending:
            for x in list(pending):
                dl = downloads[x]
                job.files[x]["bytes"] = int(dl.snapshot().get("done", dl.prefix_bytes()))
                if dl.complete():
                    pending.discard(x)
                    job.files[x]["state"] = "checking"
                    await self._finish_one(job, x, need[x])
            progress = sum(job.files[x]["bytes"] for x in downloads)
            if progress != seen:
                seen, last_move = progress, time.monotonic()
            elif time.monotonic() - last_move > self.s.publish_stall:
                for x in pending:
                    downloads[x].cancel()
                raise PublishError(408, "Stalled", f"nothing arrived for {self.s.publish_stall:.0f}s; is the publisher connected to this hub's swarm port?")
            await asyncio.sleep(0.2)

    async def _finish_one(self, job: Job, x: str, item) -> None:
        tbytes, size = item
        path = self.store.blob_path(x)
        digest = await asyncio.to_thread(_sha256_file, path)
        if digest != x or path.stat().st_size != size:
            path.unlink(missing_ok=True)
            self.metrics.inc("thub_integrity_failures_total", source="publish")
            raise PublishError(400, "ContentMismatch", f"{job.files[x]['path']}: what arrived is not the signed sha256")
        meta = with_webseeds(tbytes, [f"{self.s.public_url}/blobs/{x}"])
        self.store.torrent_path(x).write_bytes(meta)
        self.store.put_blob(BlobRow(x, size, x, "complete", infohash_from_torrent(tbytes), bdecode(tbytes)[b"info"][b"piece length"], time.time()))
        job.files[x]["state"] = "stored"
        job.files[x]["bytes"] = size

    def _publish(self, job: Job, m: Manifest, table: bytes | None, need: dict, inline: dict) -> None:
        """Make the repo visible. Charges, then commit and refs in one transaction each, then the
        manifest, so a reader that sees a ref finds every blob behind it."""
        for _path, size, x, _ in m.rows:
            self.store.charge(m.pubkey, x, size)
        if table is not None and m.files_x:
            self.store.charge(m.pubkey, m.files_x, len(table))
        info = info_from_rows(m.repo, m.commit, m.rows)
        files = [FileRec(p, size, x, x, True) for p, size, x, _ in m.rows]
        self.store.mark_published(m.repo, m.pubkey)
        for ref in m.refs:
            self.store.put_commit(m.repo, ref, m.commit, info, files)
        self.store.set_source(m.repo, m.commit, "signed")
        self.store.add_manifest(m.event)

    def status(self, job_id: str) -> dict | None:
        j = self.jobs.get(job_id)
        return j.public() if j else None

    async def aclose(self) -> None:
        for t in list(self._tasks):
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


def Manifest_seq(ev: dict) -> tuple[str, int, tuple]:
    """(id, seq, refs) of a stored manifest event, without checking its signature again (the store
    only holds verified events). Version 1 manifests count as seq 0."""
    import json

    try:
        body = json.loads(ev["content"])
        return ev["id"], int(body.get("seq", 0)) if body.get("v") == 2 else 0, tuple(body.get("refs", ()))
    except (KeyError, ValueError, TypeError):
        return ev.get("id", ""), 0, ()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()
