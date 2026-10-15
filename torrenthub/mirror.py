"""Mirroring logic: sync repo metadata, fetch blobs, build torrents, enforce policy.

Cache misses are streamed. A download runs as its own task, independent of any client,
and clients read the growing .part file while it is written. Two safeguards:

* Holdback. The last `stream_holdback` bytes are not released to readers until the whole
  file has been hashed and checked. If the check fails, readers are aborted before they
  receive the tail, so no client ever gets a complete corrupt file from the mirror.
* Single flight. Concurrent requests for the same blob attach to one download.

Where the bytes come from, in order:
  1. The swarm, if this node has the blob's torrent (kept after eviction) or, with
     `swarm_first`, can get it from the upstream hub. libtorrent checks every piece against
     the torrent as it arrives, so the verified prefix can be streamed to the client at once.
  2. HTTP from the upstream, if the swarm is off, has no torrent, or produces no bytes within
     `swarm_stall` seconds.
Either way the whole file's sha256 is checked against the catalogue before it is published.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import os
import re
import time
from pathlib import Path

from .config import Settings
from .metrics import Metrics
from .store import BlobRow, FileRec, Store
from .swarm import Swarm
from .torrent import (
    PIECE_POLICY_VERSION,
    PieceHasher,
    TorrentRejected,
    bdecode,
    build_torrent,
    choose_piece_length,
    infohash_from_torrent,
    strip_webseeds,
    validate_torrent,
)
from .lock import Lockfile
from .upstream import HubError, Upstream, UpstreamSet, UpstreamUnavailable

SHA40 = re.compile(r"^[0-9a-f]{40}$")


def files_from_info(info: dict) -> list[FileRec]:
    """Turn an upstream model-info document (fetched with blobs=true) into file records."""
    out = []
    for s in info.get("siblings", []):
        lfs = s.get("lfs")
        if lfs:
            out.append(FileRec(s["rfilename"], int(lfs["size"]), lfs["sha256"], lfs["sha256"], True))
        else:
            blob_id = s.get("blobId")
            if not blob_id:
                raise HubError(502, "UpstreamUnavailable", f"no blobId for {s['rfilename']}")
            out.append(FileRec(s["rfilename"], int(s["size"]), blob_id, f"git-{blob_id}", False))
    return out


class _Sink:
    """Writes a download to disk while computing every hash we need in one pass."""

    def __init__(self, tmp: Path, rec: FileRec, piece_length: int | None):
        self.f = open(tmp, "wb")
        self.size = 0
        self.sha256 = hashlib.sha256()
        self.git_sha1 = None if rec.is_lfs else hashlib.sha1(b"blob %d\0" % rec.size)
        self.pieces = PieceHasher(piece_length) if piece_length else None

    def write(self, chunk: bytes) -> None:
        self.f.write(chunk)
        self.f.flush()  # readers follow the file while it grows
        self.size += len(chunk)
        self.sha256.update(chunk)
        if self.git_sha1 is not None:
            self.git_sha1.update(chunk)
        if self.pieces is not None:
            self.pieces.update(chunk)

    def close(self) -> None:
        self.f.close()


class Inflight:
    """A download in progress that any number of clients can read from."""

    def __init__(self, rec: FileRec, tmp: Path, final: Path, holdback: int):
        self.rec = rec
        self.tmp = tmp
        self.final = final
        self.holdback = holdback
        self.written = 0
        self.verified = False
        self.done = False
        self.error: Exception | None = None
        self.task: asyncio.Task | None = None
        # (piece length, concatenated SHA-1 hashes) while the source is a swarm download. Readers
        # check every piece they read back from disk against these before sending it.
        self.piece_check: tuple[int, bytes] | None = None
        self._cond = asyncio.Condition()

    def releasable(self) -> int:
        if self.verified:
            return self.rec.size
        return max(0, self.written - self.holdback)

    async def progress(self, written: int) -> None:
        async with self._cond:
            self.written = written
            self._cond.notify_all()

    async def finish(self, error: Exception | None = None) -> None:
        async with self._cond:
            self.done = True
            self.error = error
            self.verified = error is None
            self._cond.notify_all()

    async def wait_for(self, pos: int) -> int:
        """Wait until byte `pos` may be released. Returns the releasable byte count."""
        async with self._cond:
            await self._cond.wait_for(lambda: self.releasable() > pos or self.done)
        if self.error:
            raise self.error
        return self.releasable()

    async def wait_done(self) -> None:
        async with self._cond:
            await self._cond.wait_for(lambda: self.done)
        if self.error:
            raise self.error

    def open_for_read(self):
        try:
            return open(self.tmp, "rb")
        except FileNotFoundError:  # already renamed into place
            return open(self.final, "rb")


class Mirror:
    def __init__(
        self,
        settings: Settings,
        store: Store,
        upstream: Upstream | UpstreamSet,
        swarm: Swarm,
        metrics: Metrics | None = None,
    ):
        self.s = settings
        self.store = store
        self.upstream = upstream
        self.swarm = swarm
        self.metrics = metrics or Metrics()
        if hasattr(upstream, "metrics"):
            upstream.metrics = self.metrics
        if hasattr(upstream, "on_manifest"):
            upstream.on_manifest = store.add_manifest  # keep verified manifests so we can serve them on
        self.lock = Lockfile(settings.lockfile, settings.lock_mode) if settings.lockfile else None
        self._locks: dict[str, asyncio.Lock] = {}
        self._inflight: dict[str, Inflight] = {}
        self._tasks: set[asyncio.Task] = set()
        self._prefetching: set[tuple[str, str]] = set()
        # Blobs where the swarm delivered bad content. Use HTTP for them until restart.
        self._no_swarm: set[str] = set()
        self._prefetch_sem = asyncio.Semaphore(settings.prefetch_concurrency)

    def _lock(self, key: str) -> asyncio.Lock:
        return self._locks.setdefault(key, asyncio.Lock())

    def inflight_count(self) -> int:
        return len(self._inflight)

    # ------------------------------------------------------------ policy

    def check_repo(self, repo_id: str) -> None:
        if any(fnmatch.fnmatchcase(repo_id, p) for p in self.s.deny):
            raise HubError(451, "RepoBlocked", f"{repo_id} is blocked on this mirror")
        if not any(fnmatch.fnmatchcase(repo_id, p) for p in self.s.allow):
            raise HubError(404, "RepoNotFound", f"{repo_id} is not available on this mirror")

    # ------------------------------------------------------------ metadata

    async def sync_ref(self, repo_id: str, revision: str) -> str:
        self.check_repo(repo_id)
        if hasattr(self.upstream, "model_info_ex"):
            info, source = await self.upstream.model_info_ex(repo_id, revision)
        else:
            info = await self.upstream.model_info(repo_id, revision)
            source = "anchor" if getattr(self.upstream, "is_anchor", False) else "upstream"
        sha = info["sha"]
        if self.lock is not None:
            try:
                # A table that no anchor vouched for is pinned on first sight.
                if self.lock.check(repo_id, info, record_unknown=(source == "hub")):
                    self.metrics.inc("thub_lock_recorded_total")
            except HubError:
                self.metrics.inc("thub_lock_refused_total")
                raise
        files = files_from_info(info)
        self.store.put_commit(repo_id, revision, sha, info, files)
        self.store.set_source(repo_id, sha, source)
        return sha

    async def resolve_commit(self, repo_id: str, revision: str) -> str:
        """Map a branch, tag or commit to a commit sha, preferring local knowledge.

        If upstream is down and we already know this ref, serve the stale answer. That
        is the point of a mirror.
        """
        self.check_repo(repo_id)
        if SHA40.match(revision) and self.store.has_commit(repo_id, revision):
            return revision
        ref = self.store.get_ref(repo_id, revision)
        if ref and time.time() - ref[1] < self.s.ref_ttl:
            return ref[0]
        if not self.s.lazy_mirror and ref is None:
            raise HubError(404, "RepoNotFound", f"{repo_id} is not mirrored here")
        try:
            return await self.sync_ref(repo_id, revision)
        except UpstreamUnavailable:
            if ref:
                return ref[0]
            raise

    # ------------------------------------------------------------ blobs

    def _web_seeds(self, key: str, repo_id: str, commit: str, path: str) -> list[str]:
        seeds = [f"{self.s.public_url}/blobs/{key}"]
        if self.s.webseed_upstream:
            seeds.append(self.upstream.resolve_url(repo_id, commit, path))
        return seeds

    async def acquire(self, repo_id: str, commit: str, rec: FileRec) -> Path | Inflight:
        """Return the finished blob path, or an Inflight download clients can stream from."""
        key = rec.blob_key
        if self.store.is_blocked(key):
            raise HubError(451, "BlobBlocked", "this content has been removed from the mirror")
        path = self.store.blob_path(key)
        if self.store.blob_complete(key):
            self.store.touch_blob(key)
            return path
        if key in self._inflight:
            return self._inflight[key]
        async with self._lock(key):
            if self.store.blob_complete(key):
                self.store.touch_blob(key)
                return path
            if key in self._inflight:
                return self._inflight[key]
            inf = Inflight(rec, self.store.tmp_path(key), path, self.s.stream_holdback)
            self._inflight[key] = inf
            inf.task = asyncio.create_task(self._run_blob(repo_id, commit, rec, path, inf))
            return inf

    async def ensure_blob(self, repo_id: str, commit: str, rec: FileRec) -> Path:
        """Like acquire, but wait for completion. Used by the CLI and prefetch."""
        got = await self.acquire(repo_id, commit, rec)
        if isinstance(got, Inflight):
            await got.wait_done()
            return self.store.blob_path(rec.blob_key)
        return got

    async def _run_blob(self, repo_id: str, commit: str, rec: FileRec, path: Path, inf: Inflight) -> None:
        key = rec.blob_key
        error: Exception | None = None
        try:
            if not await self._try_swarm(rec, path, inf):
                await self._http_download(repo_id, commit, rec, path, inf)
            await self.gc(protect={key})
        except asyncio.CancelledError:
            error = UpstreamUnavailable("download cancelled")
            raise
        except Exception as e:
            error = e
        finally:
            if error is not None:
                self.store.tmp_path(key).unlink(missing_ok=True)
            if not inf.done:
                await inf.finish(error or UpstreamUnavailable("download ended unexpectedly"))
            self._inflight.pop(key, None)

    # ------------------------------------------------------------ swarm source

    async def _torrent_for(self, rec: FileRec) -> bytes | None:
        """The validated torrent for a blob: kept locally, or fetched from the upstream hub."""
        key = rec.blob_key
        tp = self.store.torrent_path(key)
        if tp.exists():
            data = tp.read_bytes()
            try:
                validate_torrent(data, key, rec.size)
                return data
            except TorrentRejected:
                tp.unlink(missing_ok=True)
        if not self.s.swarm_first:
            return None
        rejected = 0

        def accept(candidate: bytes) -> bool:
            nonlocal rejected
            try:
                validate_torrent(candidate, key, rec.size)
                return True
            except TorrentRejected:
                rejected += 1
                self.metrics.inc("thub_torrent_fetch_total", result="rejected")
                return False

        data = await self.upstream.fetch_torrent(key, accept)
        if data is None:
            if not rejected:
                self.metrics.inc("thub_torrent_fetch_total", result="none")
            return None
        self.metrics.inc("thub_torrent_fetch_total", result="ok")
        tp.write_bytes(data)
        return data

    async def _try_swarm(self, rec: FileRec, path: Path, inf: Inflight) -> bool:
        """Download from peers, streaming the verified prefix. True if the blob is now published.
        False means nothing usable arrived and the caller should use HTTP."""
        key = rec.blob_key
        if not self.swarm.enabled or key in self._no_swarm:
            return False
        if not rec.is_lfs or rec.size < self.s.torrent_min_size:
            return False
        data = await self._torrent_for(rec)
        if data is None:
            return False

        working = self.store.swarm_torrent_path(key)
        working.write_bytes(data if self.s.use_webseeds else strip_webseeds(data))
        try:
            dl = await self.swarm.start(working, path.parent)
            if dl is None:
                return False
            inf.tmp = path  # readers follow the file libtorrent is writing
            info = bdecode(data)[b"info"]
            inf.piece_check = (info[b"piece length"], info[b"pieces"])
            seen = 0
            last_move = time.monotonic()
            try:
                while not dl.complete():
                    pos = dl.prefix_bytes()
                    now = time.monotonic()
                    if pos != seen:
                        seen, last_move = pos, now
                        await inf.progress(pos)
                    elif seen == 0 and now - last_move > self.s.swarm_stall:
                        # Nobody sent anything and no client has received anything: safe to switch.
                        self.metrics.inc("thub_swarm_fallback_total")
                        dl.cancel()
                        path.unlink(missing_ok=True)
                        inf.tmp = self.store.tmp_path(key)
                        inf.piece_check = None
                        return False
                    elif seen > 0 and now - last_move > self.s.swarm_timeout:
                        raise UpstreamUnavailable("swarm stalled")
                    await asyncio.sleep(0.1)
            except BaseException:
                dl.cancel()
                path.unlink(missing_ok=True)
                raise
        finally:
            working.unlink(missing_ok=True)

        sha = await asyncio.to_thread(_sha256_file, path)
        if sha != key:
            self.metrics.inc("thub_integrity_failures_total", source="swarm")
            dl.cancel()
            path.unlink(missing_ok=True)
            self.store.torrent_path(key).unlink(missing_ok=True)
            self._no_swarm.add(key)
            raise UpstreamUnavailable(f"integrity check failed for {rec.path}: swarm content sha256 mismatch")
        self.metrics.inc("thub_bytes_fetched_total", rec.size, source="swarm")
        self.store.put_blob(
            BlobRow(key, rec.size, sha, "complete", infohash_from_torrent(data), choose_piece_length(rec.size), time.time())
        )
        await inf.finish()  # releases the held-back tail; libtorrent keeps seeding the file
        return True

    # ------------------------------------------------------------ HTTP source

    async def _http_download(self, repo_id: str, commit: str, rec: FileRec, path: Path, inf: Inflight) -> None:
        key = rec.blob_key
        make_torrent = rec.is_lfs and rec.size >= self.s.torrent_min_size
        piece_length = choose_piece_length(rec.size) if make_torrent else None
        tmp = self.store.tmp_path(key)
        inf.tmp = tmp
        sink = _Sink(tmp, rec, piece_length)
        try:
            try:
                async with self.upstream.stream_file(repo_id, commit, rec.path) as r:
                    if r.status_code == 404:
                        raise HubError(404, "EntryNotFound", f"{rec.path} not found upstream")
                    if r.status_code != 200:
                        raise UpstreamUnavailable(f"upstream returned {r.status_code} for {rec.path}")
                    async for chunk in r.aiter_bytes(1 << 20):
                        await asyncio.to_thread(sink.write, chunk)
                        self.metrics.inc("thub_bytes_fetched_total", len(chunk), source="upstream")
                        await inf.progress(sink.size)
            except HubError:
                raise
            except Exception as e:  # network errors mid-stream
                raise UpstreamUnavailable(f"{type(e).__name__}: {e}") from e
        finally:
            sink.close()

        # Integrity: never publish bytes that do not match what upstream advertised.
        problem = None
        if sink.size != rec.size:
            problem = f"size {sink.size} != {rec.size}"
        elif rec.is_lfs and sink.sha256.hexdigest() != key:
            problem = "sha256 mismatch"
        elif not rec.is_lfs and sink.git_sha1.hexdigest() != rec.git_blob_id:
            problem = "git blob id mismatch"
        if problem:
            self.metrics.inc("thub_integrity_failures_total", source="upstream")
            raise UpstreamUnavailable(f"integrity check failed for {rec.path}: {problem}")

        os.replace(tmp, path)
        infohash = None
        if make_torrent:
            data, infohash = build_torrent(
                name=key,
                length=rec.size,
                piece_length=piece_length,
                pieces=sink.pieces.finish(),
                trackers=self.s.trackers,
                webseeds=self._web_seeds(key, repo_id, commit, rec.path),
                comment=f"torrenthub piece policy v{PIECE_POLICY_VERSION}",
            )
            self.store.torrent_path(key).write_bytes(data)
        self.store.put_blob(
            BlobRow(key, rec.size, sink.sha256.hexdigest(), "complete", infohash, piece_length, time.time())
        )
        await inf.finish()  # releases the held-back tail to readers
        if infohash:
            await self.swarm.seed(self.store.torrent_path(key), path.parent)

    # ------------------------------------------------------------ bulk

    async def mirror_repo(self, repo_id: str, revision: str = "main") -> tuple[str, list[FileRec]]:
        commit = await self.sync_ref(repo_id, revision)
        files = self.store.list_files(repo_id, commit)
        for rec in files:
            await self.ensure_blob(repo_id, commit, rec)
        return commit, files

    def prefetch(self, repo_id: str, commit: str) -> None:
        """Fetch every file of a commit in the background (opt-in)."""
        k = (repo_id, commit)
        if not self.s.prefetch or k in self._prefetching:
            return
        self._prefetching.add(k)

        async def run() -> None:
            try:
                for rec in self.store.list_files(repo_id, commit):
                    async with self._prefetch_sem:
                        try:
                            await self.ensure_blob(repo_id, commit, rec)
                        except Exception:
                            continue  # one bad file must not stop the rest
            finally:
                self._prefetching.discard(k)

        t = asyncio.create_task(run())
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------ eviction and takedown

    async def evict(self, key: str) -> bool:
        """Drop the bytes but keep the torrent, so the swarm can refill them later."""
        b = self.store.get_blob(key)
        if not b or not b.infohash or key in self._inflight:
            return False
        await self.swarm.forget(self.store.torrent_path(key))
        self.store.blob_path(key).unlink(missing_ok=True)
        self.store.set_blob_state(key, "evicted")
        self.metrics.inc("thub_evictions_total")
        return True

    async def gc(self, protect: set[str] | frozenset[str] = frozenset()) -> list[str]:
        """Evict least recently used refillable blobs until under the disk budget."""
        budget = self.s.max_disk_bytes
        if budget <= 0:
            return []
        used = self.store.disk_usage()
        evicted: list[str] = []
        for b in self.store.lru_candidates():
            if used <= budget:
                break
            if b.key in protect:
                continue
            if await self.evict(b.key):
                used -= b.size
                evicted.append(b.key)
        return evicted

    async def block(self, key: str, reason: str = "takedown") -> None:
        """Remove a blob everywhere we control: bytes, torrent, swarm entry. Refuse future serving."""
        inf = self._inflight.get(key)
        if inf and inf.task:
            inf.task.cancel()
        tp = self.store.torrent_path(key)
        if tp.exists():
            await self.swarm.forget(tp)
            tp.unlink()
        self.store.blob_path(key).unlink(missing_ok=True)
        self.store.add_block(key, reason)
        if self.store.get_blob(key):
            self.store.set_blob_state(key, "blocked")

    async def aclose(self) -> None:
        for t in list(self._tasks) + [i.task for i in self._inflight.values() if i.task]:
            t.cancel()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()
