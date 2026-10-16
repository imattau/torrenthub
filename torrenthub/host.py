"""Serving a repo from your own machine (HOSTING.md, stage H2).

`torrenthub host` runs an ordinary hub whose one repo is not mirrored or published to it: it is
read from a git repository on this machine. For each branch it watches, the host

  * derives the file table of the branch's commit from the git objects (gitrepo.derive),
  * finds each big file's bytes where they already are (the working tree, git-lfs's cache, a folder
    named on the command line) and serves and seeds them from there: the store holds a link to the
    file, not a copy,
  * signs a version 3 manifest with the owner's key, and
  * only then makes the commit visible, so a reader that sees a branch finds every file behind it.

Everything else is the hub it already was: the Hugging Face API, `/blobs`, torrents, the swarm.
Consumers pin the owner's key as for any signed repo; they do not need to trust this machine.

In place means the owner can break it. A big file edited after it was hashed no longer matches its
pointer. Each pass checks every served file's size and modification time and, on a change, hashes
it again; if it no longer matches, it stops serving that file (and says so) instead of serving bytes
that every reader would reject. Between two passes (`poll`) a changed file can still be offered.

A branch that is deleted, or whose files cannot be found, keeps serving the last good commit.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import tempfile
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import gitrepo
from .config import Settings
from .manifest import MAX_HISTORY_BYTES, build_git_manifest, table_bytes
from .publish import Manifest_seq, Manifest_version, info_from_rows
from .store import BlobRow, FileRec, Store
from .torrent import PieceHasher, bdecode, build_torrent, choose_piece_length, infohash_from_torrent, sanitize_torrent

log = logging.getLogger("torrenthub.host")


class HostError(Exception):
    pass


@dataclass
class BranchStatus:
    commit: str | None = None
    seq: int = 0
    error: str = ""
    checked: float = 0.0


@dataclass
class Host:
    settings: Settings
    store: Store
    swarm: object
    repo: str
    git_dir: Path
    secret: bytes
    branches: tuple = ("main",)
    extra_dirs: tuple = ()
    valid_for: float | None = None  # seconds a manifest stays believable; the host signs again at half
    poll: float = 10.0
    status: dict = field(default_factory=dict)
    _derived: dict = field(default_factory=dict)  # commit -> Derived, so an idle pass reads no git objects
    _where: dict = field(default_factory=dict)  # oid -> a path in the tree that names it (for finding the file)
    _history: dict = field(default_factory=dict)  # commit -> the history pack entry in its manifest

    def __post_init__(self):
        self.git_dir = Path(self.git_dir)
        self._state_path = self.store.root / "host-state.json"
        try:
            self._files = json.loads(self._state_path.read_text())
        except (OSError, ValueError):
            self._files = {}
        for b in self.branches:
            if not gitrepo.valid_ref(b):
                raise ValueError(f"{b!r} is not a usable branch name")

    # ------------------------------------------------------------------ one pass
    async def refresh(self) -> list[dict]:
        """Look at every watched branch once. Returns what happened to each."""
        heads: dict[str, str] = {}
        out = []
        for b in self.branches:
            st = self.status.setdefault(b, BranchStatus())
            st.checked = time.time()
            try:
                heads[b] = await asyncio.to_thread(gitrepo.local_commit, self.git_dir, f"refs/heads/{b}")
                st.error = ""
            except gitrepo.GitError as e:
                st.error = f"branch {b} not found in {self.git_dir}" if "not a commit" in str(e) or "Needed a single revision" in str(e) else str(e)
                out.append({"branch": b, "action": "error", "error": st.error})
                log.warning("%s", st.error)
        by_head: dict[str, list[str]] = {}
        for b, h in heads.items():
            by_head.setdefault(h, []).append(b)
        for head, names in by_head.items():
            try:
                out += await self._serve_commit(head, names)
            except (HostError, gitrepo.GitError) as e:
                for b in names:
                    self.status[b].error = str(e)
                    out.append({"branch": b, "action": "error", "error": str(e), "commit": head})
                log.warning("%s: not serving %s: %s", self.repo, head[:12], e)
        return out

    async def _serve_commit(self, head: str, names: list[str]) -> list[dict]:
        cur = {b: self._current(b) for b in names}
        due = {b: self._resign_due(cur[b]) for b in names}
        d = self._derived.get(head)
        if d is None:
            s = self.settings
            d = await asyncio.to_thread(gitrepo.derive, self.git_dir, head, blob_max=s.publish_git_blob_max,
                                        small_total=s.publish_git_small_total, max_files=s.publish_max_files, sandbox=False)
            self._derived.clear()  # only the heads in use are worth keeping
            self._derived[head] = d
        await self._ensure_files(d)
        await asyncio.to_thread(self._mirror_git, head, names)
        history = await self._history_entry(head)
        todo = [b for b in names if cur[b] is None or cur[b]["commit"] != head or due[b]]
        results = []
        if todo:
            seq = await asyncio.to_thread(self._sign_and_store, head, d, todo, history)
            for b in todo:
                self.status[b].commit, self.status[b].seq = head, seq
                results.append({"branch": b, "action": "signed", "commit": head, "seq": seq})
                log.info("%s: %s is now %s (seq %d)", self.repo, b, head[:12], seq)
        for b in names:
            if b not in todo:
                self.status[b].commit, self.status[b].seq = head, cur[b]["seq"]
                results.append({"branch": b, "action": "unchanged", "commit": head, "seq": cur[b]["seq"]})
        return results

    # ------------------------------------------------------------------ manifests
    def _manifests(self) -> list[dict]:
        out = []
        for ev in self.store.list_manifests(self.repo):
            try:
                body = json.loads(ev["content"])
            except (KeyError, ValueError):
                continue
            if body.get("v") == 3:
                out.append({"id": ev["id"], "seq": int(body["seq"]), "refs": tuple(body["refs"]), "commit": body["commit"],
                            "created_at": int(ev["created_at"]), "valid_until": body.get("valid_until")})
        return out

    def _current(self, branch: str) -> dict | None:
        mine = [m for m in self._manifests() if branch in m["refs"]]
        return max(mine, key=lambda m: m["seq"]) if mine else None

    def _resign_due(self, m: dict | None, now: float | None = None) -> bool:
        if not m or m["valid_until"] is None:
            return False
        now = time.time() if now is None else now
        return now >= m["created_at"] + 0.5 * (m["valid_until"] - m["created_at"])

    def _next_seq(self, branches) -> int:
        top = 0
        for ev in self.store.list_manifests(self.repo):
            _id, seq, refs = Manifest_seq(ev)
            if any(b in refs for b in branches):
                top = max(top, seq)
        return top + 1

    def _sign_and_store(self, head: str, d: gitrepo.Derived, branches: list[str], history: dict | None = None) -> int:
        """Sign one manifest for `branches` (all at `head`) and make the commit visible. Blocking."""
        for ev in self.store.list_manifests(self.repo):
            if Manifest_version(ev) != 3:
                raise HostError(f"{self.repo} already holds manifests that are not git backed; host it under another name or use a fresh data directory")
        prev = [self.store.get_ref(self.repo, b) for b in branches]
        rewritten = any(p is not None and p[0] != head and not gitrepo.is_ancestor(self.git_dir, p[0], head) for p in prev)
        seq = self._next_seq(branches)
        ts = int(time.time())
        ev = build_git_manifest(self.secret, self.repo, head, d.tree, d.parents, d.rows, sorted(branches), created_at=ts, seq=seq,
                                valid_until=int(ts + self.valid_for) if self.valid_for else None, force=rewritten, history=history)
        files_x = next((t[1] for t in ev["tags"] if t[0] == "files_x"), None)
        if files_x:
            self.store.put_small(files_x, table_bytes(d.rows))
        for x, data in d.small.items():
            if not self.store.blob_complete(x):
                self.store.put_small(x, data)
        info = info_from_rows(self.repo, head, d.rows)
        files = [FileRec(p, size, x, x, True) for p, size, x, _ in d.rows]
        self.store.mark_published(self.repo, ev["pubkey"])
        for b in branches:
            self.store.put_commit(self.repo, b, head, info, files)
        self.store.set_source(self.repo, head, "signed")
        self.store.add_manifest(ev)
        return seq

    def _mirror_git(self, head: str, branches: list[str]) -> None:
        """Copy the history of the served commit into the hub's own bare repository and point the
        branches at it. That repository is what plain `git clone https://...` is served from, so it
        holds exactly what is served: the owner's other branches and unpublished work are never in it."""
        s = self.settings
        perm = self.store.git_repo_path(self.repo)
        have_here = perm.exists() and gitrepo.object_type(perm, head) == "commit"
        if not have_here:
            known = []
            if perm.exists():
                known = [c for c in (gitrepo.run_git(["for-each-ref", "--format=%(objectname)", "refs/heads"], cwd=perm, sandbox=True)[1].decode().split())
                         if gitrepo.local_has(self.git_dir, c)]
            pack = gitrepo.make_pack(self.git_dir, head, known, fsize=s.serve_git_max_pack * 2, timeout=600.0)
            tmp = Path(tempfile.mkdtemp(prefix="git-", dir=self.store.root / "tmp"))
            try:
                gitrepo.init_bare(tmp, perm if perm.exists() else None)
                sha = gitrepo.index_pack(tmp, pack, max_pack=s.serve_git_max_pack * 2, timeout=600.0)
                gitrepo.adopt(tmp, perm, sha)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        for b in branches:
            gitrepo.update_ref(perm, b, head)

    async def _history_entry(self, head: str) -> dict | None:
        """The commit's whole history as a pack, kept as a blob with a torrent and seeded, so a clone fetches it
        over BitTorrent. Built once per commit; the manifest signs its sha256, size and infohash."""
        entry = self._history.get(head)
        if entry and self.store.blob_complete(entry["x"]) and self.store.torrent_path(entry["x"]).exists():
            return entry
        entry = await asyncio.to_thread(self._build_history, head)
        await self.swarm.seed(self.store.torrent_path(entry["x"]), self.store.blob_path(entry["x"]).parent)
        self._history[head] = entry
        return entry

    def _build_history(self, head: str) -> dict:
        s = self.settings
        pack = gitrepo.make_pack(self.git_dir, head, [], fsize=MAX_HISTORY_BYTES * 2)
        if len(pack) > min(MAX_HISTORY_BYTES, s.publish_git_history_max):
            raise HostError(f"the history of {head[:12]} is {len(pack):,} bytes as a pack, over the limit; large files belong in LFS pointers, not in git")
        x = hashlib.sha256(pack).hexdigest()
        ph = PieceHasher(choose_piece_length(len(pack)))
        ph.update(pack)
        raw, ih = build_torrent(name=x, length=len(pack), piece_length=choose_piece_length(len(pack)), pieces=ph.finish(), trackers=[], comment="torrenthub git history")
        path, tmp = self.store.blob_path(x), self.store.tmp_path(x)
        tmp.write_bytes(pack)
        tmp.replace(path)
        self.store.torrent_path(x).write_bytes(sanitize_torrent(raw, s.trackers, [f"{s.public_url}/blobs/{x}"]))
        self.store.put_blob(BlobRow(x, len(pack), x, "complete", ih, choose_piece_length(len(pack)), time.time()))
        return {"x": x, "size": len(pack), "i": ih}

    # ------------------------------------------------------------------ big files, in place
    async def _ensure_files(self, d: gitrepo.Derived) -> None:
        for path, size, oid, _ in d.rows:
            if oid in d.big:
                self._where.setdefault(oid, path)
        for oid, size in d.big.items():
            await self._ensure_one(oid, size)

    def _healthy(self, oid: str, size: int) -> bool:
        rec = self._files.get(oid)
        if not rec or not self.store.blob_complete(oid) or not self.store.torrent_path(oid).exists():
            return False
        try:
            st = self.store.blob_path(oid).stat()  # follows a symbolic link to the file itself
        except OSError:
            return False
        return st.st_size == size and st.st_mtime_ns == rec["mtime_ns"]

    async def _ensure_one(self, oid: str, size: int) -> None:
        if await asyncio.to_thread(self._healthy, oid, size):
            return
        path = self._where.get(oid, oid)
        src = await asyncio.to_thread(gitrepo.find_big_file, self.git_dir, path, oid, size, [Path(x) for x in self.extra_dirs])
        if src is None:
            await self._withdraw(oid)
            raise HostError(f"{path}: the commit points at {oid[:12]} ({size:,} bytes) and no file with that size was found in the working tree, git-lfs's cache or --files-from")
        pieces = await asyncio.to_thread(self._hash, src, oid, size)
        if pieces is None:
            await self._withdraw(oid)
            raise HostError(f"{src} does not hash to the oid its pointer names ({oid[:12]}); it was changed after it was committed, so it is not served")
        await asyncio.to_thread(self._place, src, oid, size, pieces)
        await self.swarm.seed(self.store.torrent_path(oid), self.store.blob_path(oid).parent)
        log.info("%s: serving %s (%s) from %s", self.repo, path, f"{size:,} bytes", src)

    @staticmethod
    def _hash(src: Path, oid: str, size: int) -> bytes | None:
        h, ph = hashlib.sha256(), PieceHasher(choose_piece_length(size))
        with open(src, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
                ph.update(chunk)
        return ph.finish() if h.hexdigest() == oid else None

    def _place(self, src: Path, oid: str, size: int, pieces: bytes) -> None:
        s = self.settings
        dest = self.store.blob_path(oid)
        dest.unlink(missing_ok=True)
        try:
            os.link(src, dest)  # the same bytes, no second copy; survives the original being replaced
        except OSError:
            dest.symlink_to(Path(src).resolve())  # another file system: follow the original
        raw, _ = build_torrent(name=oid, length=size, piece_length=choose_piece_length(size), pieces=pieces,
                               trackers=[], comment="torrenthub host")
        self.store.torrent_path(oid).write_bytes(sanitize_torrent(raw, s.trackers, [f"{s.public_url}/blobs/{oid}"]))
        self.store.put_blob(BlobRow(oid, size, oid, "complete", infohash_from_torrent(raw), bdecode(raw)[b"info"][b"piece length"], time.time()))
        st = dest.stat()
        self._files[oid] = {"size": size, "mtime_ns": st.st_mtime_ns}
        tmp = self._state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._files))
        tmp.replace(self._state_path)

    async def _withdraw(self, oid: str) -> None:
        """Stop serving a file that is gone or no longer what it was."""
        placed = self.store.get_blob(oid) is not None
        if placed:
            self.store.set_blob_state(oid, "missing")
        self.store.blob_path(oid).unlink(missing_ok=True)
        if placed and self.store.torrent_path(oid).exists():
            try:
                await self.swarm.forget(self.store.torrent_path(oid))
            except Exception:  # noqa: BLE001
                log.exception("could not stop seeding %s", oid[:12])
        self._files.pop(oid, None)

    # ------------------------------------------------------------------ running
    async def run(self) -> None:
        while True:
            try:
                await self.refresh()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("host pass failed")
            await asyncio.sleep(self.poll)

    def report(self) -> dict:
        return {"repo": self.repo, "git": str(self.git_dir),
                "branches": {b: {"commit": s.commit, "seq": s.seq, "error": s.error, "checked": s.checked} for b, s in self.status.items()}}


def build_host_app(settings: Settings, *, swarm=None, **host_kwargs):
    """The ordinary hub app with a Host watching in the background."""
    from fastapi import APIRouter

    from .app import create_app

    app = create_app(settings, swarm=swarm)
    host = Host(settings, app.state.store, app.state.mirror.swarm, **host_kwargs)
    app.state.host = host
    router = APIRouter()

    @router.get("/api/thub/host")
    async def host_status():
        return host.report()

    app.include_router(router)
    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(a):
        async with inner(a):
            # one pass before the first request is answered, so a freshly started host serves what it has
            try:
                await host.refresh()
            except Exception:  # noqa: BLE001
                log.exception("first host pass failed")
            task = asyncio.create_task(host.run())
            try:
                yield
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    app.router.lifespan_context = lifespan
    return app, host
