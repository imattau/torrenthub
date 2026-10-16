"""The publisher's side: turn a directory into a signed publication and get a hub to take it.

    torrenthub publish --repo acme/model --dir ./model --hub https://hub.example --key-file key

Steps: hash every file once (sha256 and BitTorrent pieces together), sign a version 2 manifest
over the file table, send the manifest, the small files and the torrents of the big ones, then
seed the big files and dial the hub's swarm port until the hub says it has them. Nothing needs to
be reachable from outside: the hub never connects to the publisher.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from .federation import fingerprint
from . import gitrepo
from .manifest import MAX_HISTORY_BYTES, build_git_manifest, build_manifest, content_commit, table_bytes
from .torrent import PieceHasher, build_torrent, choose_piece_length

TORRENT_MIN = 1024 * 1024  # files at least this big go by torrent, smaller ones are sent in the request
INLINE_BUDGET = 3 * 1024 * 1024  # keep clear of the hub's own limit (4 MiB by default)
SKIP_DIRS = {".git", "__pycache__", ".cache"}


@dataclass
class Item:
    path: str  # relative, with forward slashes
    source: Path
    size: int
    sha256: str
    pieces: bytes


def scan(root: Path) -> list[Item]:
    """Every regular file under `root`, hashed in one pass each."""
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"{root} is not a directory")
    items = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            p = Path(dirpath) / name
            if p.is_symlink() or not p.is_file():
                continue
            size = p.stat().st_size
            h, ph = hashlib.sha256(), PieceHasher(choose_piece_length(size))
            with open(p, "rb") as f:
                while chunk := f.read(1 << 20):
                    h.update(chunk)
                    ph.update(chunk)
            items.append(Item(p.relative_to(root).as_posix(), p, size, h.hexdigest(), ph.finish()))
    if not items:
        raise ValueError(f"{root} has no files")
    return items


@dataclass
class Publication:
    body: dict  # what to POST
    manifest: dict
    commit: str
    torrents: dict  # sha256 -> (torrent path, torrent bytes)
    stage: Path


def _stage(body: dict, stage: Path, torrents: dict, state: dict, sha: str, source: Path, size: int, pieces: bytes,
           trackers, *, label: str, force_torrent: bool = False) -> None:
    """Send a small file in the request, or make a torrent for a big one and put the bytes where
    libtorrent will look for them (under the torrent's name)."""
    if sha in state["seen"]:
        return
    state["seen"].add(sha)
    if not force_torrent and size < TORRENT_MIN and state["inline_used"] + size <= INLINE_BUDGET:
        body["inline"][sha] = base64.b64encode(source.read_bytes()).decode()
        state["inline_used"] += size
        return
    data, _ih = build_torrent(name=sha, length=size, piece_length=choose_piece_length(size), pieces=pieces,
                              trackers=trackers or [], comment="torrenthub publication")
    tpath = stage / f"{sha}.torrent"
    tpath.write_bytes(data)
    body["torrents"][sha] = base64.b64encode(data).decode()
    torrents[sha] = (tpath, data)
    target = stage / sha
    if not target.exists():
        try:
            os.link(source, target)
        except OSError:
            try:
                shutil.copyfile(source, target) if size < (64 << 20) else target.symlink_to(source.resolve())
            except OSError as e:
                raise ValueError(f"cannot stage {label}: {e}") from e


def prepare(secret: bytes, repo: str, root: Path, stage: Path, *, refs=("main",), seq: int = 1, valid_for: float | None = None,
            trackers: list[str] | None = None, created_at: int | None = None) -> Publication:
    items = scan(root)
    info = {"sha": "0" * 40, "siblings": [{"rfilename": i.path, "size": i.size, "lfs": {"size": i.size, "sha256": i.sha256}} for i in items]}
    rows = fingerprint(info)
    commit = content_commit(rows)
    info["sha"] = commit
    ts = int(created_at if created_at is not None else time.time())
    ev = build_manifest(secret, repo, info, list(refs), created_at=ts, seq=seq,
                        valid_until=int(ts + valid_for) if valid_for else None)
    body: dict = {"manifest": ev, "inline": {}, "torrents": {}}
    if any(t[0] == "files_x" for t in ev["tags"]):
        body["table"] = base64.b64encode(table_bytes(rows)).decode()
    stage = Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    state = {"inline_used": 0, "seen": set()}
    torrents = {}
    for i in items:
        _stage(body, stage, torrents, state, i.sha256, i.source, i.size, i.pieces, trackers, label=i.path)
    return Publication(body, ev, commit, torrents, stage)


async def next_seq(client: httpx.AsyncClient, hub: str, repo: str, ref: str) -> int:
    """One more than the highest seq the hub holds for this branch name."""
    import json

    r = await client.get(f"{hub}/api/thub/manifests/{quote(repo, safe='/')}")
    top = 0
    if r.status_code == 200:
        for ev in r.json().get("events", []):
            try:
                body = json.loads(ev["content"])
                if ref in body.get("refs", []) and body.get("v") in (2, 3):
                    top = max(top, int(body["seq"]))
            except (KeyError, ValueError, TypeError):
                continue
    return top + 1


async def publish(hub: str, pub: Publication, swarm, *, timeout: float = 3600.0, poll: float = 1.0, progress=None) -> dict:
    """POST the publication, seed the big files and dial the hub until it reports done or failed."""
    hub = hub.rstrip("/")
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(f"{hub}/api/thub/publish", json=pub.body)
        try:
            out = r.json()
        except ValueError:
            out = {"error": r.text[:300]}
        if r.status_code not in (200, 202):
            raise RuntimeError(f"hub refused ({r.status_code} {r.headers.get('x-error-code', '')}): {out.get('error') or out}")
        if out.get("already") or out.get("state") == "done":
            return out
        host, port = urlparse(hub).hostname, int(out["swarm"]["port"])
        for sha, (tpath, _data) in pub.torrents.items():
            await swarm.seed(tpath, pub.stage)
            await swarm.connect(tpath, host, port)
        deadline = time.monotonic() + timeout
        job = out["job"]
        while time.monotonic() < deadline:
            await asyncio.sleep(poll)
            st = (await client.get(f"{hub}/api/thub/publish/{job}")).json()
            if progress:
                progress(st)
            if st["state"] == "done":
                return st
            if st["state"] == "failed":
                raise RuntimeError(f"the hub could not take the publication: {st['error']}")
            for sha, (tpath, _data) in pub.torrents.items():  # re-dial in case the first attempt raced the hub's setup
                await swarm.connect(tpath, host, port)
        raise RuntimeError(f"not finished within {timeout:.0f}s")


def prepare_git(secret: bytes, repo: str, git_dir: Path, stage: Path, *, rev: str = "HEAD", refs=("main",), seq: int = 1,
                valid_for: float | None = None, trackers: list[str] | None = None, created_at: int | None = None,
                have: list[str] | None = None, extra_dirs: list[Path] | None = None, force: bool = False,
                blob_max: int = 8 * 1024 * 1024, small_total: int = 64 * 1024 * 1024, max_files: int = 5000) -> Publication:
    """A publication of one commit of a git repository. `have` are commits the hub already holds
    (from /api/thub/git/<repo>/refs): only the objects after them are sent. Big files are the ones
    the tree names with LFS pointers; their bytes are found in the working tree, in git-lfs's
    cache, or in `extra_dirs`, and each is checked against its pointer."""
    git_dir = Path(git_dir)
    if not git_dir.is_dir():
        raise ValueError(f"{git_dir} is not a directory")
    try:
        head = gitrepo.local_commit(git_dir, rev)
        d = gitrepo.derive(git_dir, head, blob_max=blob_max, small_total=small_total, max_files=max_files, sandbox=False)
    except gitrepo.GitError as e:
        raise ValueError(str(e)) from e
    ts = int(created_at if created_at is not None else time.time())
    stage = Path(stage)
    stage.mkdir(parents=True, exist_ok=True)
    history = make_history(git_dir, head, stage, trackers)
    ev = build_git_manifest(secret, repo, head, d.tree, d.parents, d.rows, list(refs), created_at=ts, seq=seq,
                            valid_until=int(ts + valid_for) if valid_for else None, force=force, history=history["entry"])
    body: dict = {"manifest": ev, "inline": {}, "torrents": {}}
    if any(t[0] == "files_x" for t in ev["tags"]):
        body["table"] = base64.b64encode(table_bytes(d.rows)).decode()
    known = [h for h in (have or []) if gitrepo.local_has(git_dir, h)]
    try:
        pack = gitrepo.make_pack(git_dir, head, known)
    except gitrepo.GitError as e:
        raise ValueError(str(e)) from e
    body["git"] = {"head": head, "pack": base64.b64encode(pack).decode()}
    body["torrents"][history["entry"]["x"]] = base64.b64encode(history["torrent"]).decode()
    # Big files the hub already holds, through a commit it has, are not hashed or sent again.
    held: set[str] = set()
    for h in known:
        try:
            held |= set(gitrepo.derive(git_dir, h, blob_max=blob_max, small_total=small_total, max_files=max_files, sandbox=False).big)
        except gitrepo.GitError:
            continue
    where = {}
    for path, size, oid, _ in d.rows:
        if oid in d.big and oid not in where and oid not in held:
            src = gitrepo.find_big_file(git_dir, path, oid, size, [Path(x) for x in (extra_dirs or [])])
            if src is None:
                raise ValueError(f"{path}: the commit points at {oid[:12]} ({size:,} bytes) and no file with that size was found in the working tree, git-lfs's cache or --files-from")
            where[oid] = (src, size)
    state = {"inline_used": 0, "seen": set()}
    torrents: dict = {}
    for oid, (src, size) in where.items():
        h, ph = hashlib.sha256(), PieceHasher(choose_piece_length(size))
        with open(src, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
                ph.update(chunk)
        if h.hexdigest() != oid:
            raise ValueError(f"{src} does not hash to the oid its pointer names ({oid[:12]}); is it the right version of the file?")
        _stage(body, stage, torrents, state, oid, src, size, ph.finish(), trackers, label=str(src))
    torrents[history["entry"]["x"]] = (history["torrent_path"], history["torrent"])
    return Publication(body, ev, head, torrents, stage)


def make_history(git_dir: Path, head: str, stage: Path, trackers=None) -> dict:
    """The whole history of `head` as one pack, with a torrent for it, staged for seeding. It is what a
    clone fetches over BitTorrent; the signed manifest names its sha256, size and infohash."""
    return history_from_pack(gitrepo.make_pack(git_dir, head, []), head, stage, trackers)


def history_from_pack(pack: bytes, head: str, stage: Path, trackers=None) -> dict:
    if len(pack) > MAX_HISTORY_BYTES:
        raise ValueError(f"the history of {head[:12]} is {len(pack):,} bytes as a pack; the limit is {MAX_HISTORY_BYTES:,}. Large files belong in LFS pointers, not in git")
    sha = hashlib.sha256(pack).hexdigest()
    ph = PieceHasher(choose_piece_length(len(pack)))
    ph.update(pack)
    data, ih = build_torrent(name=sha, length=len(pack), piece_length=choose_piece_length(len(pack)), pieces=ph.finish(),
                             trackers=trackers or [], comment="torrenthub git history")
    tpath = Path(stage) / f"{sha}.torrent"
    tpath.write_bytes(data)
    (Path(stage) / sha).write_bytes(pack)  # where libtorrent looks for the bytes: under the torrent's name
    return {"entry": {"x": sha, "size": len(pack), "i": ih}, "torrent": data, "torrent_path": tpath}


async def hub_heads(client: httpx.AsyncClient, hub: str, repo: str) -> list[str]:
    """The commits the hub holds at the head of each branch of a git backed repo."""
    r = await client.get(f"{hub}/api/thub/git/{quote(repo, safe='/')}/refs")
    if r.status_code != 200:
        return []
    return sorted(set(r.json().get("refs", {}).values()))
