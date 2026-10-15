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
from .manifest import build_manifest, content_commit, table_bytes
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
    torrents, inline_used, seen = {}, 0, set()
    for i in items:
        if i.sha256 in seen:
            continue
        seen.add(i.sha256)
        if i.size < TORRENT_MIN and inline_used + i.size <= INLINE_BUDGET:
            body["inline"][i.sha256] = base64.b64encode(i.source.read_bytes()).decode()
            inline_used += i.size
            continue
        data, _ih = build_torrent(name=i.sha256, length=i.size, piece_length=choose_piece_length(i.size), pieces=i.pieces,
                                  trackers=trackers or [], comment="torrenthub publication")
        tpath = stage / f"{i.sha256}.torrent"
        tpath.write_bytes(data)
        body["torrents"][i.sha256] = base64.b64encode(data).decode()
        torrents[i.sha256] = (tpath, data)
        target = stage / i.sha256  # libtorrent looks for the file under the torrent's name
        if not target.exists():
            try:
                os.link(i.source, target)
            except OSError:
                try:
                    shutil.copyfile(i.source, target) if i.size < (64 << 20) else target.symlink_to(i.source.resolve())
                except OSError as e:
                    raise ValueError(f"cannot stage {i.path}: {e}") from e
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
                if ref in body.get("refs", []) and body.get("v") == 2:
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
