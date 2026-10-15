"""A tiny stand-in for huggingface.co, good enough for the client and the mirror."""

from __future__ import annotations

import asyncio
import hashlib
import random

from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

REPO = "acme/tiny"


def git_blob_id(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def make_files() -> dict[str, bytes]:
    rng = random.Random(1234)
    return {
        "config.json": b'{"model_type": "tiny", "hidden_size": 8}\n',
        "README.md": b"# tiny\nA fake model for tests.\n",
        # 3.5 MiB so it clears the 1 MiB torrent threshold and spans several pieces.
        "model.safetensors": rng.randbytes(3 * 1024 * 1024 + 512 * 1024),
        "sub/dir/extra.bin": rng.randbytes(1500),
    }


def build_app(files: dict[str, bytes] | None = None, lfs_min: int = 1024 * 1024):
    files = files or make_files()
    lfs = {p for p, d in files.items() if len(d) >= lfs_min}
    manifest = "".join(f"{p}:{hashlib.sha256(d).hexdigest()}" for p, d in sorted(files.items()))
    commit = hashlib.sha1(manifest.encode()).hexdigest()
    app = FastAPI()
    app.state.hits = {"info": 0, "file": 0}
    app.state.file_hits = {}  # per file path
    app.state.delay = 0.0  # seconds between 256 KiB chunks; 0 means send at once
    app.state.finished = 0  # number of slow downloads fully sent

    # Advertised hashes are frozen at build time, so tests can later change the bytes
    # served and check that the mirror notices the mismatch.
    frozen = []
    for p, d in sorted(files.items()):
        s = {"rfilename": p, "size": len(d), "blobId": git_blob_id(d)}
        if p in lfs:
            s["lfs"] = {"sha256": hashlib.sha256(d).hexdigest(), "size": len(d), "pointerSize": 134}
        frozen.append(s)

    def siblings():
        return frozen

    @app.get("/api/models/{repo_id:path}/revision/{revision:path}")
    async def info(repo_id: str, revision: str):
        app.state.hits["info"] += 1
        if repo_id != REPO:
            return Response(status_code=404, headers={"X-Error-Code": "RepoNotFound"})
        if revision not in ("main", commit, "refs/pr/1"):
            return Response(status_code=404, headers={"X-Error-Code": "RevisionNotFound"})
        return {
            "_id": "fake",
            "id": repo_id,
            "modelId": repo_id,
            "sha": commit,
            "private": False,
            "gated": False,
            "disabled": False,
            "tags": [],
            "siblings": siblings(),
        }

    @app.get("/{repo_id:path}/resolve/{revision}/{filename:path}")
    async def resolve(repo_id: str, revision: str, filename: str, request: Request):
        app.state.hits["file"] += 1
        if repo_id != REPO or revision not in ("main", commit) or filename not in files:
            return Response(status_code=404, headers={"X-Error-Code": "EntryNotFound"})
        app.state.file_hits[filename] = app.state.file_hits.get(filename, 0) + 1
        data = files[filename]
        if app.state.delay <= 0:
            return Response(data, media_type="application/octet-stream")

        async def slow():
            step = 256 * 1024
            for i in range(0, len(data), step):
                await asyncio.sleep(app.state.delay)
                yield data[i:i + step]
            app.state.finished += 1

        return StreamingResponse(
            slow(), media_type="application/octet-stream", headers={"Content-Length": str(len(data))}
        )

    app.state.commit = commit
    app.state.files = files
    return app
