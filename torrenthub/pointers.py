"""Big files in a git repository without git-lfs (HOSTING.md, stage H3).

A git "filter" turns a big file into a three line pointer when it is added (`clean`) and back into
the file when it is checked out (`smudge`). The pointer format is git-lfs's, so the hub, the
publisher and git-lfs itself agree on what a pointer is. The bytes live in `.git/thub/objects/<sha256>`,
where `torrenthub publish --git` and `torrenthub host` already look for them.

    torrenthub git-init            # once per repository: sets the filter up and writes .gitattributes
    git add model.safetensors      # clean: bytes into the cache, a pointer into git
    git checkout                   # smudge: pointer to bytes, from the cache or from the hub

`smudge` fetches from a hub named in `thub.hub` or in the URL of a thub remote, and checks the
sha256 of what it got before it keeps or shows a byte. Set `THUB_SKIP_SMUDGE=1` to check out
pointers only (a clone of a big repo that you do not want to download yet); `torrenthub pull-files`
fills them in later.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import uuid
from pathlib import Path

import httpx

from .gitrepo import POINTER_MAX, GitError, parse_pointer

CHUNK = 1 << 20
DEFAULT_PATTERNS = ("*.safetensors", "*.gguf", "*.bin", "*.pt", "*.pth", "*.ckpt", "*.onnx", "*.h5", "*.npz", "*.parquet", "*.arrow", "*.tar", "*.zip")


def pointer_bytes(oid: str, size: int) -> bytes:
    return f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize {size}\n".encode()


def _git(args, cwd=None) -> str:
    r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def git_dir(cwd=None) -> Path:
    d = _git(["rev-parse", "--absolute-git-dir"], cwd)
    if not d:
        raise GitError("not inside a git repository")
    return Path(d)


def cache_path(gd: Path, oid: str) -> Path:
    return Path(gd) / "thub" / "objects" / oid


def _tmp(gd: Path) -> Path:
    d = Path(gd) / "thub" / "tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d / uuid.uuid4().hex


def as_pointer(data: bytes) -> tuple[str, int] | None:
    if len(data) > POINTER_MAX or not data.startswith(b"version https://git-lfs"):
        return None
    try:
        return parse_pointer(data)
    except GitError:
        return None


# ------------------------------------------------------------------ clean and smudge

def clean(inp, out, gd: Path) -> None:
    """Content in, pointer out; the content is kept in the cache. A pointer passes through."""
    head = inp.read(POINTER_MAX + 1)
    if as_pointer(head) is not None:
        out.write(head)
        return
    tmp = _tmp(gd)
    h, size = hashlib.sha256(), 0
    try:
        with open(tmp, "wb") as f:
            chunk = head
            while chunk:
                h.update(chunk)
                f.write(chunk)
                size += len(chunk)
                chunk = inp.read(CHUNK)
        oid = h.hexdigest()
        dest = cache_path(gd, oid)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists() and dest.stat().st_size == size:
            tmp.unlink()
        else:
            os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)
    out.write(pointer_bytes(oid, size))


def smudge(inp, out, gd: Path, hubs: list[str]) -> None:
    """Pointer in, content out. Anything that is not a pointer passes through."""
    head = inp.read(POINTER_MAX + 1)
    ptr = as_pointer(head)
    if ptr is None or os.environ.get("THUB_SKIP_SMUDGE"):
        out.write(head)
        while chunk := inp.read(CHUNK):
            out.write(chunk)
        return
    oid, size = ptr
    path = ensure_cached(gd, oid, size, hubs)
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK):
            out.write(chunk)


def ensure_cached(gd: Path, oid: str, size: int, hubs: list[str], cfg=None) -> Path:
    """The file for a pointer, from the cache or fetched: over BitTorrent first (clientswarm.py), then HTTP."""
    from . import clientswarm

    dest = cache_path(gd, oid)
    if dest.is_file() and dest.stat().st_size == size:
        return dest
    cfg = cfg or clientswarm.config_from_env(gd)
    errors = []
    for hub in hubs:
        try:
            clientswarm.fetch_blob(hub, oid, size, dest, Path(gd) / "thub" / "swarm", cfg=cfg, keep_torrent=Path(gd) / "thub" / "torrents" / f"{oid}.torrent")
            return dest
        except GitError as e:
            errors.append(str(e))
    raise GitError(f"cannot get {oid[:12]} ({size:,} bytes): " + ("; ".join(errors) or "no hub is configured (set thub.hub, or add a thub remote)"))


def download(hub: str, oid: str, size: int, dest: Path, tmp_dir: Path) -> None:
    """GET the blob over HTTP and keep it only if it is the file the pointer names."""
    tmp_dir = Path(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / uuid.uuid4().hex
    h, got = hashlib.sha256(), 0
    try:
        with httpx.stream("GET", f"{hub.rstrip('/')}/blobs/{oid}", timeout=60, follow_redirects=True) as r:
            if r.status_code != 200:
                raise ValueError(f"the hub answered {r.status_code}")
            with open(tmp, "wb") as f:
                for chunk in r.iter_bytes(CHUNK):
                    got += len(chunk)
                    if got > size:
                        raise ValueError("more bytes than the pointer says")
                    h.update(chunk)
                    f.write(chunk)
        if got != size or h.hexdigest() != oid:
            raise ValueError("what arrived is not the file the pointer names")
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(tmp, dest)
    finally:
        tmp.unlink(missing_ok=True)


# ------------------------------------------------------------------ finding the hub, filling in a checkout

def hubs_for(cwd=None) -> list[str]:
    from .gitremote import parse_url

    hubs = []
    explicit = _git(["config", "--get", "thub.hub"], cwd)
    if explicit:
        hubs.append(explicit.rstrip("/"))
    for line in _git(["config", "--get-regexp", r"^remote\..*\.url$"], cwd).splitlines():
        url = line.partition(" ")[2]
        if url.startswith("thub::") or url.startswith("thub://"):
            try:
                hubs.append(parse_url(url[len("thub::"):] if url.startswith("thub::") else url)[0])
            except ValueError:
                continue
    return list(dict.fromkeys(hubs))


def materialize(repo_dir: Path, hubs: list[str] | None = None) -> list[str]:
    """Replace every pointer file in the working tree by the file it names. Returns the paths filled in."""
    repo_dir = Path(repo_dir)
    gd = git_dir(repo_dir)
    hubs = hubs if hubs is not None else hubs_for(repo_dir)
    done = []
    for rel in _git(["ls-files", "-z"], repo_dir).split("\0"):
        p = repo_dir / rel
        if not rel or p.is_symlink() or not p.is_file() or p.stat().st_size > POINTER_MAX:
            continue
        ptr = as_pointer(p.read_bytes())
        if ptr is None:
            continue
        oid, size = ptr
        src = ensure_cached(gd, oid, size, hubs)
        tmp = p.with_name(p.name + ".thub-tmp")
        try:
            try:
                os.link(src, tmp)
            except OSError:
                tmp.write_bytes(src.read_bytes())
            os.replace(tmp, p)
        finally:
            tmp.unlink(missing_ok=True)
        done.append(rel)
    if done:
        # Git decides "modified" from the size recorded in the index before it runs any filter; the index
        # has the pointer's size. Registering the files again records the real one (their blobs, the
        # pointers, are unchanged), which is what a checkout through the smudge filter would have done.
        subprocess.run(["git", "update-index", "-z", "--stdin"], cwd=repo_dir, input="\0".join(done) + "\0", text=True, check=True)
    return done


HOOK_MARK = "# torrenthub: pre-push"
HOOK = f"""#!/bin/sh
{HOOK_MARK}
# git-lfs would upload LFS objects to the remote; a thub remote takes big files through git-remote-thub instead.
case "$2" in
  thub::*|thub://*) exit 0 ;;
esac
command -v git-lfs >/dev/null 2>&1 || exit 0
exec git lfs pre-push "$@"
"""


def _pre_push_hook(repo_dir: Path) -> list[str]:
    path = Path(_git(["rev-parse", "--git-path", "hooks/pre-push"], repo_dir))
    path = path if path.is_absolute() else Path(repo_dir) / path
    if path.exists():
        old = path.read_text(errors="replace")
        if HOOK_MARK in old:
            return []
        if "git lfs pre-push" in old and len(old) < 600:  # git-lfs's own: ours does the same for every remote but a thub one
            path.rename(path.with_name("pre-push.thub-backup"))
        else:
            return [f"{path} is a hook of your own: it will run for pushes to a thub remote too. If it calls git lfs pre-push, skip that for thub:: URLs"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(HOOK)
    path.chmod(0o755)
    return []


def install(repo_dir: Path, patterns=DEFAULT_PATTERNS, command: str = "torrenthub", lfs: bool = False) -> dict:
    """Set the filter up in a repository and say which patterns it covers. With `lfs`, write the
    attributes git-lfs expects (and set nothing up here): a stock git-lfs then handles the files, and
    a hub's LFS endpoint serves them to a plain `git clone`."""
    repo_dir = Path(repo_dir)
    gd = git_dir(repo_dir)  # raises if this is not a repository
    warnings = []
    if not lfs:
        for k, v in (("clean", f"{command} filter clean"), ("smudge", f"{command} filter smudge"), ("required", "true")):
            subprocess.run(["git", "config", f"filter.thub.{k}", v], cwd=repo_dir, check=True)
    else:
        # What `git lfs install --local` sets for the filters, and our own pre-push hook. git-lfs installs a pre-push
        # hook the first time its filter runs, and that hook uploads LFS objects to the remote, which fails against a
        # thub remote (a hub takes big files through git-remote-thub). A hook that is already there is not overwritten.
        for k, v in (("clean", "git-lfs clean -- %f"), ("smudge", "git-lfs smudge -- %f"), ("process", "git-lfs filter-process"), ("required", "true")):
            subprocess.run(["git", "config", f"filter.lfs.{k}", v], cwd=repo_dir, check=True)
        warnings += _pre_push_hook(repo_dir)
    ga = repo_dir / ".gitattributes"
    have = ga.read_text().splitlines() if ga.exists() else []
    added = []
    for pat in patterns:
        line = f"{pat} filter=lfs diff=lfs merge=lfs -text" if lfs else f"{pat} filter=thub -text"
        if line not in have:
            have.append(line)
            added.append(pat)
    if added:
        ga.write_text("\n".join(have) + "\n")
    return {"git_dir": str(gd), "added": added, "warnings": warnings}
