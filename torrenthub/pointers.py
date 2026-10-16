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


def ensure_cached(gd: Path, oid: str, size: int, hubs: list[str]) -> Path:
    dest = cache_path(gd, oid)
    if dest.is_file() and dest.stat().st_size == size:
        return dest
    errors = []
    for hub in hubs:
        try:
            download(hub, oid, size, dest, gd)
            return dest
        except (httpx.HTTPError, ValueError) as e:
            errors.append(f"{hub}: {e}")
    raise GitError(f"cannot get {oid[:12]} ({size:,} bytes): " + ("; ".join(errors) or "no hub is configured (set thub.hub, or add a thub remote)"))


def download(hub: str, oid: str, size: int, dest: Path, gd: Path) -> None:
    """GET the blob and keep it only if it is the file the pointer names."""
    tmp = _tmp(gd)
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


def install(repo_dir: Path, patterns=DEFAULT_PATTERNS, command: str = "torrenthub") -> dict:
    """Set the filter up in a repository and say which patterns it covers."""
    repo_dir = Path(repo_dir)
    gd = git_dir(repo_dir)  # raises if this is not a repository
    for k, v in (("clean", f"{command} filter clean"), ("smudge", f"{command} filter smudge"), ("required", "true")):
        subprocess.run(["git", "config", f"filter.thub.{k}", v], cwd=repo_dir, check=True)
    ga = repo_dir / ".gitattributes"
    have = ga.read_text().splitlines() if ga.exists() else []
    added = []
    for pat in patterns:
        line = f"{pat} filter=thub -text"
        if line not in have:
            have.append(line)
            added.append(pat)
    if added:
        ga.write_text("\n".join(have) + "\n")
    return {"git_dir": str(gd), "added": added}
