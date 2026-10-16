"""Git as the source of truth for a published repo (HOSTING.md).

A commit pins every file: big files are LFS style pointer files in the tree (`oid sha256:`,
`size`), small files are plain git blobs. `derive` walks a commit and returns the file table that
follows from it, the same way on the publisher's side and on the hub's. The hub never trusts a
table the publisher states: it compares it with this one.

Everything the hub runs on a publisher's objects goes through `run_git(..., sandbox=True)`: a
fresh repository the publisher does not control, no system or user config, no hooks, no
templates, a time limit and a file size limit. The tree is refused if it holds anything a loader
or a checkout could be hurt by: symlinks, submodules, `.git` in a path, two paths that differ only
in case, a big blob that is not a pointer.

Limits worth knowing: `git index-pack` inflates what it receives, so a small pack that expands a
lot costs CPU until the time limit stops it. It does not cost disk beyond the pack itself.
"""

from __future__ import annotations

import os
import re
import resource
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

SHA40 = re.compile(r"[0-9a-f]{40}")
SHA256_HEX = re.compile(r"[0-9a-f]{64}")
POINTER = re.compile(rb"version https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (0|[1-9][0-9]{0,15})\n")
POINTER_MAX = 1024  # a pointer is about 130 bytes; anything over this is not one
MAX_PATH_LEN = 512
REF_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,63}){0,3}")


class GitError(Exception):
    """The objects are not acceptable, or git could not check them."""


def have_git() -> bool:
    return shutil.which("git") is not None


def valid_ref(name) -> bool:
    return isinstance(name, str) and bool(REF_NAME.fullmatch(name)) and ".." not in name and not name.endswith((".lock", "."))


def safe_path(p) -> bool:
    """A file path inside a repo: forward slashes, no empty, "." or ".." parts, no backslash and no
    control characters. Any other character, in any script, is fine."""
    return (isinstance(p, str) and 0 < len(p) <= MAX_PATH_LEN and not p.startswith("/")
            and "\\" not in p and all(part not in ("", ".", "..") for part in p.split("/"))
            and not any(ord(c) < 0x20 or ord(c) == 0x7F for c in p))


# ------------------------------------------------------------------ running git

def run_git(args, *, cwd=None, stdin: bytes | None = None, timeout: float = 60.0, fsize: int = 64 << 20,
            sandbox: bool = False, ok=(0,)) -> tuple[int, bytes, bytes]:
    """Run git and return (exit code, stdout, stderr). Output goes to files so a chatty or stuck
    process cannot block us; `fsize` is the most any file git writes (output included) may reach."""
    with tempfile.TemporaryDirectory(prefix="thub-git-") as td:
        td = Path(td)
        env = None
        if sandbox:
            env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(td), "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_ATTR_NOSYSTEM": "1", "LC_ALL": "C"}
        stdin_f = None
        if stdin is not None:
            (td / "in").write_bytes(stdin)
            stdin_f = open(td / "in", "rb")
        try:
            with open(td / "out", "wb") as out_f, open(td / "err", "wb") as err_f:
                try:
                    proc = subprocess.Popen(["git", *map(str, args)], cwd=cwd, stdin=stdin_f or subprocess.DEVNULL,
                                            stdout=out_f, stderr=err_f, env=env)
                except OSError as e:
                    raise GitError(f"cannot run git: {e}") from e
                try:
                    resource.prlimit(proc.pid, resource.RLIMIT_FSIZE, (fsize, fsize))
                except (OSError, ProcessLookupError, ValueError):
                    pass
                try:
                    rc = proc.wait(timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    raise GitError(f"git {args[0]} took longer than {timeout:.0f}s") from None
        finally:
            if stdin_f:
                stdin_f.close()
        out, err = (td / "out").read_bytes(), (td / "err").read_bytes()[:2000]
    if rc < 0:
        raise GitError(f"git {args[0]} was stopped (signal {-rc}): it wrote or ran past its limits")
    if rc not in ok:
        raise GitError(f"git {args[0]} failed: {err.decode(errors='replace').strip().splitlines()[0] if err.strip() else rc}")
    return rc, out, err


def init_bare(path: Path, alternate: Path | None = None) -> None:
    """A fresh bare repository the hub controls, optionally borrowing the objects of `alternate`."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    run_git(["init", "--bare", "--quiet", "--template=", "--initial-branch=main", str(path)], sandbox=True)
    if alternate is not None:
        (path / "objects" / "info").mkdir(parents=True, exist_ok=True)
        (path / "objects" / "info" / "alternates").write_text(str(Path(alternate).resolve() / "objects") + "\n")


def index_pack(repo: Path, pack: bytes, *, max_pack: int, timeout: float = 60.0) -> str:
    """Add a pack to `repo`, checking every object. Returns the pack's name (a sha1)."""
    if len(pack) > max_pack:
        raise GitError(f"the pack is {len(pack):,} bytes; this hub takes {max_pack:,} at most")
    if pack[:4] != b"PACK":
        raise GitError("that is not a git pack")
    _, out, _ = run_git(["index-pack", "--stdin", "--fix-thin", "--strict"], cwd=repo, stdin=pack, timeout=timeout,
                        fsize=2 * max_pack + (1 << 20), sandbox=True)
    m = re.fullmatch(rb"pack\t([0-9a-f]{40})\n", out)
    if not m:
        raise GitError("git did not report the pack it indexed")
    return m.group(1).decode()


def object_type(repo: Path, sha: str) -> str | None:
    rc, out, _ = run_git(["cat-file", "-t", sha], cwd=repo, sandbox=True, ok=(0, 128))
    return out.decode().strip() if rc == 0 else None


def check_connected(repo: Path, head: str, *, max_objects: int, timeout: float = 60.0) -> int:
    """Every object reachable from `head` is present. Returns how many there are."""
    try:
        _, out, _ = run_git(["rev-list", "--objects", "--no-object-names", head], cwd=repo, timeout=timeout,
                            fsize=max_objects * 42 + 4096, sandbox=True)
    except GitError as e:
        raise GitError(f"the history is not complete: {e}") from None
    n = out.count(b"\n")
    if n > max_objects:
        raise GitError(f"the history holds {n:,} objects; this hub takes {max_objects:,} at most")
    return n


def commit_fields(repo: Path, commit: str) -> tuple[str, tuple[str, ...]]:
    """(tree, parents) of a commit object."""
    _, out, _ = run_git(["cat-file", "commit", commit], cwd=repo, sandbox=True, fsize=1 << 20)
    head = out.split(b"\n\n", 1)[0].decode("utf-8", "replace")
    tree, parents = None, []
    for line in head.split("\n"):
        k, _, v = line.partition(" ")
        if k == "tree" and tree is None:
            tree = v
        elif k == "parent":
            parents.append(v)
    if tree is None or not SHA40.fullmatch(tree) or not all(SHA40.fullmatch(p) for p in parents) or len(parents) > 16:
        raise GitError("the commit object is malformed")
    return tree, tuple(parents)


def is_ancestor(repo: Path, old: str, new: str) -> bool:
    rc, _, _ = run_git(["merge-base", "--is-ancestor", old, new], cwd=repo, sandbox=True, ok=(0, 1, 128))
    return rc == 0


# ------------------------------------------------------------------ the file table of a commit

@dataclass(frozen=True)
class Derived:
    commit: str
    tree: str
    parents: tuple
    rows: tuple  # (path, size, sha256, None), sorted: the table the manifest must carry
    big: dict  # sha256 -> size: files that travel by torrent, named by their pointers
    small: dict  # sha256 -> bytes: plain git blobs, which came in the pack


def parse_pointer(data: bytes) -> tuple[str, int] | None:
    """(sha256, size) if `data` is exactly an LFS pointer, None if it is not one at all. Raises
    GitError for something that starts like one and is not well formed: it is refused rather than
    guessed at, since a loader might read it differently."""
    if len(data) > POINTER_MAX or not data.startswith(b"version https://git-lfs"):
        return None
    m = POINTER.fullmatch(data)
    if not m:
        raise GitError("a file looks like an LFS pointer but is not exactly one (three lines: version, oid sha256:, size)")
    return m.group(1).decode(), int(m.group(2))


def derive(repo: Path, commit: str, *, blob_max: int, small_total: int, max_files: int, sandbox: bool = True) -> Derived:
    """The file table of `commit`, or GitError saying what is wrong with the tree."""
    import hashlib

    tree, parents = commit_fields(repo, commit)
    _, out, _ = run_git(["ls-tree", "-r", "-z", "-l", "--full-tree", commit], cwd=repo, sandbox=sandbox,
                        fsize=max_files * (MAX_PATH_LEN + 100) + (1 << 16))
    entries = []
    for rec in out.split(b"\0"):
        if not rec:
            continue
        meta, tab, raw = rec.partition(b"\t")
        try:
            mode, typ, sha, size = meta.decode("ascii").split()
            path = raw.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise GitError("a path in the tree is not valid UTF-8") from None
        if mode == "120000":
            raise GitError(f"{path}: symbolic links are not accepted")
        if typ == "commit" or mode == "160000":
            raise GitError(f"{path}: submodules are not accepted")
        if typ != "blob" or mode not in ("100644", "100755"):
            raise GitError(f"{path}: unexpected entry type {typ} {mode}")
        if not safe_path(path):
            raise GitError(f"unsafe path {path!r}")
        entries.append((path, sha, int(size)))
        if len(entries) > max_files:
            raise GitError(f"the tree holds more than {max_files} files")
    if not entries:
        raise GitError("the commit has no files")

    seen, dirs = set(), set()
    for path, _, _ in entries:
        parts = path.split("/")
        if any(p.casefold() == ".git" for p in parts):
            raise GitError(f"{path}: a path may not contain .git")
        folded = path.casefold()
        if folded in seen:
            raise GitError(f"{path}: another path differs from it only in case")
        seen.add(folded)
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]).casefold())
    clash = seen & dirs
    if clash:
        raise GitError(f"{sorted(clash)[0]}: is both a file and a folder (ignoring case)")

    to_read: dict[str, int] = {}
    for path, sha, size in entries:
        if size > blob_max:
            raise GitError(f"{path}: {size:,} bytes is too big to keep in git here (limit {blob_max:,}); track it as a large file with an LFS pointer")
        to_read[sha] = size
    if sum(s for s in to_read.values() if s > POINTER_MAX) > small_total:
        raise GitError(f"the plain files add up to more than {small_total:,} bytes; track the big ones as large files")

    blobs = _read_blobs(repo, list(to_read), sum(to_read.values()), sandbox)
    rows, big, small = [], {}, {}
    for path, sha, size in entries:
        data = blobs[sha]
        ptr = parse_pointer(data)
        if ptr is not None:
            oid, lfs_size = ptr
            if big.setdefault(oid, lfs_size) != lfs_size:
                raise GitError(f"{path}: two pointers give different sizes for the same oid")
            rows.append((path, lfs_size, oid, None))
        else:
            x = hashlib.sha256(data).hexdigest()
            small[x] = data
            rows.append((path, len(data), x, None))
    clash = set(big) & set(small)
    if clash:
        raise GitError("a plain file has the same sha256 as a large file's pointer target")
    return Derived(commit, tree, parents, tuple(sorted(rows)), big, small)


def _read_blobs(repo: Path, shas: list[str], total: int, sandbox: bool) -> dict[str, bytes]:
    """The content of each blob, from one `git cat-file --batch`."""
    _, out, _ = run_git(["cat-file", "--batch"], cwd=repo, stdin="".join(s + "\n" for s in shas).encode(), sandbox=sandbox,
                        timeout=120.0, fsize=total + 200 * len(shas) + 4096)
    got, pos = {}, 0
    for sha in shas:
        nl = out.find(b"\n", pos)
        head = out[pos:nl].split()
        if nl < 0 or len(head) != 3 or head[0].decode() != sha or head[1] != b"blob":
            raise GitError("git returned something unexpected while reading files")
        n = int(head[2])
        got[sha] = out[nl + 1:nl + 1 + n]
        pos = nl + 1 + n + 1
    return got


# ------------------------------------------------------------------ keeping what was accepted

def adopt(tmp_repo: Path, perm_repo: Path, pack_sha: str, ref: str | None = None, head: str | None = None) -> None:
    """Move an indexed pack into the hub's permanent repository, then point `ref` at `head`."""
    if not perm_repo.exists():
        init_bare(perm_repo)
    dest = perm_repo / "objects" / "pack"
    dest.mkdir(parents=True, exist_ok=True)
    for ext in ("pack", "idx"):  # the index last: git only sees a pack once its index exists
        src = tmp_repo / "objects" / "pack" / f"pack-{pack_sha}.{ext}"
        tmp = dest / f".incoming-{pack_sha}.{ext}"
        shutil.copyfile(src, tmp)
        os.replace(tmp, dest / f"pack-{pack_sha}.{ext}")
    if ref is not None and head is not None:
        update_ref(perm_repo, ref, head)


def update_ref(perm_repo: Path, ref: str, head: str) -> None:
    if not valid_ref(ref) or not SHA40.fullmatch(head):
        raise GitError("bad ref")
    run_git(["update-ref", f"refs/heads/{ref}", head], cwd=perm_repo, sandbox=True)


# ------------------------------------------------------------------ the publisher's side

def local_commit(repo: Path, rev: str) -> str:
    _, out, _ = run_git(["-C", str(repo), "rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}"])
    sha = out.decode().strip()
    if not SHA40.fullmatch(sha):
        raise GitError(f"{rev} is not a commit in {repo}")
    return sha


def local_has(repo: Path, sha: str) -> bool:
    rc, _, _ = run_git(["-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"], ok=(0, 1, 128))
    return rc == 0


def make_pack(repo: Path, head: str, have: list[str]) -> bytes:
    """A pack with everything `head` needs that the hub does not already have."""
    revs = head + "\n" + "".join(f"^{h}\n" for h in have if SHA40.fullmatch(h))
    _, out, _ = run_git(["-C", str(repo), "pack-objects", "--revs", "--stdout", "--quiet"], stdin=revs.encode(), fsize=1 << 31, timeout=600.0)
    return out


def find_big_file(repo: Path, rel: str, oid: str, size: int, extra: list[Path], worktree: bool = True) -> Path | None:
    """Where the bytes for a pointer are on the publisher's disk: the working tree, git-lfs's
    cache, or a folder given by the user. The caller still hashes what it finds."""
    repo = Path(repo)
    gitdir = repo / ".git" if (repo / ".git").exists() else repo
    cands = []
    if worktree and (repo / ".git").exists():
        cands.append(repo / rel)
    cands.append(gitdir / "lfs" / "objects" / oid[:2] / oid[2:4] / oid)
    cands.append(gitdir / "thub" / "objects" / oid)
    for d in extra:
        cands += [Path(d) / rel, Path(d) / oid]
    for c in cands:
        try:
            if c.is_file() and not c.is_symlink() and c.stat().st_size == size:
                return c
        except OSError:
            continue
    return None
