"""Signed manifests: a creator vouches for the file table of a commit.

A manifest is a Nostr style event (see signing.py), so it can be passed around as plain JSON
and also published to a relay. Its content says: in repo R, commit C has exactly these files
with these sizes and hashes, and these branch names pointed at it at created_at.

An agent that pins the creator's public key for a repo namespace can then take hashes from
any hub and know they are the creator's, without trusting the hub or any origin.

Version 2 adds three things (PROTOCOL.md 3.2). `seq` orders manifests by a counter the creator
controls, instead of by a timestamp: a hub cannot make an older manifest win by replaying it,
and a higher `seq` always beats a lower one. `valid_until` lets a creator say when a manifest
stops being worth believing, so a hub that withholds a newer one cannot keep serving the old one
forever. `files_x` moves a large file table out of the event into a blob whose sha256 the event
signs, so the event stays small. Version 1 manifests are still read and rank as seq 0.

Version 3 (HOSTING.md) is for a repo that lives in git. `commit` is a real git commit id, `git`
repeats its tree and parents (and says whether the publisher means to rewrite history), and
`table_sha256` binds the file table. The table is still carried, because readers use it, but a
hub that takes a version 3 manifest derives the table from the git objects and refuses any that
disagree.

Kind 36777 is in the addressable range (30000 to 39999). It was checked against the NIPs README
table and the NIPs repo on 2026-10-16: no collisions, but nobody has registered it for this.
Change MANIFEST_KIND if a NIP ever claims it.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, replace

from .federation import fingerprint
from .signing import sign_event, verify_event

MANIFEST_KIND = 36777
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_EVENTS_PER_REPO = 200
MAX_TABLE_BYTES = 8 * 1024 * 1024
INLINE_ROWS = 200  # more rows than this go in a table blob by default
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")


class ManifestInvalid(Exception):
    pass


@dataclass(frozen=True)
class Manifest:
    id: str
    pubkey: str
    created_at: int
    repo: str
    commit: str
    refs: tuple[str, ...]
    rows: tuple | None  # None for a v2 manifest whose table has not been supplied yet
    event: dict
    seq: int = 0
    valid_until: int | None = None
    files_x: str | None = None  # sha256 of the table blob, when the rows are not in the event
    files_i: str | None = None  # infohash of that blob, if the creator seeds it
    git: dict | None = None  # version 3: {"tree", "parents", "force"}; None for a repo that never lived in git

    def expired(self, now: float | None = None) -> bool:
        return self.valid_until is not None and (time.time() if now is None else now) >= self.valid_until

    @property
    def needs_table(self) -> bool:
        return self.rows is None


def _dump(body: dict) -> str:
    return json.dumps(body, separators=(",", ":"), sort_keys=True, ensure_ascii=True)  # pure ASCII: escaping cannot differ


def table_bytes(rows) -> bytes:
    """The canonical bytes of a file table. Its sha256 is `files_x` and it is a published blob."""
    return _dump({"files": [list(r) for r in rows]}).encode()


def table_sha256(rows) -> str:
    return hashlib.sha256(table_bytes(rows)).hexdigest()


def content_commit(rows) -> str:
    """The 40 hex name of a published file table: the start of its table's sha256. A commit sha
    names a tree, and for a repo that never lived in git this is what names it, so two different
    tables can never share a name."""
    return table_sha256(rows)[:40]


def build_manifest(secret: bytes, repo_id: str, info: dict, refs: list[str], created_at: int | None = None, *,
                   seq: int | None = None, valid_until: int | None = None, table_blob: bool | None = None,
                   files_i: str | None = None) -> dict:
    """A signed manifest. Without `seq` this is the version 1 layout. With `seq` (1 or more) it is
    version 2. `table_blob=True` puts only the table's hash in the event (default: do that when
    there are more than INLINE_ROWS rows); publish the bytes from `table_bytes(fingerprint(info))`."""
    commit = info.get("sha")
    if not isinstance(commit, str) or not SHA40.match(commit):
        raise ValueError("info has no 40 hex commit sha")
    rows = fingerprint(info)
    refs_s = sorted(set(refs))
    tags = [["d", f"{repo_id}@{commit}"], ["repo", repo_id], ["commit", commit]] + [["ref", r] for r in refs_s]
    ts = int(created_at if created_at is not None else time.time())
    if seq is None:
        if valid_until is not None or table_blob or files_i:
            raise ValueError("valid_until, table_blob and files_i need a seq (version 2)")
        body = {"v": 1, "repo": repo_id, "commit": commit, "refs": refs_s, "files": [list(r) for r in rows]}
        return sign_event(secret, MANIFEST_KIND, tags, _dump(body), ts)
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError("seq must be a whole number of 1 or more")
    if valid_until is not None and (isinstance(valid_until, bool) or not isinstance(valid_until, int) or valid_until <= ts):
        raise ValueError("valid_until must be a time after created_at")
    body = {"v": 2, "repo": repo_id, "commit": commit, "refs": refs_s, "seq": seq, "valid_until": valid_until}
    tags.append(["seq", str(seq)])
    if table_blob is None:
        table_blob = len(rows) > INLINE_ROWS
    if table_blob:
        if files_i is not None and not re.match(r"^([0-9a-f]{40}|[0-9a-f]{64})$", files_i):
            raise ValueError("bad files_i")
        x = table_sha256(rows)
        body.update({"files_x": x, "files_i": files_i, "files_n": len(rows)})
        tags.append(["files_x", x])
    else:
        body["files"] = [list(r) for r in rows]
    return sign_event(secret, MANIFEST_KIND, tags, _dump(body), ts)


def build_git_manifest(secret: bytes, repo_id: str, commit: str, tree: str, parents, rows, refs: list[str], created_at: int | None = None, *,
                       seq: int, valid_until: int | None = None, table_blob: bool | None = None, files_i: str | None = None,
                       force: bool = False) -> dict:
    """A signed version 3 manifest for a git commit. `rows` is the file table that `gitrepo.derive`
    gives for it."""
    for what, v in (("commit", commit), ("tree", tree), *(("parent", p) for p in parents)):
        if not isinstance(v, str) or not SHA40.match(v):
            raise ValueError(f"{what} is not a 40 hex git id")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValueError("seq must be a whole number of 1 or more")
    ts = int(created_at if created_at is not None else time.time())
    if valid_until is not None and (isinstance(valid_until, bool) or not isinstance(valid_until, int) or valid_until <= ts):
        raise ValueError("valid_until must be a time after created_at")
    rows = tuple(tuple(r) for r in rows)
    refs_s = sorted(set(refs))
    x = table_sha256(rows)
    body = {"v": 3, "repo": repo_id, "commit": commit, "refs": refs_s, "seq": seq, "valid_until": valid_until,
            "git": {"tree": tree, "parents": list(parents), "force": bool(force)}, "table_sha256": x}
    tags = [["d", f"{repo_id}@{commit}"], ["repo", repo_id], ["commit", commit]] + [["ref", r] for r in refs_s] + [["seq", str(seq)]]
    if table_blob is None:
        table_blob = len(rows) > INLINE_ROWS
    if table_blob:
        if files_i is not None and not re.match(r"^([0-9a-f]{40}|[0-9a-f]{64})$", files_i):
            raise ValueError("bad files_i")
        body.update({"files_x": x, "files_i": files_i, "files_n": len(rows)})
        tags.append(["files_x", x])
    else:
        body["files"] = [list(r) for r in rows]
    return sign_event(secret, MANIFEST_KIND, tags, _dump(body), ts)


def with_table(m: Manifest, table: bytes) -> Manifest:
    """Complete a v2 manifest whose rows live in a blob. Checks the bytes against the signed hash."""
    if not m.files_x:
        raise ManifestInvalid("this manifest carries its rows inline")
    if len(table) > MAX_TABLE_BYTES or hashlib.sha256(table).hexdigest() != m.files_x:
        raise ManifestInvalid("table does not match the signed hash")
    try:
        rows = tuple(tuple(r) for r in json.loads(table)["files"])
        if table != table_bytes(rows):
            raise ManifestInvalid("table is not in canonical form")
    except ManifestInvalid:
        raise
    except (KeyError, TypeError, ValueError) as e:
        raise ManifestInvalid(f"malformed table: {type(e).__name__}") from e
    return replace(m, rows=rows)


def verify_manifest(ev: dict, allowed: set[str], repo_id: str, table: bytes | None = None) -> Manifest:
    """Return the parsed manifest if it is validly signed by one of `allowed` public keys and is
    about `repo_id`. A v2 manifest with `files_x` comes back with `rows` None unless `table` (the
    blob's bytes) is given. Raises ManifestInvalid otherwise."""
    try:
        if len(json.dumps(ev)) > MAX_EVENT_BYTES:
            raise ManifestInvalid("event too large")
        if ev.get("kind") != MANIFEST_KIND:
            raise ManifestInvalid("wrong kind")
        if ev.get("pubkey") not in allowed:
            raise ManifestInvalid("not signed by a key trusted for this repo")
        if not verify_event(ev):
            raise ManifestInvalid("bad id or signature")
        body = json.loads(ev["content"])
        v = body.get("v")
        if v not in (1, 2, 3) or body.get("repo") != repo_id:
            raise ManifestInvalid("not a version 1, 2 or 3 manifest for this repo")
        commit = body["commit"]
        if not isinstance(commit, str) or not SHA40.match(commit):
            raise ManifestInvalid("bad commit")
        refs = body["refs"]
        seq, valid_until, files_x, files_i, git = 0, None, None, None, None
        if v in (2, 3):
            seq, valid_until = body["seq"], body.get("valid_until")
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
                raise ManifestInvalid("bad seq")
            if valid_until is not None and (isinstance(valid_until, bool) or not isinstance(valid_until, int)):
                raise ManifestInvalid("bad valid_until")
            files_x, files_i = body.get("files_x"), body.get("files_i")
            if (files_x is None) == ("files" not in body):
                raise ManifestInvalid("a manifest has either files or files_x, not both and not neither")
            if files_x is not None and not (isinstance(files_x, str) and SHA64.match(files_x)):
                raise ManifestInvalid("bad files_x")
            if files_i is not None and not (isinstance(files_i, str) and re.match(r"^([0-9a-f]{40}|[0-9a-f]{64})$", files_i)):
                raise ManifestInvalid("bad files_i")
            if [t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "seq"] != [str(seq)]:
                raise ManifestInvalid("tags disagree with the signed content")
            if sorted(t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "files_x") != ([files_x] if files_x else []):
                raise ManifestInvalid("tags disagree with the signed content")
        files = body.get("files", [])
        if v == 3:
            git = body.get("git")
            if (not isinstance(git, dict) or set(git) != {"tree", "parents", "force"} or not isinstance(git["tree"], str) or not SHA40.match(git["tree"])
                    or not isinstance(git["parents"], list) or len(git["parents"]) > 16
                    or not all(isinstance(p, str) and SHA40.match(p) for p in git["parents"]) or not isinstance(git["force"], bool)):
                raise ManifestInvalid("bad git field")
            tx = body.get("table_sha256")
            if not (isinstance(tx, str) and SHA64.match(tx)):
                raise ManifestInvalid("bad table_sha256")
            if files_x is not None and tx != files_x:
                raise ManifestInvalid("table_sha256 and files_x disagree")
            if files_x is None and tx != table_sha256(tuple(tuple(r) for r in files)):
                raise ManifestInvalid("table_sha256 is not the hash of the files")
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            raise ManifestInvalid("bad refs")
        tag_refs = sorted(t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "ref")
        tag_commit = [t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "commit"]
        if tag_commit != [commit] or tag_refs != sorted(refs):
            raise ManifestInvalid("tags disagree with the signed content")
        m = Manifest(ev["id"], ev["pubkey"], int(ev["created_at"]), repo_id, commit, tuple(refs),
                     None if files_x else tuple(tuple(r) for r in files), ev, seq, valid_until, files_x, files_i, git)
        return with_table(m, table) if (files_x and table is not None) else m
    except ManifestInvalid:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise ManifestInvalid(f"malformed: {type(e).__name__}") from e
