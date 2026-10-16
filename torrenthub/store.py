"""SQLite catalogue plus on-disk blob and torrent storage.

Layout under data_dir:
  hub.db                      catalogue
  blobs/<key[:2]>/<key>       content, named by blob key (also the torrent name)
  torrents/<key>.torrent      one torrent per large blob
  tmp/                        in-flight downloads

Blob key: the LFS sha256 for LFS files, "git-<blobId>" for plain git files.
Keying by content (not by repo or path) means the same weights shared by many repos
or revisions are stored, torrented and seeded once.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

# What a blob key can be: the sha256 of an LFS file, or "git-" and the 40 hex digits of a git blob id.
# Keys come from other hubs' metadata and are used to build file names, so nothing else is allowed.
KEY_RE = re.compile(r"(?:[0-9a-f]{64}|git-[0-9a-f]{40})")


def valid_key(key: str) -> bool:
    return isinstance(key, str) and KEY_RE.fullmatch(key) is not None


def _checked(key: str) -> str:
    if not valid_key(key):
        raise ValueError(f"unusable blob key {key!r}")
    return key


SCHEMA = """
CREATE TABLE IF NOT EXISTS refs (
  repo_id TEXT NOT NULL, ref TEXT NOT NULL, commit_sha TEXT NOT NULL, fetched_at REAL NOT NULL,
  PRIMARY KEY (repo_id, ref)
);
CREATE TABLE IF NOT EXISTS commits (
  repo_id TEXT NOT NULL, commit_sha TEXT NOT NULL, info_json TEXT NOT NULL,
  PRIMARY KEY (repo_id, commit_sha)
);
CREATE TABLE IF NOT EXISTS files (
  repo_id TEXT NOT NULL, commit_sha TEXT NOT NULL, path TEXT NOT NULL,
  size INTEGER NOT NULL, etag TEXT NOT NULL, blob_key TEXT NOT NULL, is_lfs INTEGER NOT NULL,
  PRIMARY KEY (repo_id, commit_sha, path)
);
CREATE TABLE IF NOT EXISTS blobs (
  key TEXT PRIMARY KEY, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
  state TEXT NOT NULL, infohash TEXT, piece_length INTEGER,
  last_access REAL NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS trust (
  repo_id TEXT NOT NULL, commit_sha TEXT NOT NULL, source TEXT NOT NULL,
  PRIMARY KEY (repo_id, commit_sha)
);
CREATE TABLE IF NOT EXISTS blocked (
  key TEXT PRIMARY KEY, reason TEXT NOT NULL, at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS published (
  repo_id TEXT PRIMARY KEY, signer TEXT NOT NULL, first_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS publish_charges (
  signer TEXT NOT NULL, blob_key TEXT NOT NULL, size INTEGER NOT NULL, at REAL NOT NULL,
  PRIMARY KEY (signer, blob_key)
);
"""


@dataclass
class FileRec:
    path: str
    size: int
    etag: str
    blob_key: str
    is_lfs: bool

    @property
    def sha256(self) -> str | None:
        return self.blob_key if self.is_lfs else None

    @property
    def git_blob_id(self) -> str | None:
        return None if self.is_lfs else self.blob_key.removeprefix("git-")


@dataclass
class BlobRow:
    key: str
    size: int
    sha256: str
    state: str
    infohash: str | None
    piece_length: int | None
    last_access: float = 0.0


class Store:
    def __init__(self, data_dir: Path):
        self.root = Path(data_dir)
        for sub in ("blobs", "torrents", "tmp"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.root / "hub.db", check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(SCHEMA)
            # Migrate catalogues created by the first prototype.
            cols = {r["name"] for r in self._db.execute("PRAGMA table_info(blobs)")}
            if "last_access" not in cols:
                self._db.execute("ALTER TABLE blobs ADD COLUMN last_access REAL NOT NULL DEFAULT 0")
                self._db.commit()

    # paths
    def blob_path(self, key: str) -> Path:
        _checked(key)
        p = self.root / "blobs" / key[:2]
        p.mkdir(parents=True, exist_ok=True)
        return p / key

    def torrent_path(self, key: str) -> Path:
        return self.root / "torrents" / f"{_checked(key)}.torrent"

    def tmp_path(self, key: str) -> Path:
        return self.root / "tmp" / f"{_checked(key)}.part"

    def swarm_torrent_path(self, key: str) -> Path:
        """Working copy of a torrent handed to the swarm engine, with web seeds removed."""
        return self.root / "tmp" / f"{_checked(key)}.swarm.torrent"

    # refs and commits
    def get_ref(self, repo_id: str, ref: str) -> tuple[str, float] | None:
        with self._lock:
            r = self._db.execute(
                "SELECT commit_sha, fetched_at FROM refs WHERE repo_id=? AND ref=?", (repo_id, ref)
            ).fetchone()
        return (r["commit_sha"], r["fetched_at"]) if r else None

    def has_commit(self, repo_id: str, sha: str) -> bool:
        with self._lock:
            return self._db.execute(
                "SELECT 1 FROM commits WHERE repo_id=? AND commit_sha=?", (repo_id, sha)
            ).fetchone() is not None

    def get_commit_info(self, repo_id: str, sha: str) -> dict | None:
        with self._lock:
            r = self._db.execute(
                "SELECT info_json FROM commits WHERE repo_id=? AND commit_sha=?", (repo_id, sha)
            ).fetchone()
        return json.loads(r["info_json"]) if r else None

    def put_commit(self, repo_id: str, ref: str, sha: str, info: dict, files: list[FileRec]) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO commits VALUES (?,?,?)", (repo_id, sha, json.dumps(info))
            )
            self._db.executemany(
                "INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?,?)",
                [(repo_id, sha, f.path, f.size, f.etag, f.blob_key, int(f.is_lfs)) for f in files],
            )
            self._db.execute(
                "INSERT OR REPLACE INTO refs VALUES (?,?,?,?)", (repo_id, ref, sha, time.time())
            )

    SOURCE_RANK = {"hub": 0, "upstream": 1, "anchor": 2, "signed": 2}

    # signed manifests: one JSON file per event, grouped by repo
    def _manifest_dir(self, repo_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?", repo_id):
            raise ValueError(f"unusable repo id {repo_id!r}")
        return self.root / "manifests" / repo_id.replace("/", "__")

    def add_manifest(self, event: dict) -> bool:
        """Keep a manifest event that the caller has already verified. True if it was new."""
        repo = next((t[1] for t in event.get("tags", []) if len(t) >= 2 and t[0] == "repo"), None)
        if not repo or not re.fullmatch(r"[0-9a-f]{64}", str(event.get("id", ""))):
            raise ValueError("manifest event without a repo tag or a valid id")
        d = self._manifest_dir(repo)
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{event['id']}.json"
        if path.exists():
            return False
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(event))
        tmp.replace(path)
        return True

    def list_manifests(self, repo_id: str, limit: int = 200) -> list[dict]:
        try:
            d = self._manifest_dir(repo_id)
        except ValueError:
            return []
        if not d.is_dir():
            return []
        files = sorted(d.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]
        out = []
        for f in files:
            try:
                out.append(json.loads(f.read_text()))
            except (OSError, ValueError):
                continue
        return out

    def set_source(self, repo_id: str, sha: str, source: str) -> None:
        """Where a commit's file table came from. A weaker source never replaces "anchor"."""
        with self._lock, self._db:
            row = self._db.execute(
                "SELECT source FROM trust WHERE repo_id=? AND commit_sha=?", (repo_id, sha)
            ).fetchone()
            if row and self.SOURCE_RANK.get(row["source"], 0) >= self.SOURCE_RANK[source]:
                return
            self._db.execute("INSERT OR REPLACE INTO trust VALUES (?,?,?)", (repo_id, sha, source))

    def get_source(self, repo_id: str, sha: str) -> str | None:
        with self._lock:
            r = self._db.execute(
                "SELECT source FROM trust WHERE repo_id=? AND commit_sha=?", (repo_id, sha)
            ).fetchone()
        return r["source"] if r else None

    def touch_ref(self, repo_id: str, ref: str, sha: str) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO refs VALUES (?,?,?,?)", (repo_id, ref, sha, time.time())
            )

    def get_file(self, repo_id: str, sha: str, path: str) -> FileRec | None:
        with self._lock:
            r = self._db.execute(
                "SELECT * FROM files WHERE repo_id=? AND commit_sha=? AND path=?", (repo_id, sha, path)
            ).fetchone()
        return self._file(r) if r else None

    def list_files(self, repo_id: str, sha: str) -> list[FileRec]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM files WHERE repo_id=? AND commit_sha=? ORDER BY path", (repo_id, sha)
            ).fetchall()
        return [self._file(r) for r in rows]

    @staticmethod
    def _file(r: sqlite3.Row) -> FileRec:
        return FileRec(r["path"], r["size"], r["etag"], r["blob_key"], bool(r["is_lfs"]))

    # blobs
    def get_blob(self, key: str) -> BlobRow | None:
        with self._lock:
            r = self._db.execute("SELECT * FROM blobs WHERE key=?", (key,)).fetchone()
        return BlobRow(**dict(r)) if r else None

    def put_blob(self, row: BlobRow) -> None:
        with self._lock, self._db:
            self._db.execute(
                "INSERT OR REPLACE INTO blobs "
                "(key, size, sha256, state, infohash, piece_length, last_access) VALUES (?,?,?,?,?,?,?)",
                (row.key, row.size, row.sha256, row.state, row.infohash, row.piece_length, row.last_access),
            )

    def held_by_infohash(self, infohash_hex: str) -> str | None:
        """The key of a complete, unblocked blob with this torrent infohash, or None."""
        with self._lock:
            r = self._db.execute("SELECT key FROM blobs WHERE infohash=? AND state='complete' "
                                 "AND key NOT IN (SELECT key FROM blocked) LIMIT 1", (infohash_hex,)).fetchone()
        return r["key"] if r else None

    def put_small(self, key: str, data: bytes) -> None:
        """Store a whole small blob whose key is the sha256 of its bytes (the caller has checked that)."""
        path, tmp = self.blob_path(key), self.tmp_path(key)
        tmp.write_bytes(data)
        tmp.replace(path)
        self.put_blob(BlobRow(key, len(data), key, "complete", None, None, time.time()))

    def touch_blob(self, key: str) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE blobs SET last_access=? WHERE key=?", (time.time(), key))

    def disk_usage(self) -> int:
        with self._lock:
            r = self._db.execute("SELECT COALESCE(SUM(size), 0) AS n FROM blobs WHERE state='complete'").fetchone()
        return int(r["n"])

    def count_blobs(self) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COUNT(*) AS n FROM blobs WHERE state='complete'").fetchone()["n"])

    def git_repo_path(self, repo_id: str) -> Path:
        """The bare git repository the hub keeps for a published or hosted repo."""
        self._manifest_dir(repo_id)  # validates the name
        return self.root / "git" / (repo_id.replace("/", "__") + ".git")

    def repo_has_blob(self, repo_id: str, key: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM files WHERE repo_id=? AND blob_key=? LIMIT 1", (repo_id, key)).fetchone() is not None

    # published repos: content that exists nowhere else, so it is never evicted and never re-asked of an upstream
    def mark_published(self, repo_id: str, signer: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR IGNORE INTO published VALUES (?,?,?)", (repo_id, signer, time.time()))

    def list_repos(self, query: str = "", limit: int = 50) -> list[dict]:
        """Repos this hub knows a branch of, newest first. `query` is a plain substring of the name."""
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        with self._lock:
            rows = self._db.execute(
                "SELECT r.repo_id AS repo_id, COUNT(*) AS refs, MAX(r.fetched_at) AS at, p.signer AS signer "
                "FROM refs r LEFT JOIN published p ON p.repo_id = r.repo_id "
                "WHERE r.repo_id LIKE ? ESCAPE '\\' GROUP BY r.repo_id ORDER BY at DESC LIMIT ?",
                (like, max(1, min(int(limit), 500)))).fetchall()
        return [{"repo": r["repo_id"], "branches": r["refs"], "updated_at": r["at"], "published_by": r["signer"]} for r in rows]

    def is_published(self, repo_id: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM published WHERE repo_id=?", (repo_id,)).fetchone() is not None

    def charge(self, signer: str, blob_key: str, size: int) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR IGNORE INTO publish_charges VALUES (?,?,?,?)", (signer, blob_key, size, time.time()))

    def charged_bytes(self, signer: str) -> int:
        with self._lock:
            return int(self._db.execute("SELECT COALESCE(SUM(size), 0) AS n FROM publish_charges WHERE signer=?", (signer,)).fetchone()["n"])

    def lru_candidates(self) -> list[BlobRow]:
        """Complete blobs that can be refilled from the swarm, least recently used first. Blobs a
        publisher put here are left out: if the publisher is gone, nobody could refill them."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM blobs WHERE state='complete' AND infohash IS NOT NULL "
                "AND key NOT IN (SELECT blob_key FROM publish_charges) ORDER BY last_access ASC"
            ).fetchall()
        return [BlobRow(**dict(r)) for r in rows]

    # takedown block list
    def add_block(self, key: str, reason: str) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO blocked VALUES (?,?,?)", (key, reason, time.time()))

    def is_blocked(self, key: str) -> bool:
        with self._lock:
            return self._db.execute("SELECT 1 FROM blocked WHERE key=?", (key,)).fetchone() is not None

    def names_for_blob(self, key: str) -> list[str]:
        with self._lock:
            rows = self._db.execute("SELECT DISTINCT path FROM files WHERE blob_key=? ORDER BY path", (key,)).fetchall()
        return [r[0] for r in rows]

    def complete_lfs_blobs(self) -> list[str]:
        with self._lock:
            rows = self._db.execute("SELECT key FROM blobs WHERE state='complete' AND key NOT LIKE 'git-%' ORDER BY key").fetchall()
        return [r[0] for r in rows]

    def list_blocked(self) -> list[tuple[str, str]]:
        with self._lock:
            rows = self._db.execute("SELECT key, reason FROM blocked ORDER BY at").fetchall()
        return [(r["key"], r["reason"]) for r in rows]

    def set_blob_state(self, key: str, state: str) -> None:
        with self._lock, self._db:
            self._db.execute("UPDATE blobs SET state=? WHERE key=?", (state, key))

    def blob_complete(self, key: str) -> bool:
        b = self.get_blob(key)
        return b is not None and b.state == "complete" and self.blob_path(key).exists()

    def seedable(self) -> list[BlobRow]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM blobs WHERE state='complete' AND infohash IS NOT NULL"
            ).fetchall()
        return [BlobRow(**dict(r)) for r in rows]
