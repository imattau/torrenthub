"""A lockfile of commits and the file tables they had when you first saw them.

It does not depend on any hub or on the origin staying honest later. Once a commit is in the
lockfile, any upstream that reports that commit with a different file table is refused.

Modes (THUB_LOCK_MODE):
  verify  a commit that is in the lockfile must match it. Unknown commits pass.
  record  as verify, and unknown commits are added to the lockfile.
  strict  as verify, and a commit that is not in the lockfile is refused.

This cannot help the first time a commit is seen. Record it from a source you trust (see the
`lock` command, which uses the origin anchor when one is set).
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .federation import fingerprint
from .upstream import HubError

MODES = ("verify", "record", "strict")


def _rows(info: dict) -> list[list]:
    return [list(r) for r in fingerprint(info)]


class Lockfile:
    def __init__(self, path: Path, mode: str = "verify"):
        if mode not in MODES:
            raise ValueError(f"lock mode must be one of {MODES}, not {mode!r}")
        self.path = Path(path)
        self.mode = mode
        self._lock = threading.Lock()
        self.entries: dict[str, list[list]] = {}
        if self.path.exists():
            data = json.loads(self.path.read_text())
            if data.get("version") != 1:
                raise ValueError(f"{self.path}: unsupported lockfile version {data.get('version')!r}")
            self.entries = data["commits"]

    @staticmethod
    def _key(repo_id: str, commit: str) -> str:
        return f"{repo_id}@{commit}"

    def check(self, repo_id: str, info: dict, record_unknown: bool = False) -> bool:
        """Raise HubError if `info` breaks the lockfile. Returns True if it was recorded now.
        `record_unknown` records a new commit even in verify mode: used for file tables that
        no anchor vouched for, so the first answer is at least pinned."""
        commit = info.get("sha")
        if not isinstance(commit, str):
            raise HubError(502, "LockMismatch", f"{repo_id}: upstream gave no commit sha")
        key = self._key(repo_id, commit)
        rows = _rows(info)
        with self._lock:
            known = self.entries.get(key)
            if known is not None:
                if known != rows:
                    raise HubError(502, "LockMismatch", f"{key} differs from the lockfile")
                return False
            if self.mode == "strict":
                raise HubError(403, "NotLocked", f"{key} is not in the lockfile")
            if self.mode == "record" or record_unknown:
                self.entries[key] = rows
                self._save()
                return True
            return False

    def add(self, repo_id: str, info: dict) -> bool:
        """Record a commit regardless of mode. Refuses to change an existing entry."""
        key = self._key(repo_id, info["sha"])
        rows = _rows(info)
        with self._lock:
            known = self.entries.get(key)
            if known is not None and known != rows:
                raise HubError(502, "LockMismatch", f"{key} differs from the lockfile")
            if known is not None:
                return False
            self.entries[key] = rows
            self._save()
            return True

    def _save(self) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps({"version": 1, "commits": dict(sorted(self.entries.items()))}, indent=1) + "\n")
        os.replace(tmp, self.path)
