"""Storage for participant events, in their own SQLite file.

Two tiers. "main" holds events from keys the hub knows about. "quarantine" holds events from
strangers, in small amounts, for a short time, and only on request. Only main events are used
to build the trust graph, so a stranger's events cannot change any answer.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY, kind INTEGER NOT NULL, pubkey TEXT NOT NULL, created_at INTEGER NOT NULL,
  tier TEXT NOT NULL, received_at INTEGER NOT NULL, raw TEXT NOT NULL, size INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ev_kind ON events(kind, created_at);
CREATE INDEX IF NOT EXISTS ev_author ON events(pubkey, created_at);
CREATE INDEX IF NOT EXISTS ev_tier ON events(tier, received_at);
CREATE TABLE IF NOT EXISTS tags (id TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS tag_lookup ON tags(name, value);
CREATE INDEX IF NOT EXISTS tag_id ON tags(id);
"""

MAX_LIMIT = 500
FILTER_TAGS = ("e", "p", "x", "i")


class EventStore:
    def __init__(self, data_dir: Path):
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(data_dir / "events.sqlite", check_same_thread=False)
        self.lock = threading.Lock()
        self.db.executescript(SCHEMA)
        self.version = 0  # bumps when main changes, so cached graphs know to rebuild

    def add(self, ev: dict, tier: str, now: int | None = None) -> bool:
        """Store an event. False if it was already held (in either tier)."""
        raw = json.dumps(ev, separators=(",", ":"), sort_keys=True)
        with self.lock:
            if self.db.execute("SELECT 1 FROM events WHERE id=?", (ev["id"],)).fetchone():
                return False
            self.db.execute(
                "INSERT INTO events VALUES (?,?,?,?,?,?,?,?)",
                (ev["id"], ev["kind"], ev["pubkey"], ev["created_at"], tier, int(now if now is not None else time.time()), raw, len(raw)),
            )
            self.db.executemany(
                "INSERT INTO tags VALUES (?,?,?)",
                [(ev["id"], t[0], t[1]) for t in ev["tags"] if len(t) >= 2 and t[0] in FILTER_TAGS],
            )
            self.db.commit()
            if tier == "main":
                self.version += 1
        return True

    def get(self, event_id: str) -> dict | None:
        with self.lock:
            r = self.db.execute("SELECT raw FROM events WHERE id=?", (event_id,)).fetchone()
        return json.loads(r[0]) if r else None

    def tier_of(self, event_id: str) -> str | None:
        with self.lock:
            r = self.db.execute("SELECT tier FROM events WHERE id=?", (event_id,)).fetchone()
        return r[0] if r else None

    def main_events(self) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT raw FROM events WHERE tier='main' ORDER BY created_at, id").fetchall()
        return [json.loads(r[0]) for r in rows]

    def query(self, kinds=None, authors=None, tags: dict | None = None, since=None, until=None, limit=100,
              include_quarantine=False) -> list[dict]:
        where, args = [], []
        if not include_quarantine:
            where.append("e.tier='main'")
        if kinds:
            where.append(f"e.kind IN ({','.join('?' * len(kinds))})")
            args += [int(k) for k in kinds]
        if authors:
            where.append(f"e.pubkey IN ({','.join('?' * len(authors))})")
            args += list(authors)
        if since is not None:
            where.append("e.created_at>=?")
            args.append(int(since))
        if until is not None:
            where.append("e.created_at<=?")
            args.append(int(until))
        for name, values in (tags or {}).items():
            if name not in FILTER_TAGS or not values:
                continue
            where.append(f"EXISTS (SELECT 1 FROM tags t WHERE t.id=e.id AND t.name=? AND t.value IN ({','.join('?' * len(values))}))")
            args += [name, *values]
        sql = "SELECT e.raw FROM events e" + (" WHERE " + " AND ".join(where) if where else "")
        sql += " ORDER BY e.created_at DESC, e.id LIMIT ?"
        args.append(max(1, min(int(limit), MAX_LIMIT)))
        with self.lock:
            rows = self.db.execute(sql, args).fetchall()
        return [json.loads(r[0]) for r in rows]

    def quarantined_by(self, pubkey: str) -> list[dict]:
        with self.lock:
            rows = self.db.execute("SELECT raw FROM events WHERE tier='quarantine' AND pubkey=? ORDER BY created_at, id", (pubkey,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def quarantine_authors(self) -> list[str]:
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT DISTINCT pubkey FROM events WHERE tier='quarantine' ORDER BY pubkey")]

    def promote(self, event_id: str) -> None:
        with self.lock:
            self.db.execute("UPDATE events SET tier='main' WHERE id=? AND tier='quarantine'", (event_id,))
            self.db.commit()
            self.version += 1

    def count(self, pubkey: str, tier: str) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events WHERE pubkey=? AND tier=?", (pubkey, tier)).fetchone()[0]

    def usage_since(self, pubkey: str, since: int) -> tuple[int, int]:
        """(events, bytes) received from this key since a time, across both tiers."""
        with self.lock:
            r = self.db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM events WHERE pubkey=? AND received_at>=?", (pubkey, since)).fetchone()
        return r[0], r[1]

    def purge_quarantine(self, older_than: int) -> int:
        with self.lock:
            ids = [r[0] for r in self.db.execute("SELECT id FROM events WHERE tier='quarantine' AND received_at<?", (older_than,))]
            for i in ids:
                self.db.execute("DELETE FROM tags WHERE id=?", (i,))
                self.db.execute("DELETE FROM events WHERE id=?", (i,))
            self.db.commit()
        return len(ids)

    def counts(self) -> dict:
        with self.lock:
            return dict(self.db.execute("SELECT tier, COUNT(*) FROM events GROUP BY tier").fetchall())
