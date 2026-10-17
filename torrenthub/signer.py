"""A signer: the only process that holds a signing key, so an agent never does.

An agent (or the MCP server acting for it) asks the signer to do one of a few named things. The
signer decides, using limits the operator set when starting it, and writes every decision to an
audit log. It does not sign arbitrary events. For checks anyone can redo (hash_verified,
format_scan, replication) the signer does the check itself on a file it is pointed at, so a
confused or hostile agent cannot get a false result signed.

Limits (all set by the operator, not the agent):
  * which operations and claims are allowed
  * events per hour and per day (counted again from the audit log after a restart)
  * a time after which it signs nothing
  * files it will read must be under one folder (read_root), and under a size cap

It listens on a Unix socket made readable only by its user. Anything that can reach the socket
can use whatever the limits allow. It does not protect against code running as the same user
that can read the key file itself. Put the key where only the signer reads it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from . import events as E
from . import verifier as V
from .signing import backend, public_key

MAX_LINE = 256 * 1024
DEFAULT_CLAIMS = ("hash_verified", "format_scan", "replication")


log = logging.getLogger("torrenthub.signer")


@dataclass
class SignerConfig:
    read_root: Path
    audit_path: Path
    allowed_ops: tuple = ("attest_file", "replicate")
    allowed_claims: tuple = DEFAULT_CLAIMS
    max_per_hour: int = 60
    max_per_day: int = 500
    not_after: int | None = None
    max_file_bytes: int = 50 * 1024**3


class Signer:
    def __init__(self, secret: bytes, config: SignerConfig, clock=time.time):
        self.secret = secret
        self.cfg = config
        self.clock = clock
        self.pubkey = public_key(secret).hex()
        if backend() != "libsecp256k1":
            log.warning("signing with the pure Python backend, whose running time depends on the secret key. "
                        "A client that can time this signer's answers could learn about the key. "
                        "Install the fast backend: pip install 'torrenthub[fast]'")
        self.cfg.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self.signed: deque[float] = deque()
        self._reload_counts()

    # ------------------------------------------------------------------ audit
    def _reload_counts(self) -> None:
        now = self.clock()
        if not self.cfg.audit_path.exists():
            return
        for line in self.cfg.audit_path.read_text().splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("decision") == "signed" and now - rec.get("t", 0) < 86400:
                self.signed.append(rec["t"])

    def _audit(self, op: str, decision: str, reason: str, request: dict, event_ids: list[str] | None = None) -> None:
        safe = {}
        for k, v in request.items():
            if k == "event":
                v = {"id": v.get("id")} if isinstance(v, dict) else str(v)[:80]
            elif isinstance(v, (str, list, dict)) and len(json.dumps(v)) > 2000:
                v = str(v)[:200] + "..."  # an agent cannot make the log grow by sending big requests
            safe[k] = v
        rec = {"t": self.clock(), "op": op, "decision": decision, "reason": reason, "request": safe, "events": event_ids or []}
        with open(self.cfg.audit_path, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")

    # ----------------------------------------------------------------- handle
    def handle(self, req: dict) -> dict:
        op = req.get("op") if isinstance(req, dict) else None
        if op == "pubkey":
            return {"ok": True, "pubkey": self.pubkey, "crypto": backend()}
        try:
            events = self._decide(op, req)
        except Refused as r:
            self._audit(str(op), "refused", str(r), req if isinstance(req, dict) else {})
            return {"ok": False, "error": str(r)}
        now = self.clock()
        for _ in events:
            self.signed.append(now)
        self._audit(op, "signed", "", req, [e["id"] for e in events])
        return {"ok": True, "events": events}

    def _decide(self, op, req) -> list[dict]:
        if not isinstance(req, dict) or op not in self.cfg.allowed_ops:
            raise Refused(f"operation {op!r} is not allowed")
        now = self.clock()
        if self.cfg.not_after is not None and now >= self.cfg.not_after:
            raise Refused("this signer's authority has expired")
        while self.signed and now - self.signed[0] >= 86400:
            self.signed.popleft()
        hour = sum(1 for t in self.signed if now - t < 3600)
        if hour >= self.cfg.max_per_hour or len(self.signed) >= self.cfg.max_per_day:
            raise Refused("rate limit reached")
        path = self._readable(req.get("path"))
        names = req.get("filenames")
        if not isinstance(names, list) or not all(isinstance(n, str) and len(n) < 300 for n in names) or len(names) > 20:
            raise Refused("filenames must be a short list of strings")
        if op == "attest_file":
            x = req.get("sha256")
            if not isinstance(x, str) or not E.HEX64.match(x):
                raise Refused("sha256 must be 64 lowercase hex characters")
            evs = V.attest_file_events(self.secret, path, x, names, int(now))
            evs = [e for e in evs if self._claim_of(e) in self.cfg.allowed_claims]
        else:
            ev = req.get("event")
            if not isinstance(ev, dict):
                raise Refused("replicate needs the attestation event")
            if "replication" not in self.cfg.allowed_claims:
                raise Refused("replication claims are not allowed")
            out = V.replicate_event(self.secret, ev, path, names, int(now))
            if out is None:
                raise Refused("that attestation cannot be redone from this file")
            evs = [out]
        if not evs:
            raise Refused("nothing to sign under the allowed claims")
        if hour + len(evs) > self.cfg.max_per_hour or len(self.signed) + len(evs) > self.cfg.max_per_day:
            raise Refused("rate limit reached")
        return evs

    @staticmethod
    def _claim_of(ev: dict) -> str:
        return E.parse_event(ev).claim

    def _readable(self, p) -> Path:
        if not isinstance(p, str) or "\0" in p or not p:
            raise Refused("path is required")
        root = Path(self.cfg.read_root).resolve()
        path = Path(p).resolve()
        if root != path and root not in path.parents:
            raise Refused("that file is outside the folder this signer may read")
        if not path.is_file():
            raise Refused("no such file")
        if path.stat().st_size > self.cfg.max_file_bytes:
            raise Refused("file is larger than this signer will read")
        return path


class Refused(Exception):
    pass


# --------------------------------------------------------------------- server

# The most a Unix socket path can hold: 108 bytes on Linux, 104 on macOS and the BSDs (one of them is the final NUL).
MAX_SOCKET_PATH = 103 if sys.platform != "linux" else 107


async def serve(signer: Signer, socket_path: str):
    if len(os.fsencode(socket_path)) > MAX_SOCKET_PATH:
        raise ValueError(f"the socket path is {len(os.fsencode(socket_path))} bytes and this system allows {MAX_SOCKET_PATH}: "
                         f"use a shorter path, such as /tmp/thub-signer.sock or one under $XDG_RUNTIME_DIR")
    path = Path(socket_path)
    if path.exists():
        path.unlink()
    old = os.umask(0o177)
    try:
        server = await asyncio.start_unix_server(lambda r, w: _client(signer, r, w), path=str(path), limit=MAX_LINE)
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    return server


async def _client(signer: Signer, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            try:
                line = await reader.readline()
            except (asyncio.LimitOverrunError, ValueError):
                writer.write(b'{"ok":false,"error":"request too large"}\n')
                break
            if not line:
                break
            try:
                req = json.loads(line)
            except ValueError:
                resp = {"ok": False, "error": "not JSON"}
            else:
                resp = await asyncio.get_running_loop().run_in_executor(None, signer.handle, req)
            writer.write(json.dumps(resp).encode() + b"\n")
            await writer.drain()
    finally:
        writer.close()


class SignerClient:
    """Blocking client. Run it in a thread from async code."""

    def __init__(self, socket_path: str, timeout: float = 600.0):
        self.path, self.timeout = socket_path, timeout

    def request(self, req: dict) -> dict:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(self.timeout)
            s.connect(self.path)
            s.sendall(json.dumps(req).encode() + b"\n")
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        if not buf:
            return {"ok": False, "error": "signer closed the connection"}
        return json.loads(buf)
