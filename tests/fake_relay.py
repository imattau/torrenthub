"""A small, strict Nostr relay for tests. It follows NIP-01 where it matters to this project:

* kinds 30000 to 39999 are addressable: only the latest event per (kind, pubkey, d tag) is kept,
  and a missing d tag counts as the empty string;
* replaceable kinds keep the latest per (kind, pubkey); ephemeral kinds are not stored;
* it checks every event's id and signature;
* it can be told to enforce limits (message size, content length, tag count, accepted kinds),
  rate limit, demand NIP-42 authentication, and publish a NIP-11 document.

It exists so the adapter is tested against a relay that behaves like a strict one, not just a
lenient one.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time

from websockets.asyncio.server import serve
from websockets.http11 import Response
from websockets.datastructures import Headers

from torrenthub.signing import verify_event


class FakeRelay:
    def __init__(self, *, max_message_length=None, max_content_length=None, max_event_tags=None, kinds=None,
                 rate_limit_every=0, auth_required=False, nip11=True, port=0):
        self.max_message_length, self.max_content_length, self.max_event_tags = max_message_length, max_content_length, max_event_tags
        self.kinds, self.rate_limit_every, self.auth_required, self.serve_nip11 = kinds, rate_limit_every, auth_required, nip11
        self.events: dict[str, dict] = {}
        self.port = port
        self.received = 0
        self.rate_limited = 0
        self.log: list[str] = []
        self._loop = None
        self._thread = None
        self._stop = None
        self.url = ""

    # --------------------------------------------------------------- storage
    @staticmethod
    def _addr(ev):
        k = ev["kind"]
        d = next((t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "d"), "")
        if 30000 <= k < 40000:
            return (k, ev["pubkey"], d)
        if k in (0, 3) or 10000 <= k < 20000:
            return (k, ev["pubkey"])
        return None

    def _store(self, ev) -> str:
        if ev["id"] in self.events:
            return "duplicate: already have this event"
        a = self._addr(ev)
        if a is not None:
            for old in list(self.events.values()):
                if self._addr(old) == a:
                    new_wins = ev["created_at"] > old["created_at"] or (ev["created_at"] == old["created_at"] and ev["id"] < old["id"])
                    if not new_wins:
                        return "duplicate: have a newer event at this address"
                    del self.events[old["id"]]
        if ev["kind"] == 5:
            for t in ev["tags"]:
                if t[0] == "e" and t[1] in self.events and self.events[t[1]]["pubkey"] == ev["pubkey"]:
                    del self.events[t[1]]
        if 20000 <= ev["kind"] < 30000:
            return ""
        self.events[ev["id"]] = ev
        return ""

    @staticmethod
    def _match(ev, f) -> bool:
        if "ids" in f and ev["id"] not in f["ids"]:
            return False
        if "kinds" in f and ev["kind"] not in f["kinds"]:
            return False
        if "authors" in f and ev["pubkey"] not in f["authors"]:
            return False
        if "since" in f and ev["created_at"] < f["since"]:
            return False
        if "until" in f and ev["created_at"] > f["until"]:
            return False
        for key, vals in f.items():
            if key.startswith("#") and len(key) == 2:
                have = {t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == key[1]}
                if not have & set(vals):
                    return False
        return True

    # ------------------------------------------------------------------ wire
    async def _handler(self, ws):
        authed = not self.auth_required
        challenge = os.urandom(8).hex()
        if self.auth_required:
            await ws.send(json.dumps(["AUTH", challenge]))
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except ValueError:
                await ws.send(json.dumps(["NOTICE", "invalid: not JSON"]))
                continue
            if not isinstance(msg, list) or not msg:
                continue
            kind = msg[0]
            if kind == "AUTH":
                ev = msg[1]
                ok = (verify_event(ev) and ev.get("kind") == 22242
                      and ["challenge", challenge] in ev["tags"] and ["relay", self.url] in ev["tags"])
                authed = authed or ok
                await ws.send(json.dumps(["OK", ev.get("id"), ok, "" if ok else "invalid: bad auth"]))
            elif kind == "EVENT":
                ev = msg[1]
                self.received += 1
                self.log.append(f"EVENT {ev.get('id', '')[:8]} kind {ev.get('kind')}")
                reply = await self._on_event(ev, authed)
                await ws.send(json.dumps(["OK", ev.get("id"), reply == "", reply]))
            elif kind == "REQ":
                sub, filters = msg[1], msg[2:]
                if not authed:
                    await ws.send(json.dumps(["CLOSED", sub, "auth-required: log in first"]))
                    continue
                sent = set()
                for f in filters:
                    hits = sorted((e for e in self.events.values() if self._match(e, f)), key=lambda e: (-e["created_at"], e["id"]))
                    for e in hits[: min(int(f.get("limit", 500)), 500)]:
                        if e["id"] not in sent:
                            sent.add(e["id"])
                            await ws.send(json.dumps(["EVENT", sub, e]))
                await ws.send(json.dumps(["EOSE", sub]))
            elif kind == "CLOSE":
                pass

    async def _on_event(self, ev, authed) -> str:
        if not authed:
            return "auth-required: this relay wants you to log in"
        if self.rate_limit_every and self.received % self.rate_limit_every == 0 and self.rate_limited < 3:
            self.rate_limited += 1
            return "rate-limited: slow down"
        try:
            if not verify_event(ev):
                return "invalid: bad id or signature"
        except Exception:  # noqa: BLE001
            return "invalid: malformed event"
        if self.kinds is not None and ev["kind"] not in self.kinds and ev["kind"] != 5:
            return "blocked: this kind is not accepted here"
        if self.max_content_length and len(ev["content"]) > self.max_content_length:
            return "invalid: content is too long"
        if self.max_event_tags and len(ev["tags"]) > self.max_event_tags:
            return "invalid: too many tags"
        return self._store(ev)

    def _process_request(self, connection, request):
        if self.serve_nip11 and request.headers.get("Upgrade", "").lower() != "websocket" and "application/nostr+json" in request.headers.get("Accept", ""):
            lim = {k: v for k, v in dict(max_message_length=self.max_message_length, max_content_length=self.max_content_length,
                                         max_event_tags=self.max_event_tags, auth_required=self.auth_required).items() if v}
            body = json.dumps({"name": "fake relay", "software": "tests", "supported_nips": [1, 9, 11, 42], "limitation": lim}).encode()
            return Response(200, "OK", Headers({"Content-Type": "application/nostr+json", "Content-Length": str(len(body))}), body)
        return None

    # --------------------------------------------------------------- running
    def start(self):
        ready = threading.Event()

        def run():
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            async def main():
                self._stop = asyncio.Event()
                async with serve(self._handler, "127.0.0.1", self.port, max_size=self.max_message_length or 16 * 1024 * 1024,
                                 process_request=self._process_request, ping_interval=None) as srv:
                    self.port = srv.sockets[0].getsockname()[1]
                    self.url = f"ws://127.0.0.1:{self.port}"
                    ready.set()
                    await self._stop.wait()

            self._loop.run_until_complete(main())

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()
        assert ready.wait(10), "fake relay did not start"
        return self

    def stop(self):
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
            self._thread.join(5)
