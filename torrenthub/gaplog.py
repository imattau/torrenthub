"""Log long pauses in a byte stream, to tell an upstream stall from a gateway one.

A client that gets no bytes for ~10s (the huggingface_hub read timeout) gives up. Two places can
cause that: upstream is slow to deliver, or the gateway holds bytes back (upstream chunk size,
`stream_holdback`). Each stream gets a `GapLog`; `tick()` is called once per chunk and any pause
over the threshold is logged on `torrenthub.gaps`, with a one-line summary when the stream ends.
"""

from __future__ import annotations

import logging
import time

log = logging.getLogger("torrenthub.gaps")


class GapLog:
    def __init__(self, label: str, warn_after: float):
        self.label, self.warn_after = label, warn_after
        self.start = self.last = time.monotonic()
        self.chunks = self.bytes = self.slow = 0
        self.max_gap = 0.0

    def tick(self, nbytes: int) -> None:
        if self.warn_after <= 0:
            return
        now = time.monotonic()
        gap = now - self.last
        self.last = now
        self.chunks += 1
        self.bytes += nbytes
        self.max_gap = max(self.max_gap, gap)
        if gap >= self.warn_after:
            self.slow += 1
            log.warning("%s: %.1fs with no data before this chunk (%d bytes, %d total)", self.label, gap, nbytes, self.bytes)

    def done(self, outcome: str = "ok") -> None:
        if self.warn_after <= 0 or not self.chunks:
            return
        level = logging.WARNING if self.slow else logging.INFO
        log.log(
            level,
            "%s: %s, %d bytes in %.0fs, %d chunks, max gap %.1fs, %d gaps >= %.0fs",
            self.label, outcome, self.bytes, time.monotonic() - self.start, self.chunks,
            self.max_gap, self.slow, self.warn_after,
        )
