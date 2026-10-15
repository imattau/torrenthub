#!/usr/bin/env python3
"""Download a repo through a torrenthub gateway and report where the bytes came from.

    python3 validation/measure.py --gateway http://agent:8080 --repo SOME/REPO \
        [--hub http://hub:8080] [--cache DIR] [--json out.json]

It reads /metrics from the gateway (and the hub, if given) before and after, runs an ordinary
huggingface_hub snapshot_download against the gateway, and prints:

  * the bytes the client received and the time taken
  * for the gateway: bytes it fetched from peers (swarm) and over HTTP from its upstream
  * the peer share: swarm / (swarm + upstream HTTP). This is the number that decides whether
    the whole idea saves hosting cost. A gateway that is not in agent mode will show 0.
  * how many times the swarm fell back to HTTP
  * for the hub: bytes it served over its own HTTP during the run

Needs `pip install huggingface_hub`. Use a fresh --cache for each run (default: a temp dir),
and a gateway that has not already stored the repo, or the swarm is never asked.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

LINE = re.compile(r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>[^}]*)\})?\s+(?P<value>[-+0-9.eE]+)\s*$')


def read_metrics(base: str, timeout: int = 20) -> dict[tuple[str, str], float]:
    with urllib.request.urlopen(base.rstrip("/") + "/metrics", timeout=timeout) as r:
        text = r.read().decode()
    out: dict[tuple[str, str], float] = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            out[(m["name"], m["labels"] or "")] = float(m["value"])
    return out


def delta(before, after, name: str, label_contains: str = "") -> float:
    def total(d):
        return sum(v for (n, lab), v in d.items() if n == name and label_contains in lab)
    return total(after) - total(before)


def human(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return str(n)


def dir_bytes(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())  # follows symlinks into blobs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--gateway", required=True, help="base URL of the gateway the client downloads through")
    ap.add_argument("--repo", required=True)
    ap.add_argument("--revision", default="main")
    ap.add_argument("--hub", help="base URL of the gateway's upstream hub, to measure the load on it")
    ap.add_argument("--cache", help="client cache directory (default: a temporary one, removed afterwards)")
    ap.add_argument("--json", help="write the numbers here too")
    args = ap.parse_args(argv)

    from huggingface_hub import snapshot_download

    gw0 = read_metrics(args.gateway)
    hub0 = read_metrics(args.hub) if args.hub else None
    tmp = None if args.cache else tempfile.mkdtemp(prefix="thub-measure-")
    cache = args.cache or tmp
    t0 = time.monotonic()
    try:
        path = Path(snapshot_download(args.repo, revision=args.revision, endpoint=args.gateway.rstrip("/"),
                                      cache_dir=cache, token=False))
        elapsed = time.monotonic() - t0
        received = dir_bytes(path)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    gw1 = read_metrics(args.gateway)
    hub1 = read_metrics(args.hub) if args.hub else None

    swarm = delta(gw0, gw1, "thub_bytes_fetched_total", 'source="swarm"')
    http = delta(gw0, gw1, "thub_bytes_fetched_total", 'source="upstream"')
    served = delta(gw0, gw1, "thub_bytes_served_total")
    fallbacks = delta(gw0, gw1, "thub_swarm_fallback_total")
    integrity = delta(gw0, gw1, "thub_integrity_failures_total")
    rep = {
        "repo": args.repo, "revision": args.revision, "client_received_bytes": received,
        "seconds": round(elapsed, 2), "client_MiB_per_s": round(received / 1048576 / elapsed, 2) if elapsed else None,
        "gateway_fetched_from_swarm": swarm, "gateway_fetched_over_http": http,
        "peer_share": round(swarm / (swarm + http), 4) if (swarm + http) else None,
        "gateway_served_bytes": served, "swarm_fallbacks": fallbacks, "integrity_failures": integrity,
    }
    if hub0 is not None and hub1 is not None:
        rep["hub_http_served_bytes"] = delta(hub0, hub1, "thub_bytes_served_total")
        rep["hub_fetched_from_origin_bytes"] = delta(hub0, hub1, "thub_bytes_fetched_total", 'source="upstream"')

    print(f"\n{args.repo}@{args.revision} through {args.gateway}")
    print(f"  client received      {human(received)} in {elapsed:.1f}s ({rep['client_MiB_per_s']} MiB/s)")
    print(f"  gateway from peers   {human(swarm)}")
    print(f"  gateway over HTTP    {human(http)}")
    share = rep["peer_share"]
    print(f"  peer share           {'n/a (nothing fetched: the gateway already had it?)' if share is None else f'{share:.1%}'}")
    print(f"  swarm fallbacks      {int(fallbacks)}    integrity failures {int(integrity)}")
    if "hub_http_served_bytes" in rep:
        print(f"  hub served over HTTP {human(rep['hub_http_served_bytes'])}    hub fetched from origin {human(rep['hub_fetched_from_origin_bytes'])}")
    if args.json:
        Path(args.json).write_text(json.dumps(rep, indent=1))
        print(f"  written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
