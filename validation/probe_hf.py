#!/usr/bin/env python3
"""Check the assumptions torrenthub makes about a Hugging Face compatible origin.

Standard library only, so it runs anywhere Python 3.9+ does. It talks to the origin directly and
never to a torrenthub gateway.

    python3 validation/probe_hf.py --repo SOME/REPO [--repo OTHER/REPO] [--max-mb 100] [--json out.json]
    python3 validation/probe_hf.py --endpoint http://127.0.0.1:9999 --repo acme/tiny   # any HF compatible server

For each repo it downloads one file (the smallest large file under --max-mb, otherwise the
smallest file) and checks the things the mirror relies on:

  R1  the model info API answers 200 with a file list
  R2  every file has a size, large files have lfs.sha256, small ones have a blobId
  R3  the commit sha is 40 hex characters
  R4  GET /resolve/<commit>/<file>, following redirects, returns 200 and the advertised size
  R5  the sha256 of the bytes equals lfs.sha256 (or the git blob id matches, for plain files)

and records, for information, the redirect hops, interesting headers (X-Linked-Etag, X-Xet-Hash,
...), and whether Range requests work. A failed R-check means torrenthub would reject or
mis-serve that repo. The most interesting case is a Xet-backed repo: pick a recently created one.

Public repos only. No token is read or sent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "torrenthub-probe/0.1"
INTERESTING = (
    "etag", "x-linked-etag", "x-linked-size", "x-repo-commit", "x-xet-hash", "x-xet-refresh-route",
    "content-length", "content-type", "accept-ranges", "link", "location", "x-cache", "server", "via",
)


class Hops(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.hops: list[dict] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops.append({"status": code, "from": req.full_url, "to": newurl, "headers": pick(headers)})
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def pick(headers) -> dict:
    return {k: v for k, v in ((k.lower(), v) for k, v in headers.items()) if k in INTERESTING}


def host(url: str) -> str:
    return urllib.parse.urlparse(url).netloc


def get_json(url: str, timeout: int):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.load(r), pick(r.headers)


def git_blob_sha1(data_len: int, hasher_feed):
    h = hashlib.sha1(b"blob %d\0" % data_len)
    hasher_feed(h)
    return h.hexdigest()


def download(url: str, timeout: int, headers: dict | None = None):
    hops = Hops()
    opener = urllib.request.build_opener(hops)
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    resp = opener.open(req, timeout=timeout)
    return resp, hops.hops


def probe_repo(endpoint: str, repo: str, revision: str, max_bytes: int, timeout: int) -> dict:
    out: dict = {"repo": repo, "endpoint": endpoint, "checks": {}, "info": {}}
    checks = out["checks"]

    def check(name: str, ok: bool | None, note: str = ""):
        checks[name] = {"ok": ok, "note": note}

    api = f"{endpoint}/api/models/{repo}/revision/{urllib.parse.quote(revision, safe='')}?blobs=true"
    try:
        status, doc, hdrs = get_json(api, timeout)
    except urllib.error.HTTPError as e:
        check("R1 model info answers 200", False, f"HTTP {e.code}")
        return out
    except Exception as e:  # noqa: BLE001
        check("R1 model info answers 200", False, f"{type(e).__name__}: {e}")
        return out
    check("R1 model info answers 200", status == 200 and isinstance(doc.get("siblings"), list), f"status {status}")
    out["info"]["api_headers"] = hdrs
    sib = doc.get("siblings") or []
    commit = doc.get("sha", "")
    check("R3 commit sha is 40 hex", bool(re.fullmatch(r"[0-9a-f]{40}", str(commit))), str(commit))

    lfs = [s for s in sib if s.get("lfs")]
    bad_size = [s["rfilename"] for s in sib if not isinstance(s.get("size"), int) and not (s.get("lfs") or {}).get("size")]
    bad_lfs = [s["rfilename"] for s in lfs if not re.fullmatch(r"[0-9a-f]{64}", str(s["lfs"].get("sha256", "")))]
    bad_blob = [s["rfilename"] for s in sib if not s.get("lfs") and not re.fullmatch(r"[0-9a-f]{40}", str(s.get("blobId", "")))]
    out["info"].update(files=len(sib), lfs_files=len(lfs), lfs_bytes=sum(int(s["lfs"].get("size", 0)) for s in lfs))
    check("R2 sizes, lfs.sha256 and blobId present", not (bad_size or bad_lfs or bad_blob),
          f"missing size: {bad_size[:3]}, bad lfs.sha256: {bad_lfs[:3]}, missing blobId: {bad_blob[:3]}")

    def size_of(s):
        return int((s.get("lfs") or {}).get("size") or s.get("size") or 0)

    pool = [s for s in lfs if 0 < size_of(s) <= max_bytes] or [s for s in sib if 0 < size_of(s) <= max_bytes]
    if not pool:
        check("R4 resolve returns the advertised bytes", None, f"no file under {max_bytes} bytes to test")
        check("R5 hash matches", None, "skipped")
        return out
    target = min(pool, key=size_of)
    name, expect_size = target["rfilename"], size_of(target)
    out["info"]["tested_file"] = {"path": name, "size": expect_size, "lfs": bool(target.get("lfs"))}

    url = f"{endpoint}/{repo}/resolve/{commit}/{urllib.parse.quote(name)}"
    t0 = time.monotonic()
    try:
        resp, hops = download(url, timeout)
        sha, n = hashlib.sha256(), 0
        sha1 = hashlib.sha1(b"blob %d\0" % expect_size)
        with resp:
            final_headers = pick(resp.headers)
            while chunk := resp.read(1 << 20):
                sha.update(chunk)
                sha1.update(chunk)
                n += len(chunk)
            final_status, final_url = resp.status, resp.url
    except Exception as e:  # noqa: BLE001
        check("R4 resolve returns the advertised bytes", False, f"{type(e).__name__}: {e}")
        return out
    elapsed = time.monotonic() - t0
    out["info"].update(redirect_hops=hops, final_host=host(final_url), final_headers=final_headers,
                       download_seconds=round(elapsed, 2))
    check("R4 resolve returns the advertised bytes", final_status == 200 and n == expect_size,
          f"status {final_status}, got {n} bytes, advertised {expect_size}")
    if target.get("lfs"):
        want = target["lfs"]["sha256"]
        check("R5 hash matches", sha.hexdigest() == want, f"sha256 {sha.hexdigest()[:16]} vs advertised {want[:16]}")
    else:
        want = target.get("blobId", "")
        check("R5 hash matches", sha1.hexdigest() == want, f"git blob {sha1.hexdigest()[:16]} vs advertised {want[:16]}")

    # information only: headers on the first hop, and Range support
    try:
        first = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            r0 = urllib.request.build_opener(NoRedirect).open(first, timeout=timeout)
            out["info"]["head_first_hop"] = {"status": r0.status, "headers": pick(r0.headers)}
        except urllib.error.HTTPError as e:  # a 302 arrives here
            out["info"]["head_first_hop"] = {"status": e.code, "headers": pick(e.headers)}
    except Exception as e:  # noqa: BLE001
        out["info"]["head_first_hop"] = {"error": f"{type(e).__name__}: {e}"}
    try:
        resp, _ = download(url, timeout, {"Range": "bytes=0-99"})
        with resp:
            body = resp.read(200)
            out["info"]["range"] = {"status": resp.status, "bytes": len(body), "content_range": resp.headers.get("Content-Range")}
    except Exception as e:  # noqa: BLE001
        out["info"]["range"] = {"error": f"{type(e).__name__}: {e}"}
    xet = any("xet" in k for k in list(final_headers) + list((out["info"].get("head_first_hop") or {}).get("headers", {})))
    xet = xet or any("xet" in h.get("to", "") or "xet" in host(h.get("to", "")) for h in hops)
    out["info"]["looks_xet_backed"] = xet
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--endpoint", default="https://huggingface.co")
    ap.add_argument("--repo", action="append", required=True)
    ap.add_argument("--revision", default="main")
    ap.add_argument("--max-mb", type=float, default=100, help="largest file to download for the check")
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--json", help="also write the full report here")
    args = ap.parse_args(argv)

    reports = [probe_repo(args.endpoint.rstrip("/"), r, args.revision, int(args.max_mb * 1024 * 1024), args.timeout)
               for r in args.repo]
    failed = False
    for rep in reports:
        print(f"\n{rep['repo']}  ({rep['endpoint']})")
        for name, c in rep["checks"].items():
            mark = {True: "PASS", False: "FAIL", None: "SKIP"}[c["ok"]]
            failed |= c["ok"] is False
            print(f"  {mark}  {name}  {c['note']}")
        i = rep["info"]
        if "tested_file" in i:
            tf = i["tested_file"]
            print(f"  info  tested {tf['path']} ({tf['size']} bytes, {'LFS' if tf['lfs'] else 'plain'}), "
                  f"{len(i.get('redirect_hops', []))} redirect(s), final host {i.get('final_host')}")
            print(f"  info  looks Xet backed: {i.get('looks_xet_backed')}")
            print(f"  info  Range: {i.get('range')}")
            hop = i.get('head_first_hop') or {}
            print(f"  info  first hop: HTTP {hop.get('status')} {hop.get('headers') or hop.get('error')}")
    if args.json:
        with open(args.json, "w") as f:
            json.dump(reports, f, indent=1)
        print(f"\nfull report written to {args.json}")
    print("\nRESULT:", "at least one required check FAILED" if failed else "all required checks passed (SKIP means not tested)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
