from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .app import create_app
from .cli_events import EVENT_COMMANDS, add_event_commands, run_event_command
from .config import Settings
from .mirror import Mirror
from .store import Store
from .swarm import make_swarm
from .upstream import make_upstream


def _mirror(settings: Settings) -> Mirror:
    return Mirror(
        settings,
        Store(settings.data_dir),
        make_upstream(settings),
        make_swarm(settings.swarm, settings.listen_port, settings.peers, settings.outgoing_utp),
    )


def _version() -> str:
    from importlib import metadata

    try:
        return metadata.version("torrenthub")
    except metadata.PackageNotFoundError:
        return "unknown (not installed)"


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="torrenthub")
    p.add_argument("--version", action="version", version=f"torrenthub {_version()}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the HF-compatible gateway")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])

    dr = sub.add_parser("doctor", help="check this machine and the settings (THUB_*) for running a hub; exit 1 if something is wrong")
    dr.add_argument("--probe", action="store_true", help="also ask the running hub at THUB_PUBLIC_URL what it believes, and try its swarm port")

    m = sub.add_parser("mirror", help="mirror a repo (all files) and build torrents")
    m.add_argument("repo_id")
    m.add_argument("--revision", default="main")

    e = sub.add_parser("evict", help="drop blob bytes but keep the torrent (swarm refills later)")
    e.add_argument("key")

    sub.add_parser("gc", help="evict least recently used torrented blobs until under THUB_MAX_DISK")

    bl = sub.add_parser("block", help="takedown: remove a blob's bytes and torrent and refuse to serve it")
    bl.add_argument("key", help="blob key (the LFS sha256)")
    bl.add_argument("--reason", default="takedown")

    lk = sub.add_parser("lock", help="record a repo revision's file table in THUB_LOCKFILE")
    lk.add_argument("repo_id")
    lk.add_argument("--revision", default="main")

    sub.add_parser("locked", help="list commits in THUB_LOCKFILE")

    mc = sub.add_parser("mcp", help="run an MCP server (stdio) that lets an AI agent use a gateway")
    mc.add_argument("--gateway", default="http://127.0.0.1:8080")
    mc.add_argument("--download-root", default="./downloads")
    mc.add_argument("--max-gib", type=float, default=20.0)
    mc.add_argument("--signer", help="Unix socket of a running signer. Adds the attest_file tool")

    sub.add_parser("keygen", help="make a signing key pair and print it (nothing is saved)")

    sg = sub.add_parser("sign", help="sign a repo revision's file table and keep the manifest here")
    sg.add_argument("repo_id")
    sg.add_argument("--revision", default="main")
    sg.add_argument("--ref", action="append", help="branch name this commit is for (default: the revision, if it is a name)")
    sg.add_argument("--key-file", help="file holding the secret key (hex or nsec). Otherwise THUB_SIGNING_KEY")

    ml = sub.add_parser("manifests", help="list signed manifests held for a repo")
    ml.add_argument("repo_id")

    ma = sub.add_parser("manifest-add", help="import a signed manifest file, after checking it against --key")
    ma.add_argument("file")
    ma.add_argument("--key", action="append", required=True, help="trusted public key (hex or npub), repeatable")
    add_event_commands(sub)
    sub.add_parser("blocked", help="list blocked blobs")
    sub.add_parser("list", help="list known blobs")

    args = p.parse_args(argv)
    settings = Settings.from_env()

    if args.cmd == "doctor":
        from .doctor import run as run_doctor

        checks = run_doctor(settings, probe=args.probe)
        for c in checks:
            print(c.line())
        bad = sum(c.level == "fail" for c in checks)
        warn = sum(c.level == "warn" for c in checks)
        print(f"{len(checks)} checks: {bad} failed, {warn} warnings")
        raise SystemExit(1 if bad else 0)
    if args.cmd == "serve":
        import logging

        import uvicorn

        from .doctor import run as run_doctor

        logging.basicConfig(level=getattr(logging, args.log_level.upper()), format="%(asctime)s %(levelname)s %(name)s %(message)s")
        for c in run_doctor(settings):
            if c.level != "ok":
                logging.getLogger("torrenthub.doctor").warning("%s", c.line())
        uvicorn.run(create_app(settings), host=args.host, port=args.port, log_level=args.log_level)
    elif args.cmd == "mirror":
        mirror = _mirror(settings)

        async def run():
            try:
                commit, files = await mirror.mirror_repo(args.repo_id, args.revision)
            finally:
                await mirror.upstream.aclose()
            print(json.dumps({"repo": args.repo_id, "commit": commit, "files": len(files)}))

        asyncio.run(run())
    elif args.cmd == "evict":
        print("evicted" if asyncio.run(_mirror(settings).evict(args.key)) else "nothing to evict")
    elif args.cmd == "gc":
        evicted = asyncio.run(_mirror(settings).gc())
        print(json.dumps({"evicted": evicted}))
    elif args.cmd == "block":
        asyncio.run(_mirror(settings).block(args.key, args.reason))
        print("blocked", args.key)
    elif args.cmd == "lock":
        if not settings.lockfile:
            p.error("set THUB_LOCKFILE")
        from .lock import Lockfile
        from .upstream import HubError

        async def lock_it():
            up = make_upstream(settings)
            try:
                if hasattr(up, "model_info_ex"):
                    info, source = await up.model_info_ex(args.repo_id, args.revision)
                else:
                    info, source = await up.model_info(args.repo_id, args.revision), "upstream"
            finally:
                await up.aclose()
            return info, source

        try:
            info, source = asyncio.run(lock_it())
            added = Lockfile(settings.lockfile, settings.lock_mode).add(args.repo_id, info)
        except HubError as e:
            raise SystemExit(f"{e.code}: {e.message}")
        print(json.dumps({"repo": args.repo_id, "commit": info["sha"], "recorded": added, "source": source}))
    elif args.cmd == "mcp":
        import logging

        from .mcp_server import build_server

        logging.getLogger("httpx").setLevel(logging.WARNING)  # stderr is read by MCP clients, keep it quiet

        build_server(args.gateway, Path(args.download_root), int(args.max_gib * 1024**3), signer=args.signer).run("stdio")
    elif args.cmd == "keygen":
        import os

        from .signing import bech32_encode, public_key

        while True:
            sk = os.urandom(32)
            try:
                pk = public_key(sk)
                break
            except ValueError:
                continue
        print(json.dumps({"nsec": bech32_encode("nsec", sk), "npub": bech32_encode("npub", pk), "pubkey_hex": pk.hex()}, indent=1))
    elif args.cmd == "sign":
        import os
        import re as _re

        from .manifest import build_manifest
        from .signing import parse_secret
        from .upstream import HubError

        raw = Path(args.key_file).read_text() if args.key_file else os.environ.get("THUB_SIGNING_KEY", "")
        if not raw.strip():
            p.error("give --key-file or set THUB_SIGNING_KEY")
        refs = args.ref or ([] if _re.fullmatch(r"[0-9a-f]{40}", args.revision) else [args.revision])

        async def get_info():
            up = make_upstream(settings)
            try:
                return await up.model_info(args.repo_id, args.revision)
            finally:
                await up.aclose()

        try:
            info = asyncio.run(get_info())
            ev = build_manifest(parse_secret(raw), args.repo_id, info, refs)
        except (HubError, ValueError) as e:
            raise SystemExit(f"cannot sign: {getattr(e, 'message', e)}")
        Store(settings.data_dir).add_manifest(ev)
        print(json.dumps({"repo": args.repo_id, "commit": info["sha"], "refs": refs, "files": len(info.get("siblings", [])),
                          "event_id": ev["id"], "pubkey": ev["pubkey"]}))
    elif args.cmd == "manifests":
        from .manifest import ManifestInvalid, verify_manifest

        for ev in Store(settings.data_dir).list_manifests(args.repo_id):
            try:
                m = verify_manifest(ev, {ev.get("pubkey")}, args.repo_id)
                print(m.id[:16], m.pubkey[:16], m.commit[:12], ",".join(m.refs) or "-", m.created_at, len(m.rows), "files")
            except ManifestInvalid as e:
                print(ev.get("id", "?")[:16], "INVALID", e)
    elif args.cmd == "manifest-add":
        from .manifest import ManifestInvalid, verify_manifest
        from .signing import parse_pubkey

        ev = json.loads(Path(args.file).read_text())
        repo = next((t[1] for t in ev.get("tags", []) if len(t) >= 2 and t[0] == "repo"), "")
        try:
            m = verify_manifest(ev, {parse_pubkey(k) for k in args.key}, repo)
        except (ManifestInvalid, ValueError) as e:
            raise SystemExit(f"rejected: {e}")
        print(json.dumps({"repo": repo, "commit": m.commit, "added": Store(settings.data_dir).add_manifest(ev)}))
    elif args.cmd in EVENT_COMMANDS:
        run_event_command(args, settings, p)
    elif args.cmd == "locked":
        if not settings.lockfile:
            p.error("set THUB_LOCKFILE")
        from .lock import Lockfile

        for key, rows in Lockfile(settings.lockfile).entries.items():
            print(key, len(rows), "files")
    elif args.cmd == "blocked":
        for key, reason in Store(settings.data_dir).list_blocked():
            print(key, reason)
    elif args.cmd == "list":
        store = Store(settings.data_dir)
        for b in store.seedable():
            print(b.key, b.size, b.infohash, b.state)


if __name__ == "__main__":
    main()
