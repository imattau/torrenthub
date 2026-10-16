"""Command line for participant events: make them, add them here, pull them from a hub, ask about trust."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

EVENT_COMMANDS = {"identity", "delegate", "endorse", "revoke", "derive", "lineage", "publish", "host", "filter", "git-init", "pull-files", "verify-git", "seed", "request", "requests", "work", "relay-info", "relay-check", "relay-push", "relay-pull", "events-add", "events-pull", "events-sync", "events", "trust",
                  "verify-blobs", "replicate", "signer", "verdict"}


def _key_args(sp):
    sp.add_argument("--key-file", help="file holding the secret key (hex or nsec). Otherwise THUB_SIGNING_KEY")
    sp.add_argument("--out", help="write the event to this file instead of printing it")


def add_event_commands(sub) -> None:
    sp = sub.add_parser("identity", help="make an identity event for your key")
    _key_args(sp)
    sp.add_argument("--label", default="unspecified", choices=["human", "agent", "org", "unspecified"])
    sp.add_argument("--recovery", help="public key (hex or npub) that may later replace this key")
    sp.add_argument("--note", default="")

    sp = sub.add_parser("delegate", help="let another key act for you (a statement of authority, not an opinion)")
    _key_args(sp)
    sp.add_argument("--subject", required=True, help="public key to authorise")
    sp.add_argument("--scope", action="append", required=True, help="e.g. publish:acme/*, repeatable")
    sp.add_argument("--expires-in", type=int, help="seconds from now")
    sp.add_argument("--redelegable", action="store_true", help="the subject may delegate onward")
    sp.add_argument("--max-events-per-day", type=int)
    sp.add_argument("--max-bytes-per-day", type=int)

    sp = sub.add_parser("endorse", help="say you trust a key for some scopes (an opinion, weighed)")
    _key_args(sp)
    sp.add_argument("--subject", required=True)
    sp.add_argument("--scope", action="append", required=True)
    sp.add_argument("--weight", type=float, required=True, help="above 0, up to 1")
    sp.add_argument("--delegable", action="store_true", help="the subject's own endorsements count onward")
    sp.add_argument("--expires-in", type=int)

    sp = sub.add_parser("revoke", help="revoke an event, a key or a blob")
    _key_args(sp)
    sp.add_argument("--kind", required=True, choices=["event", "key", "x"])
    sp.add_argument("--target", required=True, help="event id, public key (hex or npub), or sha256")
    sp.add_argument("--reason", default="")
    sp.add_argument("--taint", action="store_true", help="things derived from a revoked blob are affected too")
    sp.add_argument("--successor", help="with --kind key: rotate to this key, which inherits the old key's incoming trust")

    sp = sub.add_parser("derive", help="say that some blobs were made from others by a tool (a claim, class S unless the tool is on a trusted list)")
    _key_args(sp)
    sp.add_argument("--input", action="append", required=True, metavar="SHA256")
    sp.add_argument("--output", action="append", required=True, metavar="SHA256[:SIZE[:INFOHASH]]")
    sp.add_argument("--tool", required=True, help="tool name and version, for example safetensors-bf16@1")
    sp.add_argument("--tool-x", help="sha256 of the tool or its container image")
    sp.add_argument("--args", default="{}", help="JSON object of the tool's arguments")
    sp.add_argument("--origin", default="unknown", choices=["human", "synthetic", "mixed", "unknown"])
    sp.add_argument("--depth", type=int, default=0, help="generations of synthetic data behind the output")
    sp.add_argument("--licence-out", default="")

    sp = sub.add_parser("publish", help="publish a directory as a signed repo on a hub; works from behind NAT (the hub never connects to you)")
    _key_args(sp)
    sp.add_argument("--repo", required=True, help="owner/name")
    sp.add_argument("--dir", help="a folder of files (a snapshot, no history)")
    sp.add_argument("--git", metavar="DIR", help="a git repository: publish one commit, with its history. Big files are LFS pointers in the tree; their bytes are found in the working tree or git-lfs's cache")
    sp.add_argument("--commit", default="HEAD", help="with --git: the commit to publish (default HEAD)")
    sp.add_argument("--files-from", action="append", default=[], metavar="DIR", help="with --git: another folder to look in for big files (by path or by sha256)")
    sp.add_argument("--force", action="store_true", help="with --git: say the branch is meant to be rewritten (the hub must allow it)")
    sp.add_argument("--hub", required=True, help="base URL of a hub that takes publications")
    sp.add_argument("--ref", action="append", help="branch name the manifest claims (default main)")
    sp.add_argument("--seq", default="auto", help="the manifest counter; auto asks the hub for the next one")
    sp.add_argument("--valid-days", type=float, help="stop believing this manifest after this many days")
    sp.add_argument("--stage", help="folder for the staged big files (default: a temporary one next to the data dir)")
    sp.add_argument("--timeout", type=float, default=3600)
    sp.add_argument("--tracker", action="append", default=[])

    sp = sub.add_parser("host", help="serve a repo straight from a git repository on this machine, signed with your key")
    _key_args(sp)
    sp.add_argument("--git", required=True, metavar="DIR", help="the git repository (its working tree or git-lfs cache holds the big files)")
    sp.add_argument("--repo", required=True, help="owner/name under which it is served")
    sp.add_argument("--public-url", required=True, help="the address other machines reach this host at, such as http://host.example:8080")
    sp.add_argument("--branch", action="append", help="branch to serve (repeatable; default main)")
    sp.add_argument("--files-from", action="append", default=[], metavar="DIR", help="another folder to look in for big files (by path or by sha256)")
    sp.add_argument("--poll", type=float, default=10.0, help="seconds between looks at the branches and at the served files")
    sp.add_argument("--valid-days", type=float, help="manifests stop being believed after this long; the host signs again at half of it")
    sp.add_argument("--bind", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8080)
    sp.add_argument("--listen-port", type=int, default=6881, help="swarm port")

    sp = sub.add_parser("filter", help="the git filter for big files (run by git, not by hand): clean turns a file into a pointer, smudge turns it back")
    sp.add_argument("mode", choices=["clean", "smudge"])
    sp.add_argument("path", nargs="?", help="the file's name (git passes it; unused)")

    sp = sub.add_parser("git-init", help="set up the big-file filter in this git repository and write .gitattributes, so git add makes pointers without git-lfs")
    sp.add_argument("--pattern", action="append", help="file pattern to treat as big (repeatable; default: common model formats)")
    sp.add_argument("--dir", default=".")
    sp.add_argument("--lfs", action="store_true", help="write git-lfs's attributes instead and use stock git-lfs (install it with git lfs install); hubs then serve the files to a plain git clone")

    sp = sub.add_parser("verify-git", help="check a clone made with stock git against the signed manifests of the owner's key (stock git trusts the hub; this does not)")
    sp.add_argument("--dir", default=".")
    sp.add_argument("--signer", action="append", default=[], help="the owner's public key (hex or npub), repeatable; also thub.signer and THUB_SIGNERS")
    sp.add_argument("--hub", help="URL of the repo on the hub (default: remote.origin.url)")

    sp = sub.add_parser("seed", help="share what this clone has fetched (big files and history packs) with other clones over BitTorrent")
    sp.add_argument("--dir", default=".")
    sp.add_argument("--listen-port", type=int, default=6881)
    sp.add_argument("--seconds", type=float, help="stop after this long (default: until interrupted)")
    sp.add_argument("--once", action="store_true", help="start seeding, report, and exit (for scripts and tests)")

    sp = sub.add_parser("pull-files", help="replace the pointer files in this working tree by the files they name, fetched from the hub of a thub remote")
    sp.add_argument("--dir", default=".")
    sp.add_argument("--hub", action="append", help="hub URL to fetch from (default: thub.hub and the thub remotes)")

    sp = sub.add_parser("request", help="ask for work and wait for an answer you trust (judged by THUB_ROOTS, not by the hub)")
    _key_args(sp)
    sp.add_argument("--hub", required=True)
    sp.add_argument("--task", required=True, help="for example hash_verified or format_scan")
    sp.add_argument("--input", action="append", default=[], metavar="SHA256")
    sp.add_argument("--filename", action="append", help="file name hint, so a worker knows which scanner applies")
    sp.add_argument("--want", default="attestation", choices=list(("attestation", "artifact")))
    sp.add_argument("--deadline-in", type=float, default=600, help="seconds from now")
    sp.add_argument("--independent", type=int, default=1, help="how many independent trusted workers must agree")
    sp.add_argument("--min-trust", type=float, default=0.0)
    sp.add_argument("--reward", help="an opaque pointer to wherever settlement happens; the protocol does not move money")
    sp.add_argument("--wait", type=float, default=0, help="seconds to wait for an accepted answer (0: post and exit)")

    sp = sub.add_parser("requests", help="list requests a hub holds")
    sp.add_argument("--hub", required=True)
    sp.add_argument("--task")
    sp.add_argument("--all", action="store_true", help="include accepted and expired ones")

    sp = sub.add_parser("work", help="serve requests from a hub: claim, do the work, answer")
    _key_args(sp)
    sp.add_argument("--hub", required=True)
    sp.add_argument("--tasks", default="hash_verified,format_scan")
    sp.add_argument("--poll", type=float, default=5.0)
    sp.add_argument("--once", action="store_true", help="one pass, then exit")
    sp.add_argument("--max", type=int, help="exit after this many requests")
    sp.add_argument("--idle-exit", type=float, help="exit after this many seconds with nothing to do")
    sp.add_argument("--lease", type=float, default=300, help="seconds a claim lasts")
    sp.add_argument("--max-bytes", type=int, default=8 * 1024**3)

    sp = sub.add_parser("relay-info", help="a Nostr relay's published limits (NIP-11), and which of our events would not fit")
    sp.add_argument("relay", help="ws:// or wss:// address")

    sp = sub.add_parser("relay-check", help="TEST a relay you run: send probe events to find its real limits and how it treats our event kinds")
    sp.add_argument("relay")
    sp.add_argument("--max-bytes", type=int, default=1024 * 1024, help="largest probe event to try (default 1 MiB)")
    sp.add_argument("--keep", action="store_true", help="do not ask the relay to delete the probe events afterwards")

    sp = sub.add_parser("relay-push", help="send events (and optionally manifests) from this store to a relay")
    _key_args(sp)
    sp.add_argument("relay")
    sp.add_argument("--kinds", default=",".join(str(k) for k in (36778, 36779, 36780, 36781, 36782, 36783, 36784, 36785, 36786)))
    sp.add_argument("--since", type=int)
    sp.add_argument("--author", action="append")
    sp.add_argument("--manifest-repo", action="append", default=[], help="also send the signed manifests held for this repo")
    sp.add_argument("--max-event-bytes", type=int, default=65536, help="skip events bigger than this; relays often refuse over 64 KiB without publishing it (0: no limit)")

    sp = sub.add_parser("relay-pull", help="read events (and optionally manifests) from a relay; each goes through admission like any other")
    _key_args(sp)
    sp.add_argument("relay")
    sp.add_argument("--kinds", default=",".join(str(k) for k in (36778, 36779, 36780, 36781, 36782, 36783, 36784, 36785, 36786)))
    sp.add_argument("--since", type=int)
    sp.add_argument("--author", action="append")
    sp.add_argument("--follow", action="store_true", help="ask only for keys THUB_ROOTS already trusts, and keep going as trust grows (ignores --author)")
    sp.add_argument("--manifest-signer", action="append", default=[], help="a key whose manifests to take (hex or npub); needs --manifest-repo")
    sp.add_argument("--manifest-repo", action="append", default=[])

    sp = sub.add_parser("lineage", help="what trusted derivation events say about a blob (from THUB_ROOTS)")
    sp.add_argument("sha256")

    sp = sub.add_parser("events-add", help="check an event file and add it to this gateway's event store")
    sp.add_argument("file")

    sp = sub.add_parser("events-pull", help="fetch events from another gateway and add the ones that pass")
    sp.add_argument("url")
    sp.add_argument("--kinds", default="36778,36779,36780,36781,36782")
    sp.add_argument("--author", action="append")
    sp.add_argument("--since", type=int)
    sp.add_argument("--limit", type=int, default=500)

    sp = sub.add_parser("events-sync", help="level this gateway's events with another's: pull what it has, push what it lacks")
    sp.add_argument("url")
    sp.add_argument("--kinds", default="36778,36779,36780,36781,36782")
    g = sp.add_mutually_exclusive_group()
    g.add_argument("--pull-only", action="store_true")
    g.add_argument("--push-only", action="store_true")

    sp = sub.add_parser("events", help="list events held here")
    sp.add_argument("--kind", type=int, action="append")
    sp.add_argument("--quarantine", action="store_true")

    sp = sub.add_parser("verify-blobs", help="check every blob held here and sign hash_verified and format_scan attestations")
    _key_args(sp)
    sp.add_argument("--post", help="send the events to this gateway. Otherwise they are added to the local store")

    sp = sub.add_parser("replicate", help="redo other people's attestations on blobs held here and sign the result")
    _key_args(sp)
    sp.add_argument("--from", dest="source", required=True, help="gateway to read attestations from")
    sp.add_argument("--post", help="gateway to send replications to (default: the --from gateway)")

    sp = sub.add_parser("signer", help="run a signer: holds the key, signs only what its limits allow, keeps an audit log")
    sp.add_argument("--key-file", help="file holding the secret key. Otherwise THUB_SIGNING_KEY")
    sp.add_argument("--socket", required=True, help="Unix socket path to listen on (readable by this user only)")
    sp.add_argument("--audit", required=True, help="audit log file (JSON lines)")
    sp.add_argument("--read-root", required=True, help="the only folder it will read files from")
    sp.add_argument("--claims", default="hash_verified,format_scan,replication")
    sp.add_argument("--max-per-hour", type=int, default=60)
    sp.add_argument("--max-per-day", type=int, default=500)
    sp.add_argument("--expires-in", type=int, help="seconds from now after which it signs nothing")

    sp = sub.add_parser("verdict", help="what the attestations here say about a blob, from THUB_ROOTS")
    sp.add_argument("sha256")
    sp.add_argument("--claim", default="format_scan")
    sp.add_argument("--independent", type=int, default=1)
    sp.add_argument("--min-trust", type=float, default=0.0)

    sp = sub.add_parser("trust", help="how much this gateway trusts a key, from THUB_ROOTS, with the path")
    sp.add_argument("key", help="public key, hex or npub")
    sp.add_argument("--scope")


def _secret(args, p) -> bytes:
    from .signing import parse_secret

    raw = Path(args.key_file).read_text() if args.key_file else os.environ.get("THUB_SIGNING_KEY", "")
    if not raw.strip():
        p.error("give --key-file or set THUB_SIGNING_KEY")
    return parse_secret(raw)


def _emit(ev: dict, out: str | None) -> None:
    text = json.dumps(ev, indent=1, sort_keys=True)
    if out:
        Path(out).write_text(text)
        print(json.dumps({"id": ev["id"], "kind": ev["kind"], "file": out}))
    else:
        print(text)


def run_event_command(args, settings, p) -> None:
    from .admission import Admission
    from .eventstore import EventStore
    from .events import build_delegation, build_derivation, build_endorsement, build_identity, build_revocation
    from .signing import parse_pubkey

    def key(v):
        try:
            return parse_pubkey(v)
        except ValueError as e:
            p.error(str(e))

    c = args.cmd
    try:
        if c == "identity":
            _emit(build_identity(_secret(args, p), args.label, key(args.recovery) if args.recovery else None, args.note), args.out)
        elif c == "delegate":
            exp = int(time.time()) + args.expires_in if args.expires_in else None
            _emit(build_delegation(_secret(args, p), key(args.subject), args.scope, expires=exp, redelegable=args.redelegable,
                                   max_events_per_day=args.max_events_per_day, max_bytes_per_day=args.max_bytes_per_day), args.out)
        elif c == "endorse":
            exp = int(time.time()) + args.expires_in if args.expires_in else None
            _emit(build_endorsement(_secret(args, p), key(args.subject), args.scope, args.weight, delegable=args.delegable, expires=exp), args.out)
        elif c == "derive":
            outs = []
            for o in args.output:
                x, _, rest = o.partition(":")
                size, _, ih = rest.partition(":")
                outs.append({"x": x, "size": int(size) if size else None, "i": ih or None})
            _emit(build_derivation(_secret(args, p), args.input, outs, args.tool, tool_x=args.tool_x, args=json.loads(args.args),
                                   data_origin=args.origin, synthetic_depth=args.depth,
                                   licences={"output": args.licence_out}), args.out)
        elif c in ("relay-info", "relay-check", "relay-push", "relay-pull"):
            import asyncio

            from . import relay as R
            from . import relay_sync as RS
            from .admission import Admission as _Adm
            from .eventstore import EventStore as _ES
            from .store import Store as _Store

            try:
                if c == "relay-info":
                    doc = asyncio.run(R.info(args.relay))
                    lim = doc.get("limitation") or {}
                    print(json.dumps({"name": doc.get("name"), "software": doc.get("software"), "version": doc.get("version"),
                                      "supported_nips": doc.get("supported_nips"), "limitation": lim}, indent=1))
                    if not lim:
                        print("(the relay publishes no limits: run relay-check on a relay you run to measure them)")
                elif c == "relay-check":
                    pr = asyncio.run(R.probe(args.relay, max_bytes=args.max_bytes, delete=not args.keep))
                    print(json.dumps(pr.asdict(), indent=1, default=str))
                else:
                    auth = _secret(args, p) if (args.key_file or os.environ.get("THUB_SIGNING_KEY")) else None
                    adm = _Adm(_ES(settings.data_dir), settings.roots, hops=settings.trust_hops)
                    kinds = [int(k) for k in args.kinds.split(",") if k]
                    authors = [parse_pubkey(a) for a in (args.author or [])] or None
                    if c == "relay-push":
                        cap = args.max_event_bytes or None
                        out = asyncio.run(RS.push(adm, args.relay, kinds, since=args.since, authors=authors, auth_secret=auth, max_event_bytes=cap))
                        if args.manifest_repo:
                            out["manifests"] = asyncio.run(RS.push_manifests(_Store(settings.data_dir), args.relay, args.manifest_repo, auth_secret=auth, max_event_bytes=cap))
                    else:
                        if args.follow:
                            out = asyncio.run(RS.pull_following(adm, args.relay, kinds, since=args.since, auth_secret=auth))
                        else:
                            out = asyncio.run(RS.pull(adm, args.relay, kinds, since=args.since, authors=authors, auth_secret=auth))
                        if args.manifest_signer:
                            if not args.manifest_repo:
                                raise SystemExit("error: --manifest-signer needs --manifest-repo")
                            out["manifests"] = asyncio.run(RS.pull_manifests(_Store(settings.data_dir), args.relay, {parse_pubkey(k) for k in args.manifest_signer},
                                                                              args.manifest_repo, auth_secret=auth))
                    print(json.dumps(out))
            except R.RelayError as e:
                raise SystemExit(f"error: {e}")
        elif c == "request":
            from .workflow import Participant, make_request, wait_for_answer

            part = Participant(settings.data_dir / "agent", settings.roots, args.hub, _secret(args, p), settings.trust_hops)
            a = {"filename": args.filename} if args.filename else None
            try:
                ev = make_request(part, args.task, args.input, deadline_in=args.deadline_in, args=a, want=args.want, reward=args.reward)
            except RuntimeError as e:
                raise SystemExit(f"error: {e}")
            print(json.dumps({"request": ev["id"], "task": args.task}), flush=True)
            if args.wait > 0:
                st = wait_for_answer(part, ev["id"], n=args.independent, min_trust=args.min_trust, timeout=args.wait,
                                     progress=lambda s: print(f"  {s.state}", flush=True))
                print(json.dumps({"state": st.state, "accepted_by": list(st.accepted_by), "outcome": st.outcome, "detail": st.detail}))
                if st.state != "accepted":
                    raise SystemExit(1)
        elif c == "requests":
            import httpx

            r = httpx.get(args.hub.rstrip("/") + "/api/thub/requests", params={"state": "all" if args.all else "open", **({"task": args.task} if args.task else {})}, timeout=30)
            r.raise_for_status()
            for q in r.json()["requests"]:
                print(q["id"][:16], q["task"], q["state"], f"{len(q['inputs'])} input(s)", "claimed by " + ",".join(k[:8] for k in q["claimants"]) if q["claimants"] else "")
        elif c == "work":
            from .workflow import Participant, Worker

            part = Participant(settings.data_dir / "agent", settings.roots, args.hub, _secret(args, p), settings.trust_hops)
            w = Worker(part, tuple(t for t in args.tasks.split(",") if t), lease=args.lease, max_bytes=args.max_bytes)
            print(json.dumps({"worker": part.pubkey, "tasks": list(w.tasks)}), flush=True)
            try:
                done = w.run(poll=args.poll, max_requests=args.max, once=args.once, idle_exit=args.idle_exit)
            except KeyboardInterrupt:
                done = []
            for o in done:
                print(json.dumps({"request": o.request, "action": o.action, "detail": o.detail}))
        elif c == "publish":
            import asyncio
            import tempfile

            import httpx

            from .publisher import next_seq, prepare, publish
            from .swarm import LibtorrentSwarm

            secret = _secret(args, p)
            refs = tuple(args.ref or ["main"])
            hub = args.hub.rstrip("/")
            if bool(args.dir) == bool(args.git):
                raise SystemExit("error: give exactly one of --dir and --git")

            async def go():
                async with httpx.AsyncClient(timeout=30) as client:
                    seq = await next_seq(client, hub, args.repo, refs[0]) if args.seq == "auto" else int(args.seq)
                stage = Path(args.stage) if args.stage else Path(tempfile.mkdtemp(prefix="thub-publish-"))
                if args.git:
                    from .publisher import hub_heads, prepare_git

                    async with httpx.AsyncClient(timeout=30) as client:
                        have = await hub_heads(client, hub, args.repo)
                    print(f"reading {args.git} at {args.commit} ({len(have)} commits already on the hub) ...", flush=True)
                    pub = prepare_git(secret, args.repo, Path(args.git), stage, rev=args.commit, refs=refs, seq=seq, have=have,
                                      valid_for=args.valid_days * 86400 if args.valid_days else None, trackers=args.tracker,
                                      extra_dirs=[Path(x) for x in args.files_from], force=args.force)
                else:
                    print(f"hashing {args.dir} ...", flush=True)
                    pub = prepare(secret, args.repo, Path(args.dir), stage, refs=refs, seq=seq,
                                  valid_for=args.valid_days * 86400 if args.valid_days else None, trackers=args.tracker)
                print(f"commit {pub.commit}, seq {seq}, {len(pub.body['inline'])} small and {len(pub.torrents)} big files", flush=True)
                swarm = LibtorrentSwarm(0, dht=False)
                last = [""]

                def show(st):
                    line = "; ".join(f"{f['path']} {f['bytes'] * 100 // max(f['size'], 1)}%" for f in st["files"].values() if f["state"] in ("pulling", "checking"))
                    if line and line != last[0]:
                        last[0] = line
                        print("hub is pulling:", line, flush=True)

                try:
                    return await publish(hub, pub, swarm, timeout=args.timeout, progress=show)
                finally:
                    await swarm.close()

            try:
                res = asyncio.run(go())
            except (RuntimeError, ValueError) as e:
                raise SystemExit(f"error: {e}")
            print(json.dumps({k: res.get(k) for k in ("state", "repo", "commit", "seconds", "already")}))
        elif c == "host":
            import dataclasses
            import logging

            import uvicorn

            from .host import build_host_app
            from .signing import public_key

            logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
            secret = _secret(args, p)
            pk = public_key(secret).hex()
            s = dataclasses.replace(settings, public_url=args.public_url.rstrip("/"), roots=[pk], swarm="libtorrent",
                                    listen_port=args.listen_port, webseed_upstream=False, lazy_mirror=False, anchor="",
                                    upstream="http://127.0.0.1:9", publish_quota=0)
            app, host = build_host_app(s, repo=args.repo, git_dir=Path(args.git), secret=secret, branches=tuple(args.branch or ["main"]),
                                       extra_dirs=tuple(args.files_from), valid_for=args.valid_days * 86400 if args.valid_days else None, poll=args.poll)
            print(json.dumps({"hosting": args.repo, "git": args.git, "pubkey": pk, "url": s.public_url, "branches": list(host.branches)}), flush=True)
            print(f"consumers pin it with: THUB_TRUST='{args.repo}=signed:{pk}' THUB_UPSTREAM={s.public_url}", flush=True)
            uvicorn.run(app, host=args.bind, port=args.port)
        elif c == "filter":
            from . import pointers

            gd = pointers.git_dir()
            try:
                if args.mode == "clean":
                    pointers.clean(sys.stdin.buffer, sys.stdout.buffer, gd)
                else:
                    pointers.smudge(sys.stdin.buffer, sys.stdout.buffer, gd, pointers.hubs_for())
            except Exception as e:  # noqa: BLE001
                print(f"torrenthub filter {args.mode}: {e}", file=sys.stderr)
                raise SystemExit(1)
            sys.stdout.buffer.flush()
        elif c == "git-init":
            from . import pointers

            try:
                out = pointers.install(Path(args.dir), tuple(args.pattern) if args.pattern else pointers.DEFAULT_PATTERNS, lfs=args.lfs)
            except Exception as e:  # noqa: BLE001
                raise SystemExit(f"error: {e}")
            print(json.dumps(out))
            print("big files matching those patterns now become pointers when added, and are fetched when checked out", file=sys.stderr)
        elif c == "verify-git":
            from .gitremote import RemoteError, verify_clone

            try:
                res = verify_clone(Path(args.dir), [*args.signer, *[k for k in os.environ.get("THUB_SIGNERS", "").replace(",", " ").split() if k]], args.hub)
            except (RemoteError, ValueError, Exception) as e:  # noqa: BLE001
                raise SystemExit(f"error: {e}")
            print(json.dumps(res, indent=1))
            if not res["ok"]:
                raise SystemExit(1)
        elif c == "seed":
            import asyncio

            from . import clientswarm, pointers
            from .swarm import LibtorrentSwarm

            gd = pointers.git_dir(Path(args.dir))
            items = []
            for tp in sorted((gd / "thub" / "torrents").glob("*.torrent")):
                for sub_dir in ("objects", "packs"):
                    f = gd / "thub" / sub_dir / tp.stem
                    if f.is_file():
                        items.append((tp, f))
            cfg = clientswarm.config_from_env(gd)

            async def go():
                sw = LibtorrentSwarm(args.listen_port, dht=cfg.dht)
                try:
                    for tp, f in items:
                        await sw.seed(tp, f.parent)
                    print(json.dumps({"seeding": len(items), "port": args.listen_port or sw.ses.listen_port(), "files": [f.name for _, f in items]}), flush=True)
                    if args.once:
                        return
                    await asyncio.sleep(args.seconds) if args.seconds else await asyncio.Event().wait()
                finally:
                    await sw.close()

            try:
                asyncio.run(go())
            except KeyboardInterrupt:
                pass
        elif c == "pull-files":
            from . import pointers

            try:
                done = pointers.materialize(Path(args.dir), [h.rstrip("/") for h in args.hub] if args.hub else None)
            except Exception as e:  # noqa: BLE001
                raise SystemExit(f"error: {e}")
            print(json.dumps({"filled": done}))
        elif c == "revoke":
            target = key(args.target) if args.kind == "key" else args.target
            succ = key(args.successor) if args.successor else None
            _emit(build_revocation(_secret(args, p), args.kind, target, args.reason, taint=args.taint, successor=succ), args.out)
        elif c == "signer":
            import asyncio

            from .signer import Signer, SignerConfig, serve

            cfg = SignerConfig(Path(args.read_root), Path(args.audit), allowed_claims=tuple(x for x in args.claims.split(",") if x),
                               max_per_hour=args.max_per_hour, max_per_day=args.max_per_day,
                               not_after=int(time.time()) + args.expires_in if args.expires_in else None)
            signer = Signer(_secret(args, p), cfg)

            async def run():
                srv = await serve(signer, args.socket)
                from .signing import backend as _backend

                print(json.dumps({"listening": args.socket, "pubkey": signer.pubkey, "crypto": _backend()}), flush=True)
                if _backend() != "libsecp256k1":
                    print("warning: signing with pure Python, whose timing depends on the secret key; install torrenthub[fast]", file=sys.stderr, flush=True)
                async with srv:
                    await srv.serve_forever()

            try:
                asyncio.run(run())
            except KeyboardInterrupt:
                pass
        elif c in ("verify-blobs", "replicate"):
            from .store import Store
            from .verifier import Verifier

            secret = _secret(args, p)
            store = Store(settings.data_dir)
            ver = Verifier(secret, store)
            post = args.post if c == "verify-blobs" else (args.post or args.source)
            tally: dict[str, int] = {}

            def deliver(evs):
                import httpx

                for ev in evs:
                    if post:
                        from .sync import post_event

                        r = post_event(post.rstrip("/") + "/api/thub/events", ev)
                        st = r.json().get("status", f"http{r.status_code}") if r.headers.get("content-type", "").startswith("application/json") else f"http{r.status_code}"
                    else:
                        st = Adm(EventStore(settings.data_dir), settings.roots).admit(ev).status
                    tally[st] = tally.get(st, 0) + 1

            from .admission import Admission as Adm
            from .signing import public_key as _pk

            me = _pk(secret).hex()
            if c == "verify-blobs":
                done = {t[1] for e in EventStore(settings.data_dir).query([36782], [me], limit=500) for t in e["tags"] if t[0] == "x"} if not post else set()
                for x in store.complete_lfs_blobs():
                    if x not in done:
                        deliver(ver.attest_blob(x))
            else:
                import httpx

                src = args.source.rstrip("/")
                atts = httpx.get(src + "/api/thub/events", params={"kinds": 36782, "limit": 500}, timeout=30).json().get("events", [])
                mine = httpx.get(post.rstrip("/") + "/api/thub/events", params={"kinds": 36782, "authors": me, "limit": 500}, timeout=30).json().get("events", [])
                redone = {t[1] for e in mine for t in e["tags"] if t[0] == "e"}
                for att in atts:
                    if att.get("pubkey") == me or att.get("id") in redone:
                        continue
                    out = ver.replicate(att)
                    if out:
                        deliver([out])
            print(json.dumps(tally))
        elif c in ("events-add", "events-pull", "events-sync", "events", "trust", "verdict", "lineage"):
            store = EventStore(settings.data_dir)
            adm = Admission(store, settings.roots, hops=settings.trust_hops)
            if c == "events-add":
                res = adm.admit(json.loads(Path(args.file).read_text()))
                print(json.dumps({"status": res.status, "reason": res.reason, "tier": res.tier}))
                if res.status == "rejected":
                    raise SystemExit(1)
            elif c == "events-pull":
                import httpx

                params = {"kinds": args.kinds, "limit": args.limit}
                if args.author:
                    params["authors"] = ",".join(parse_pubkey(a) for a in args.author)
                if args.since is not None:
                    params["since"] = args.since
                r = httpx.get(args.url.rstrip("/") + "/api/thub/events", params=params, timeout=30)
                r.raise_for_status()
                tally: dict[str, int] = {}
                for ev in r.json().get("events", []):
                    st = adm.admit(ev).status
                    tally[st] = tally.get(st, 0) + 1
                print(json.dumps(tally))
            elif c == "events-sync":
                from .sync import sync

                kinds = [int(k) for k in args.kinds.split(",") if k]
                print(json.dumps(sync(adm, args.url, kinds, pull=not args.push_only, push=not args.pull_only)))
            elif c == "lineage":
                g = adm.graph()
                mt = 0.0
                print(json.dumps({"x": args.sha256, "status": g.blob_status(args.sha256), "synthetic_depth": g.synthetic_depth(args.sha256, mt),
                                  "descends_from_revoked": g.tainted_descendants(mt).get(args.sha256),
                                  "made_by": [{"event": d.id[:16], "issuer": d.issuer[:16], "tool": d.tool, "inputs": [i[:16] for i in d.inputs]}
                                              for d in g.parents(args.sha256, mt)],
                                  "used_by": [{"event": d.id[:16], "issuer": d.issuer[:16], "tool": d.tool, "outputs": [o[0][:16] for o in d.outputs]}
                                              for d in g.children(args.sha256, mt)]}, indent=1))
            elif c == "verdict":
                g = adm.graph()
                v = g.verdict(args.sha256, args.claim, args.independent, args.min_trust)
                print(json.dumps({"status": v.status, "keys": list(v.keys), "need": v.need, "detail": v.detail, "revoked": g.blob_status(args.sha256),
                                  "refuted_attestors": sorted(g.refuted_attestors())}, indent=1))
            elif c == "events":
                for ev in store.query(args.kind, include_quarantine=args.quarantine, limit=500):
                    print(ev["id"][:16], ev["kind"], ev["pubkey"][:16], ev["created_at"], store.tier_of(ev["id"]))
            else:
                g = adm.graph()
                k = key(args.key)
                t = g.trust(k, args.scope)
                print(json.dumps({"key": k, "scope": args.scope, "trust": t.value, "root": k in g.roots, "member": g.reachable(k),
                                  "path": [{"from": a[:16], "to": b[:16], "event": e[:16]} for a, b, e in t.path]}, indent=1))
    except ValueError as e:
        raise SystemExit(f"error: {e}")
