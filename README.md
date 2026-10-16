# torrenthub

A Hugging Face compatible model mirror that distributes weights over BitTorrent. See `ARCHITECTURE.md` for the design and its limits.

This is a prototype. It has been tested against a fake upstream, not against the real huggingface.co. Run the live check first on a machine with internet:

```bash
THUB_LIVE=1 python -m pytest tests/test_live_hf.py -s
```

It mirrors a small public repo and compares every file with a direct download. It has never been run, so its first result is new information.

## Run it

```bash
pip install -e '.[swarm,dev]'

export THUB_DATA=./data
export THUB_PUBLIC_URL=http://localhost:8080
export THUB_SWARM=libtorrent        # or "none" for plain HTTP mirroring
export THUB_TRACKERS=udp://tracker.opentrackr.org:1337/announce

torrenthub serve --port 8080
```

The first client to ask for an uncached file streams it while the mirror downloads it. You can also pre-warm a model, or set `THUB_PREFETCH=true` to warm a repo's files as soon as its metadata is first read:

```bash
torrenthub mirror gpt2 --revision main
```

Use it from any HF client:

```bash
export HF_ENDPOINT=http://localhost:8080
hf download gpt2
```

## Agent mode

Run the gateway on your own machine, pointed at a hub, and let it pull big files from the swarm:

```bash
export THUB_UPSTREAM=https://your-hub.example.org
export THUB_SWARM=libtorrent
export THUB_SWARM_FIRST=true
export THUB_PUBLIC_URL=http://localhost:8080
torrenthub serve --port 8080

export HF_ENDPOINT=http://localhost:8080
hf download some/model
```

Big files come from peers, small files from the hub over HTTP, and anything the swarm cannot supply within `THUB_SWARM_STALL` seconds comes from the hub over HTTP. What you download you also seed. This exposes your IP address to other peers, and you need an open `THUB_LISTEN_PORT` to give anything back. The hub must itself run with `THUB_SWARM=libtorrent` and be reachable. See `ARCHITECTURE.md`, section 6a.

## Several upstreams

```bash
export THUB_UPSTREAMS=https://hub-a.example.org,https://hub-b.example.org
export THUB_QUORUM=2
```

With one URL and quorum 1 nothing changes. With several, metadata, torrents and file bytes fail over in order. With `THUB_QUORUM=2` a repo's file table is accepted only when two upstreams give the same commit and the same files, and a conflict is refused with 502. To check a hub against the origin, list both: `THUB_UPSTREAMS=https://hub.example.org,https://huggingface.co THUB_QUORUM=2`. Big files still come from peers. See `ARCHITECTURE.md`, section 6b.

## Not trusting hubs

In agent mode the gateway takes each repo's expected hashes from Hugging Face (the anchor) and only torrents and bytes from your hubs, so a hub cannot lie about what is correct. This needs the agent to reach huggingface.co for metadata (a few KB). Set `THUB_ANCHOR` to use another origin, or `THUB_ANCHOR=none` to trust your hub as before.

Your own repos, which Hugging Face does not have, need a rule that lets hubs answer:

```bash
export THUB_TRUST='myorg/*=hub,*=anchor-or-hub'
```

Responses carry `X-Thub-Source: anchor|hub|upstream` so you can see which kind of answer you got. Hub answers are not independently verified. With a lockfile set they are pinned on first sight.

To publish a repo that Hugging Face does not have, with a signature agents can check:

```bash
torrenthub keygen                                  # prints nsec and npub, saves nothing
torrenthub sign myorg/model --key-file ./my.nsec   # signs the file table your hub holds
# agents trust the key, not the hubs:
export THUB_TRUST='myorg/*=signed:npub1...,*=anchor'
```

Signing proves who said the file table is right. It does not prove it is the latest, and there is no upload API yet. See `ARCHITECTURE.md`, section 6d.

To pin what you have seen:

```bash
export THUB_LOCKFILE=./thub.lock
torrenthub lock meta-llama/Llama-3.2-1B     # records the current commit's file table
export THUB_LOCK_MODE=strict                # then only locked commits are served
```

See `ARCHITECTURE.md`, section 6c.

## Commands

| Command | What it does |
|---|---|
| `torrenthub serve` | Run the HF compatible gateway |
| `torrenthub mirror <repo> [--revision]` | Download, verify and torrent every file in a repo |
| `torrenthub evict <key>` | Drop a blob's bytes, keep its torrent so the swarm can refill it |
| `torrenthub gc` | Evict least recently used torrented blobs until under `THUB_MAX_DISK` |
| `torrenthub block <sha256> [--reason]` | Takedown: delete bytes and torrent, stop seeding, return 451 for that content |
| `torrenthub lock <repo> [--revision]` | Record a revision's file table in `THUB_LOCKFILE` |
| `torrenthub locked` | List locked commits |
| `torrenthub keygen` | Make a signing key pair and print it |
| `torrenthub sign <repo> [--revision] [--ref] [--key-file]` | Sign a repo revision's file table and keep the manifest here |
| `torrenthub manifests <repo>` | List signed manifests held for a repo |
| `torrenthub manifest-add <file> --key <npub>` | Check and import a signed manifest |
| `torrenthub mcp --gateway URL --download-root DIR [--max-gib N] [--agent-key-file K --allow-repo GLOB --work-root DIR]` | MCP server (stdio) for AI agents; with an agent key it can also publish, record derivations, report evaluations and answer requests. Needs `pip install '.[mcp]'` |
| `torrenthub identity / delegate / endorse / revoke` | Make a signed participant event (`--key-file`, `--out`) |
| `torrenthub events-add FILE` | Check an event and add it to this gateway's store |
| `torrenthub events-pull URL` | Fetch events from another gateway and add the ones that pass |
| `torrenthub events` | List stored events |
| `torrenthub trust KEY [--scope]` | Trust in a key, from `THUB_ROOTS`, with the path that explains it |
| `torrenthub verify-blobs --key-file F [--post URL]` | Check every blob held here and sign `hash_verified` and `format_scan` attestations |
| `torrenthub replicate --key-file F --from URL` | Redo other people's attestations on blobs held here and sign whether they match |
| `torrenthub signer --key-file F --socket S --audit A --read-root D` | Run a signer that holds the key and signs only what its limits allow |
| `torrenthub verdict SHA256 [--claim] [--independent N] [--min-trust T]` | What the attestations held here say about a blob |
| `torrenthub blocked` | List blocked blobs |
| `torrenthub list` | List torrented blobs |

Gateway endpoints beyond the HF API: `/metrics` (Prometheus text), `/healthz`, `/blobs/<key>` (web seed), `/torrents/<key>.torrent`, `/api/swarm/<repo>/revision/<rev>` (magnets).

## Settings (environment)

| Variable | Default | Meaning |
|---|---|---|
| `THUB_DATA` | `./data` | Catalogue, blobs, torrents |
| `THUB_UPSTREAM` | `https://huggingface.co` | Where to mirror from |
| `THUB_UPSTREAMS` | none | Comma separated upstream hubs in priority order. When set, `THUB_UPSTREAM` is ignored |
| `THUB_QUORUM` | `1` | Upstreams that must agree on a repo's file table. 1 uses the first that answers. Needs at least that many upstreams |
| `THUB_META_TIMEOUT` | `15` | Seconds to wait for each upstream's metadata when a quorum is used |
| `THUB_ANCHOR` | auto | The origin that decides the correct hashes. Auto means `https://huggingface.co` in agent mode and none otherwise. `none` turns it off |
| `THUB_ANCHOR_REQUIRED` | `true` | If the anchor is unreachable, refuse new metadata. `false` falls back to the hubs |
| `THUB_TRUST` | none | Per repo source of hashes: `<glob>=anchor\|anchor-or-hub\|hub\|signed:KEY[+KEY]`, comma separated, first match wins |
| `THUB_SIGNING_KEY` | none | Secret key (hex or nsec) for `torrenthub sign`. `--key-file` also works |
| `THUB_LOCKFILE` | none | Path of a lockfile of commits and file tables |
| `THUB_LOCK_MODE` | `verify` | `verify`, `record` (add unknown commits) or `strict` (refuse unknown commits) |
| `THUB_PUBLIC_URL` | `http://localhost:8080` | Used in web seed URLs, must be reachable by peers |
| `THUB_TRACKERS` | none | Comma separated tracker URLs |
| `THUB_LAZY_MIRROR` | `true` | Mirror on first request. If false, only `mirror` populates it |
| `THUB_TORRENT_MIN_SIZE` | `1048576` | Only LFS files this big get a torrent |
| `THUB_REF_TTL` | `300` | Seconds before re-checking a branch upstream |
| `THUB_WEBSEED_UPSTREAM` | `true` | Add the upstream URL as a web seed. Shifts load to the upstream host |
| `THUB_SWARM` | `none` | `none` or `libtorrent` |
| `THUB_LISTEN_PORT` | `6881` | BitTorrent listen port (open TCP and UDP) |
| `THUB_ROOTS` | none | Public keys (hex or npub, comma separated) this gateway starts its trust from. Keys named in `signed:` rules count too |
| `THUB_TRUST_HOPS` | `3` | Longest chain of endorsements followed from a root |
| `THUB_POLICY` | none | TOML file of rules for what must be attested before a file is served. See `PROTOCOL.md` section 13 |
| policy `max_age` / `[freshness]` | none | `max_age = "30d"` on a `[[file]]` rule counts only attestations that recent. `[freshness] manifest_max_age` is the same as `THUB_MANIFEST_MAX_AGE` |
| `THUB_EVENTS_PER_IP_BURST` / `_MINUTE`, `THUB_PUBLISH_PER_IP_MINUTE` | `300` / `600`, `30` | Requests an address may send to the event and publish endpoints; 0 turns a limit off. Behind a proxy on another machine, set uvicorn's `FORWARDED_ALLOW_IPS` to its address |
| `THUB_MAX_EVENT_BODY`, `THUB_PUBLISH_MAX_BODY` | `256K`, `64M` | Largest request body read for each POST endpoint |
| `THUB_PUBLISH_QUOTA` | `0` | Bytes of published content one signing key may hold here, such as `10G`. 0 turns publishing off. Only roots and their `publish:<repo>` delegates may publish |
| `THUB_PUBLISH_GIT`, `THUB_PUBLISH_ALLOW_FORCE` | `1`, `0` | Take git backed publications (needs `git` on the hub); accept a manifest that rewrites a branch |
| `THUB_PUBLISH_GIT_MAX_PACK`, `_BLOB_MAX`, `_SMALL_TOTAL`, `_MAX_OBJECTS`, `_TIMEOUT` | `32M`, `8M`, `64M`, `100000`, `60` | Limits on a publisher's git objects: the pack, one plain file (bigger must be a pointer), all plain files of a commit, objects in the history, seconds per git command |
| `THUB_PUBLISH_STALL` / `THUB_PUBLISH_TIMEOUT` | `120` / `3600` | Seconds a publisher may send nothing, and the longest a publication may take |
| `THUB_MANIFEST_MAX_AGE` | none | Seconds. Refuse to resolve a branch name through a signed manifest older than this |
| `THUB_OUTGOING_UTP` | `false` | Dial peers over uTP first, which is libtorrent's own default. Off means TCP. Between two machines on a fast link uTP-first was about 15x slower |
| `THUB_PEERS` | none | Static peer hints, `host:port` comma separated. Discovery stays on. Useful to tell "transfer works" from "discovery works" |
| `THUB_SWARM_FIRST` | `false` | Agent mode: fetch the torrent from the upstream hub and download from peers first |
| `THUB_SWARM_STALL` | `20` | Seconds with no swarm bytes before falling back to HTTP from the upstream |
| `THUB_SWARM_TIMEOUT` | `300` | Seconds without progress, once bytes were flowing, before the download fails |
| `THUB_USE_WEBSEEDS` | `false` | Also pull from the torrent's web seeds. They are HTTP, so this sends bytes back through the hub |
| `THUB_MAX_DISK` | `0` | Disk budget such as `500G`. 0 means unlimited. Only torrented blobs are evicted |
| `THUB_STREAM_HOLDBACK` | `64K` | Bytes withheld from a streaming client until the file is verified. Any size above zero keeps a corrupt file from completing; smaller means the first byte arrives sooner |
| `THUB_ALLOW` | `*` | Comma separated globs of repo ids to mirror |
| `THUB_DENY` | none | Comma separated globs to refuse with 451. Wins over allow |
| `THUB_PREFETCH` | `false` | Fetch all files of a repo in the background after its metadata is read |
| `THUB_PREFETCH_CONCURRENCY` | `2` | Repos prefetched at once |
| `HF_TOKEN` | none | Sent to `huggingface.co` only, never to another hub. Private and gated repos are still refused |

## Tests

```bash
python -m pytest
```

283 tests plus the opt-in live test, about three and a half minutes. They run the real `huggingface_hub` client against the gateway, and real libtorrent transfers between separate nodes (hub, agent, second agent) on loopback.

## MCP server for agents

`torrenthub mcp` lets an MCP client (an LLM agent) use a gateway. Its first six tools are `repo_info`, `check_trust`, `fetch_file`, `verify_file`, `get_verdict` and `gateway_status`, and it has more for finding and comparing repos (below). By default it only reads and downloads. It cannot publish, sign or change the gateway, unless you start it with a signer or an agent key (below).

Client config:

```json
{"mcpServers": {"torrenthub": {"command": "torrenthub", "args": ["mcp", "--gateway", "http://127.0.0.1:8080", "--download-root", "/home/you/thub-downloads"]}}}
```

Each answer says where the hashes came from (`anchor`, `signed`, `hub` or `upstream`). With `--signer SOCKET` there is also `attest_file`, which has a separate signer process check the file and sign the result. `get_verdict` shows what the signed attestations say about a file. `fetch_file` checks the bytes against the advertised hash itself and deletes the file if they differ. Downloads stay inside `--download-root` and under `--max-gib` (default 20). Anything copied from a repo is marked as untrusted data in the results. Tested with in-process and stdio MCP clients, and driven by hand over stdio once, not with a real LLM client yet. `fetch_file` blocks until the file is done, so a very large download may hit a client timeout.

### Letting an agent do research and development

With its own key, an agent can do what a person does with the command line, and not only read:

```
torrenthub keygen                                   # the AGENT's own key; never give it the owner's
torrenthub delegate --key-file owner.key --subject <agent pubkey> --scope 'publish:acme/*' --scope 'attest:*' --expires-in 604800
torrenthub endorse  --key-file owner.key --subject <agent pubkey> --scope derive --weight 0.8   # only if its derivations should count in lineage
# delegate and endorse print an event (add --out FILE); hand each to the hub:  curl -X POST -d @FILE $HUB/api/thub/events
torrenthub mcp --gateway https://hub.example --download-root ./dl --work-root ./work \
    --agent-key-file agent.key --allow-repo 'acme/*' --audit-log ./agent-audit.jsonl \
    --max-events-per-hour 60 --max-publish-gib 50 --valid-hours 168
```

| Tool | Needs a key | What it does |
|---|---|---|
| `find_repos`, `repo_history`, `compare_revisions`, `download_repo`, `lineage`, `trust_of`, `list_events`, `list_requests`, `hash_local_file`, `whoami` | no | Find a repo, read its signed history (each signature checked here), see what changed between two revisions, download a whole snapshot with every hash checked, see what a file was made from, ask how far the gateway trusts a key |
| `publish_repo` | yes | Publish a folder under `--work-root` as a signed repo. A folder with `.git` goes with its history |
| `declare_derivation` | yes | Sign how a model was made: inputs, outputs, tool, data origin, licences |
| `report_eval` | yes | Sign a benchmark result for a file (class R: a reported result, with the dataset hash and settings so others can redo it) |
| `post_request`, `claim_request`, `submit_result` | yes | Ask for work, say you are on it, answer |
| `retract_event` | yes | Withdraw one of the agent's own earlier events |

The tools that sign or publish are not offered at all without `--agent-key-file`. What stops an agent doing harm with them: its key is a delegation that expires and can be revoked; it publishes only to `--allow-repo` globs and only from under `--work-root` (links that lead outside are refused); the operator's per hour and per day limits, size cap and expiry are checked in this process and counted again from the audit log after a restart; every action, signed or refused, is in the audit log. Delegating authority (`delegate`, `endorse`, `revoke` of keys) is deliberately **not** a tool: an agent cannot widen its own trust. A key the gateway does not know can still post events, but they are held in quarantine and the tool says so. Text from other participants (request arguments, notes, repo names) is labelled untrusted data in every result.

Tested with 18 tests that drive the tools over a real MCP session against a real hub (publish, a second version, history, compare, download, derivation read back through lineage, an eval, two agents on one request, retraction, every limit, links, a git repo with history, and the command line flags). Not tested: a real LLM client making these choices, a long autonomous run, or any hub other than this code.

## Validating it for real

`validation/README.md` is a runbook for the checks that need a real network: a probe of Hugging Face (including Xet-backed repos), a live comparison test, a two machine swarm test, a measurement of how many bytes come from peers, and a multi-GB run. Nothing in this project has been run against the real internet yet.

## Where this is going

`PROTOCOL.md` sketches how AI agents and humans could take part on equal terms: publishing, attesting, endorsing and revoking through signed events, with trust computed locally from keys you pin.

Built: identity, delegation, endorsement, revocation and attestation events, a trust evaluator, an event store with admission control, `/api/thub/events`, a policy file, a verifier, replication, a signer, and the CLI above. A `signed:ROOT` rule accepts manifests from keys the root has delegated to, and a policy can refuse a file until enough independent trusted keys have attested it. Derivations, requests and the publishing path are design only, and so is any run on a real network. `PROTOCOL.md` sections 12 and 13 list what is and is not built.

## Known limits

- Never run against the real huggingface.co (see the live test above).
- Never run at multi-GB scale.
- Agent mode has only been run on loopback with fixed peer addresses. Finding peers through a tracker or DHT on a real network is untested.
- Repos hosted only on hubs have no independent check unless the creator signs them. Unsigned ones are pinned on first sight (lockfile), not proven genuine.
- Signed manifests prove who said it, not that it is the latest: a hub can withhold a newer manifest. No key rotation or revocation, no upload API, no relay publishing.
- Without an anchor, an agent trusts its hub, or the quorum of its upstreams, for each file's expected sha256. With the anchor (the default in agent mode) it trusts the origin's API instead. A lockfile only protects commits you have already recorded.
- A conflict between upstreams is refused, so one lying hub in the list can block a repo. Tested only with hubs that mirror one fake origin.
- File failover only happens before bytes flow. A broken stream is not moved to another hub.
- No auth, no private or gated repos, no search, datasets or spaces.
- Takedown stops this gateway serving and seeding. It cannot remove content from peers who already have it.

## Diagnosing stalls

`THUB_GAP_WARN` (seconds, default 5, 0 disables) logs pauses in a stream on the `torrenthub.gaps` logger, once for the upstream download and once for each client reading it, with a summary line when each ends. Compare the two max gaps to tell an upstream stall from bytes held back by the gateway (1 MiB upstream chunks plus `THUB_STREAM_HOLDBACK`). A client that sees no data for ~10s gives up, which is the `huggingface_hub` read timeout.

## Publishing

A hub started with `THUB_PUBLISH_QUOTA=10G` and `THUB_ROOTS=<your public key>` takes repos you sign. From any machine, including one behind NAT or a firewall that allows no inbound connections:

```bash
torrenthub publish --repo you/model --dir ./model --hub https://hub.example --key-file ~/.thub/key
```

It hashes the directory, signs a manifest, sends it with the torrents of the big files, then seeds them and dials the hub, which pulls the bytes and checks them against the signed hashes before anything is visible. Agents fetch it with `THUB_TRUST="you/*=signed:<your public key>"`. Use `--valid-days N` to make a manifest expire.

**From a git repository.** Keep the repo in git, with big files as LFS pointers (git-lfs's format) and the real bytes in the working tree or git-lfs's cache, and publish a commit:

```bash
torrenthub publish --repo you/model --git ./model --hub https://hub.example --key-file ~/.thub/key
```

The commit id is git's own, history is kept (the hub holds a bare git repository per repo), and a new commit must descend from the branch's current one unless you pass `--force` and the hub allows it (`THUB_PUBLISH_ALLOW_FORCE=1`). Only objects the hub lacks are sent, and big files it already holds are not hashed again. The hub needs `git` installed. Details and limits: `HOSTING.md` and `PROTOCOL.md` section 18. `torrenthub publish --git` reads the committed state, not the working tree, apart from finding the big files' bytes.

## Plain git

`git-remote-thub` (installed with the package) lets git talk to a hub, and `torrenthub git-init` handles big files without git-lfs:

```bash
torrenthub git-init                                   # once per repo: filter + .gitattributes for model formats
git add model.safetensors && git commit -m "weights"  # the file becomes a pointer; its bytes stay in .git/thub/objects
git remote add hub thub://hub.example/you/model
git config thub.keyfile ~/.thub/key
git push hub main                                     # signed and published, big files by torrent, works behind NAT

git clone -c thub.signer=<owner key> -c filter.thub.clean="torrenthub filter clean" \
  -c filter.thub.smudge="torrenthub filter smudge" -c filter.thub.required=true thub://hub.example/you/model
```

A clone only follows branches that a manifest signed by a pinned key vouches for, and checks the commit and its file table against that manifest; the hub is not trusted. Without the filter options a clone has pointers in place of big files; `torrenthub pull-files` fills them in. `THUB_SKIP_SMUDGE=1` does the same during checkout. Use `thub::http://host:port/you/model` for a hub without TLS. Details and limits: `PROTOCOL.md` section 20.

### The bytes travel over BitTorrent

Git is how an author versions their own repo; distribution is the swarm. A clone through `git-remote-thub` gets the git **history** as a pack that is itself a torrent (its sha256, size and infohash are in the signed manifest) and each **big file** by torrent, with the hub as one direct peer, any trackers or DHT you have, and `thub.peer` hints. Plain HTTP from the hub is the fallback when the swarm has nobody. Whatever arrives is hashed before it is kept. A clone can then share what it fetched:

```bash
torrenthub seed --listen-port 6881        # seeds the big files and history packs this clone fetched
git clone -c thub.peer=friend.example:6881 -c thub.signer=<owner key> thub://hub.example/you/model   # gets them from a peer
```

The hub is also a BitTorrent tracker (`<public url>/announce`, on by default; `THUB_TRACKER=0` turns it off), and every torrent it hands out names it. So a clone that has fetched a file and runs `torrenthub seed` is found by the next clone through the hub, with nobody typing an address; `thub.peer` is only needed where neither the tracker nor the DHT can help. With `THUB_TRACKER=0` the hub is still a DHT node that clients and `torrenthub seed` start from (`THUB_DHT_PUBLIC=0 THUB_DHT_LOCAL=1` for a private network), so even without any tracker a seeder is found. The tracker answers only for torrents the hub holds, records the address each connection came from, and is rate limited. It cannot get two peers that are both behind NAT to reach each other.

Settings (git config, or the environment variable shown): `thub.swarm` (`THUB_CLIENT_SWARM`), `thub.peer` (`THUB_PEERS`), `thub.tracker` (`THUB_TRACKERS`), `thub.dht` (`THUB_CLIENT_DHT`), `thub.webseed` (`THUB_CLIENT_WEBSEED`), `thub.swarmStall` / `thub.swarmTimeout` (`THUB_CLIENT_STALL`, `THUB_CLIENT_TIMEOUT`). `PROTOCOL.md` section 22 has the details and what is not shown (discovery across real networks).

### Stock git and git-lfs, no helper (a convenience over HTTP)

A hub with a published or hosted repo also speaks read-only smart HTTP and the git-lfs download API, so anyone can:

```bash
git lfs install
git clone https://hub.example/you/model          # needs only stock git and git-lfs
torrenthub verify-git --signer <owner key>       # optional, and the only check: stock git believes the hub
```

Make a repo that stock git-lfs handles with `torrenthub git-init --lfs` (git-lfs does the pointers, and a `pre-push` hook is written that keeps git-lfs from trying to upload to a thub remote; publish with `git push` through `git-remote-thub` or `torrenthub publish --git` as above). `THUB_PUBLIC_URL` must be the address clients reach the hub at, because the LFS download links use it. `THUB_GIT_HTTP_PER_IP_MINUTE` and `THUB_GIT_HTTP_MAX_BODY` limit the git endpoints. Pushing over plain HTTP is refused.

## Running it

`DEPLOY.md` is the operator's guide: install (pip at the locked versions, or a container), `torrenthub doctor` to check a machine and a
running hub, systemd units, a TLS proxy, backups and upgrades, a hardening checklist, and a table of symptoms and causes.

```bash
pip install -c lock/runtime.txt 'torrenthub[swarm,fast,relay]'
torrenthub --version && torrenthub doctor
podman build --format docker -f deploy/Containerfile -t torrenthub .
```

Two settings matter for any real deployment: `THUB_PUBLIC_URL` (the address clients reach the hub at; web seeds, LFS links and the tracker
address are built from it) and `THUB_SWARM_PUBLIC_PORT` (the swarm port as seen from outside, if it is not the one the hub listens on).

## Hosting from your own machine

Instead of sending a repo to a hub, serve it yourself from a git repository (same layout as above: big files are LFS pointers in the tree, their bytes in the working tree or git-lfs's cache):

```bash
torrenthub host --git ./model --repo you/model --key-file ~/.thub/key --public-url http://my.host.example:8080
# prints the line consumers use:  THUB_TRUST='you/model=signed:<key>' THUB_UPSTREAM=http://my.host.example:8080
```

It signs a manifest for each commit of the branches it watches (`--branch`, default `main`; `--poll` seconds apart), serves big files from where they are (a link, not a copy) and seeds them. A file edited after it was committed stops being served instead of being served wrong. Needs libtorrent, a reachable HTTP port (`--port`, 8080) and swarm port (`--listen-port`, 6881). `PROTOCOL.md` section 19 has the rules, the measurements and the limits.

## Asking for work

Agents can ask each other to check things. A requester posts a request to a hub and waits; a worker watches the hub, claims it, does the check and answers; the requester decides by its own roots whether the answer stands. Each side pulls the events into its own store, so the hub is never trusted for the verdict.

```bash
# worker (a machine that can reach the hub)
THUB_ROOTS=<operator key> torrenthub work --hub https://hub.example --key-file worker.key

# requester
THUB_ROOTS=<operator key> torrenthub request --hub https://hub.example --key-file me.key \
    --task format_scan --filename model.safetensors --input <sha256> --independent 2 --wait 120
```

It works once the operator has endorsed the workers for `work:*` and `attest:*` and the requester for `request:*`. See `PROTOCOL.md` section 16.

## Nostr relays

Events are already Nostr events, so they can travel through relays as well as hubs. Install the extra (`pip install 'torrenthub[relay]'`), then:

```bash
torrenthub relay-info  wss://relay.example                 # its published limits
torrenthub relay-push  wss://relay.example --key-file k    # send this store's events
THUB_ROOTS=<your root> torrenthub relay-pull wss://relay.example --follow   # take only what your roots trust
torrenthub relay-check ws://127.0.0.1:7777                 # TEST a relay you run: finds its real limits
```

A pulled event goes through the same checks as one from a hub, so a relay is trusted for nothing. Relays often refuse events over 64 KiB without publishing it; pushes skip those unless you pass `--max-event-bytes 0`. See `PROTOCOL.md` section 17 for what was measured.

## Licence

MIT. See `LICENSE`.
