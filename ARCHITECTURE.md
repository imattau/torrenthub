# torrenthub architecture

A Hugging Face compatible model mirror that moves weights over BitTorrent. Existing tools (`hf download`, `transformers`, `snapshot_download`) work unchanged by setting `HF_ENDPOINT`.

Decisions taken from the brief: build and run it ourselves, mirror Hugging Face first, aim to cut hosting cost, keep HF client compatibility.

## 1. The point that decides the design

If a stock HF client talks to a remote gateway over HTTP, the gateway serves every byte over HTTP. The swarm does not reduce that bill. A hosted gateway in front of BitTorrent is just a cache with extra steps.

The swarm only saves money when the HTTP leg is short. There are two ways to get that:

1. **Gateway refills from peers, not from origin.** The gateway keeps the torrent, drops cold bytes, and refills from the swarm on demand. This cuts origin egress and storage, not client-facing bandwidth. Built and tested in the prototype.
2. **Agent mode (the real cost lever).** The same program runs on the user's own machine (`HF_ENDPOINT=http://localhost:8080`) with `THUB_SWARM_FIRST=true` and a hub as its upstream. The HTTP leg is loopback. The agent asks the hub for the blob's torrent, downloads big files from peers, and then seeds them. Every user is a bandwidth contributor. Built and tested in phase 2 (section 6a).

Both modes are the same code with different settings. A **hub** mirrors from Hugging Face and seeds. An **agent** has a hub as its upstream, pulls big files from the swarm, and seeds what it fetched. An agent can itself be the upstream of another agent.

## 2. Components

```
  hf CLI / transformers / snapshot_download
                 |  HTTP (HF Hub API subset)
                 v
        +------------------+      miss      +-----------------+
        |     gateway      | -------------> | upstream (HF)   |
        |  (FastAPI app)   | <------------- | HTTP + web seed |
        +--------+---------+     bytes      +-----------------+
                 |
        +--------+---------+        +---------------------+
        |  mirror logic    | -----> |  swarm (libtorrent) |<---> peers, DHT, trackers
        | verify, torrent  |        |  seed / refill      |
        +--------+---------+        +---------------------+
                 |
        +--------+---------+
        | store: SQLite +  |
        | blobs + torrents |
        +------------------+
```

- **gateway** (`app.py`): read-only HF Hub API, plus `/blobs/<key>` (BEP-19 web seed), `/torrents/<key>.torrent`, `/api/swarm/<repo>/revision/<rev>` (magnets), `/metrics` (Prometheus text) and `/healthz`.
- **mirror** (`mirror.py`): resolves refs to commits, downloads and verifies blobs, builds torrents, chooses the source on a miss (swarm first, upstream second), and enforces policy: repo allow and deny globs, disk budget with LRU eviction, takedown block list.
- **swarm** (`swarm.py`): interface with `NullSwarm` and `LibtorrentSwarm`. A swarm download is a handle that reports how many bytes from the start of the file are complete and piece-verified, which is what lets the gateway stream to a client mid-download. The HTTP side can be tested without a torrent engine.
- **store** (`store.py`): SQLite catalogue, blob and torrent files on disk.

## 3. HF API surface

What the client needs, checked against `huggingface_hub` 2.2.0 by running its real `snapshot_download` and `hf_hub_download` against the gateway.

| Endpoint | Status | Notes |
|---|---|---|
| `GET /api/models/{repo}/revision/{rev}` | done | Stored upstream document, `sha` set to the resolved commit |
| `GET /api/models/{repo}/tree/{rev}[/{path}]` | done | Needed by current clients for file listing. Found when the real client failed against an earlier version of the gateway |
| `GET,HEAD /{repo}/resolve/{rev}/{file}` | done | `X-Repo-Commit`, `ETag`, `X-Linked-Etag`, `X-Linked-Size`, ranges |
| 404 with `X-Error-Code` | done | `RepoNotFound`, `RevisionNotFound`, `EntryNotFound` map to the client's exceptions |
| 451 with `X-Error-Code` | done | `RepoBlocked` (deny glob) and `BlobBlocked` (takedown). Not a code the client knows, so it surfaces as a generic HTTP error |
| Revisions containing `/` (`refs/pr/1`) | done | Routes parse the raw request path, because the client sends `%2F` and the decoded path is ambiguous |
| Search, repo listing, datasets, spaces | not done | |
| Xet | avoided | The gateway never sends `x-xet-hash`, so clients use plain HTTP. Verified by the tests passing, but not against a real Xet-backed repo |
| Auth, private and gated repos | refused | Reported as `RepoNotFound`. Mirroring them needs a licence and access policy |

HEAD is answered from the catalogue without touching bytes, which is what the client expects.

## 4. Storage model

Content addressed. Blob key is the LFS sha256, or `git-<blobId>` for plain git files.

- The same weights shared by many repos or revisions are stored, torrented and seeded once.
- Branch names map to commits with a TTL. If upstream is unreachable, the stale mapping is served. That is the mirror property.
- Files under 1 MiB, and non-LFS files, are served directly and never torrented. Torrenting `config.json` is overhead with no benefit.

## 5. Torrent layer

- **One torrent per large blob**, not per repo. Per-repo torrents change infohash whenever any file changes and cannot share swarms across repos.
- **Deterministic infohash.** The info dict holds only `name` (the key), `length`, `piece length` and `pieces`. Trackers, web seeds and timestamps live outside it. Two operators who mirror the same blob independently get the same infohash and join one swarm. Tested.
- **Piece length policy is a protocol constant.** Smallest power of two from 256 KiB to 16 MiB giving at most 2048 pieces. Changing it changes every infohash, so it is versioned (`PIECE_POLICY_VERSION`).
- **Web seeds (BEP-19)** point at the gateway's `/blobs/<key>` and, optionally, the upstream resolve URL. New torrents are downloadable on day one before any peer exists.
- **BitTorrent v1 (SHA-1 pieces).** v1 has the widest client support. SHA-1 weakness is covered by checking the file's sha256 against the value upstream advertises, before the blob is published (tested with corrupt bytes). A v2 or hybrid torrent is a possible later change, but it changes every infohash.
- **Discovery:** DHT plus configured trackers. A first-party tracker is not built.

## 6. Request flows

**Cache hit.** Client asks for a file. The gateway resolves the commit, sees the blob is complete, and streams it with range support.

**Miss.** Resolve the commit, then start one download task per blob (details of the swarm source are in 6a). The task tries the swarm first when it has or can get a torrent, and otherwise downloads from the upstream over HTTP. Either way the client is streamed as bytes arrive:

- The task is independent of any client. On the HTTP source, hashing happens in one pass (sha256, git blob id, torrent pieces). If the client disconnects, mirroring carries on.
- Concurrent requests for the same blob attach to the one download (single flight).
- **Holdback.** The last `THUB_STREAM_HOLDBACK` bytes (default 64 KiB) are not released until the whole file has been verified. The size does not change the guarantee, since any non-empty tail keeps a response from completing; it sets how long a client waits for its first byte, because nothing is released until that many bytes are written. If verification fails, readers are dropped before they receive the tail, so a single response never completes with corrupt bytes. Files smaller than the holdback are released only after verification, so they are not streamed at all. The prefix is released before it is verified, so a client resuming a partial file could in principle join a bad prefix to a good tail. `huggingface_hub` 2.2.0 does not: it discards its partial file when the stream is cut (`tests/test_resume_hazard.py`). Tools that resume partial files (`curl -C`, `wget -c`, `aria2`) were not tested.
- After verification the file is renamed into place, the torrent is written, seeding starts, and the disk budget is enforced.

The length is known from the catalogue, so `Content-Length` and range requests (including suffix ranges) work on an in-flight download.

**Upstream outage.** Known refs and complete blobs keep working. Unknown repos fail with a clear error.

**Evict and refill.** `evict` removes the bytes and keeps the torrent. The next request refills from peers (streamed, see 6a) and re-verifies the sha256.

**Disk budget.** With `THUB_MAX_DISK` set, each completed download triggers eviction of the least recently accessed blobs until usage is under budget. Only blobs that have a torrent are evictable, because only those can be refilled from the swarm. Small files and non-LFS files stay. The blob just downloaded is protected. If everything evictable is gone and usage is still over budget, the gateway stays over budget rather than refusing to serve. With no swarm configured, an evicted blob is refilled from upstream, which costs origin egress again.

## 6a. Agent mode

An agent is a gateway with `THUB_UPSTREAM=<a hub>`, `THUB_SWARM=libtorrent` and `THUB_SWARM_FIRST=true`. No separate index service was built. A hub already is one: it serves HF-shaped metadata with each file's sha256, and `/torrents/<sha256>.torrent`. An agent gets metadata and torrents from its hub, and the hub's address is the trust root (see section 8).

On a miss for a big LFS file the agent:

1. Fetches the torrent from the hub and **validates** it (`validate_torrent`): single-file v1, name equals the blob's sha256, length equals the catalogue size, piece length follows the piece policy, correct number of piece hashes, under 4 MiB. A torrent that fails is dropped and the agent uses HTTP.
2. Strips the web seed URLs from a working copy (`THUB_USE_WEBSEEDS=false` by default), so bytes come from peers only. Web seeds are HTTP. Using them would send the bytes back through the hub and defeat the point. The infohash is unchanged because web seeds sit outside the info dict.
3. Starts a sequential libtorrent download and streams to the client as pieces complete. libtorrent checks each piece as it arrives, and the gateway then **reads each piece back from disk and checks its SHA-1 against the torrent again before sending any of it**. A mismatch aborts the stream before those bytes go out. This means what a client receives does not depend on libtorrent's file writes being visible yet. The last `THUB_STREAM_HOLDBACK` bytes still wait for the full-file sha256 check.
4. **Falls back to HTTP** from the hub only if no byte has arrived within `THUB_SWARM_STALL` seconds (default 20). At that point no client has received anything, so switching is safe. If bytes were flowing and then stop for `THUB_SWARM_TIMEOUT` (default 300), the download fails instead and the client retries, because a client may already hold part of the file.
5. Compares the file's sha256 with the catalogue. On a mismatch the file and the torrent are deleted, the stream is cut before the tail, and that blob uses HTTP for the rest of the process lifetime.
6. Keeps the validated torrent and keeps seeding, so the next agent can use this one.

Small files and non-LFS files (under `THUB_TORRENT_MIN_SIZE`, 1 MiB by default) always come over HTTP from the hub. `HF_TOKEN` is now sent only to `huggingface.co`, never to a hub, because an agent's upstream is someone else's server.

`THUB_SWARM_FIRST` is off by default. It exposes the machine's IP address to every peer in the swarm, and it needs a reachable listen port to contribute upload.

## 6b. Federation

A hub or agent can list several upstream hubs: `THUB_UPSTREAMS=https://hub1,https://hub2,https://huggingface.co`, in priority order. With more than one URL, or a quorum above 1, the upstream becomes an `UpstreamSet` (`upstream.py`). There is still no separate index service. Each hub is an index, and a gateway reads from several.

- **Metadata** (`THUB_QUORUM=1`, the default): ask in order and use the first upstream that answers. A 404 or 451 from one upstream is only reported if no other upstream has the repo.
- **Metadata with a quorum above 1**: ask every upstream at once (each limited by `THUB_META_TIMEOUT`) and accept an answer only when at least `THUB_QUORUM` upstreams give the same commit and the same file table (`federation.choose_consensus`). The rules:
  - The same commit sha with a different file table is always a refusal (502 `UpstreamDisagreement`), even if a majority agrees. Content addressing means a commit sha should fix its contents, so a split here is a lie or a bug and the agent will not guess which.
  - For a pinned 40 hex revision, only answers for that commit count.
  - For a branch name, answers are grouped by commit. A group needs `quorum` members, and the highest priority group that has them wins. Hubs that are simply behind do not block an agent as long as enough of them agree on one commit.
  - Too few answers (for example one hub is down) is 502 `UpstreamUnavailable`, which is counted separately from a disagreement.
  - `quorum` larger than the number of upstreams is a startup error.
- **Torrents**: ask in order and use the first torrent that passes `validate_torrent`. A bad torrent from one hub is counted as rejected and the next hub is tried.
- **File bytes over HTTP**: try each upstream in order until one answers 200. If every upstream says 404 the client gets 404, otherwise 502. Failover only happens before bytes reach the client. A hub that answers 200 and breaks before sending any byte is skipped. One that breaks after the first chunk is not retried on another hub, and the client's download fails and is retried from the start.

Checking a hub against the origin: list the hub first and Hugging Face second with quorum 2 (`THUB_UPSTREAMS=https://hub,https://huggingface.co THUB_QUORUM=2`). The agent accepts a file table only if the hub and the origin agree, and it still takes big file bytes from peers (the swarm path does not touch the origin). The test `test_a_lying_hub_is_caught_by_the_origin` covers a hub that reports a wrong sha256.

Two independently run hubs produce the same infohash for the same blob (deterministic torrent, section 5), so their seeders and any agents that fetched from either all sit in one swarm. A hub that disappears takes its metadata with it but not the data.

Choices to be aware of:
- Refusing on a conflict means one lying hub in the list can stop an agent from resolving a repo. The alternative is to drop a dissenting minority and carry on. I chose to refuse because it fails loudly. This is a policy question and is easy to change.
- Quorum protects against one hub lying or being stale. It does not protect against hubs that agree with each other because they share an operator or a compromised source. Independent operators are what make the number mean anything.
- The agent still trusts whatever the quorum accepted for each file's sha256 (section 8).

## 6c. Anchor and lockfile

Section 6b makes hubs agree with each other. That does not make them truthful, so the design needs a source of truth that no hub controls.

**The anchor** is the origin (Hugging Face for a mirror). With an anchor set, repo metadata, which holds every file's expected sha256, comes only from the anchor. Hubs are never asked for metadata. They supply torrents and bytes, and everything they supply is checked against what the anchor said: the torrent must be for that sha256 and size (`validate_torrent`), each piece is checked while streaming, and the whole file is checked before it is published. A hub can lie about nothing that matters. At worst it serves garbage, which is detected, or nothing, in which case the agent tries the next hub or fails.

- `THUB_ANCHOR` unset means automatic: `https://huggingface.co` in agent mode (`THUB_SWARM_FIRST=true`), none otherwise. `THUB_ANCHOR=none` turns it off. Set it to any URL to anchor on something else.
- The anchor costs a metadata request of a few KB per repo refresh. No file bytes come from it unless it is also the only upstream.
- If the anchor cannot be reached, new metadata is refused (502) by default, because falling back to a hub silently removes the protection. `THUB_ANCHOR_REQUIRED=false` falls back to the hubs and counts it in `thub_anchor_skipped_total`. Metadata already stored is served either way, so a repo you have already fetched keeps working with the origin down.
- With an anchor, `THUB_QUORUM` no longer applies to metadata. The anchor is a single authority, not a vote.
- By default, if the anchor says 404 the answer is 404, even when a hub has the repo. Per repo trust (below) changes this for repos you choose.

**Per repo trust.** One global anchor would make Hugging Face the only way a repo can exist, and users must be able to create their own. So the source of truth is chosen per repo with `THUB_TRUST`, a comma separated list of `<repo glob>=<mode>`, first match wins:

| Mode | Where the expected hashes come from |
|---|---|
| `anchor` | The anchor only. If it says 404 the answer is 404. This is the default whenever an anchor is in force. |
| `anchor-or-hub` | The anchor. If the anchor does not have the repo, the hubs. |
| `hub` | The hubs only (with `THUB_QUORUM` applied), never the anchor. |
| `signed:KEY[+KEY]` | The creator's signed manifest (section 6d). Hubs are not believed about hashes. |

Example: `THUB_TRUST='acme/*=hub,*=anchor-or-hub'` lets anyone's `acme/` repos live on your hubs and falls back to hubs for any other repo Hugging Face lacks.

Every file table is labelled with where it came from, stored per commit, counted in `thub_metadata_source_total`, and sent to clients as `X-Thub-Source`:
- `anchor`: checked with the origin.
- `hub`: a hub answered where the policy allowed it, while an anchor was available. Nothing independent vouches for it.
- `signed`: matches a manifest signed by a key you pinned for that repo.
- `upstream`: there is no anchor, so the configured upstreams are trusted (the plain mirror case).
A weaker label never replaces `anchor` for the same commit.

Hub-sourced tables are **pinned on first sight** in the lockfile (when `THUB_LOCKFILE` is set), even in `verify` mode. That limits what a hub can do later: if it, or someone else, changes the table for that commit, or the repo name later appears on the origin with different contents (squatting), the mismatch is refused. It does not prove the first answer was genuine. For an unvouched repo, integrity after first sight is pinned and authenticity is not proven. The only things that prove authenticity there are an origin or the creator's signature (section 6d, mode `signed`).

An anchor that is unreachable is not treated as "the repo is absent". Even with `anchor-or-hub`, an outage is refused (unless `THUB_ANCHOR_REQUIRED=false`), because otherwise an outage would turn the protection off.

**The lockfile** (`THUB_LOCKFILE=path`) is a JSON file of `repo@commit` entries, each holding that commit's file table (path, size, sha256, git blob id). It does not depend on anyone staying honest later. Once a commit is in it, any upstream, anchor included, that reports that commit with a different table is refused with 502 `LockMismatch`.
- `THUB_LOCK_MODE=verify` (default): known commits must match, unknown ones pass.
- `record`: as verify, and unknown commits are added. This is trust on first use.
- `strict`: unknown commits are refused with 403 `NotLocked`. Use this for a fixed set of models.
- `torrenthub lock <repo> [--revision main]` records a commit (through the anchor when there is one) and refuses to change an existing entry. `torrenthub locked` lists entries.

What this does not cover:
- The first sight of a commit. The lockfile is only as good as where you recorded it from. With an anchor, that is the origin.
- A compromised origin. The anchor is trusted by definition. The lockfile limits the damage to things you have not locked yet.
- Branch names. A lock is per commit. A hub that serves an old commit for `main` is not caught by the lockfile, and the anchor is what tells you the current one.
- I have not checked whether Hugging Face's commit sha can be used to verify the file table independently of the API's answer. That needs the real API and I can't reach it from the sandbox.

## 6d. Creator signatures

For a repo that exists nowhere but on hubs, the creator is the source of truth, and a signature is how an agent knows it. Per repo trust (6c) gets a fourth mode:

`THUB_TRUST='acme/*=signed:<npub or hex>[+<npub or hex>]'`

An agent with that rule takes the file table for any `acme/` repo only from a manifest signed by one of the listed keys. Hubs are used to find manifests and to supply torrents and bytes. They are not believed about anything.

**The manifest** is a Nostr style event (`signing.py`, `manifest.py`): the NIP-01 layout (id, pubkey, created_at, kind, tags, content, sig) with a BIP-340 Schnorr signature. That means a manifest is plain JSON that can be passed around by hubs and also published to a relay later. The content, in ASCII only JSON, is `{v, repo, commit, refs, files}` where `files` is each path with its size, sha256 and git blob id. The kind is 36777, which is provisional: it is in the addressable range and was not in the NIPs README when I looked on 15 Oct 2026, but it is not registered for this. `MANIFEST_KIND` is one constant.

**Flow for `signed` repos:**
1. Collect manifests from every hub (`GET /api/thub/manifests/<repo>`) and check each: signed by a trusted key, signature and id valid, for this repo, tags equal to the signed content. Anything else is dropped and counted.
2. Choose the manifest. A pinned commit needs a manifest for that commit. A branch name needs manifests that list it in `refs`, and the one with the newest `created_at` wins.
3. Ask the hubs in order for that commit and accept the first whose file table is exactly the manifest's. A hub that gives a different table is skipped and counted (`thub_manifest_hub_mismatch_total`). If every hub that answers disagrees the result is 502 `ManifestMismatch`, and with no valid manifest at all it is 502 `NoValidManifest`.
4. Every hash the agent later enforces is the creator's. The verified manifest is kept and served on, so agents can be sources of manifests for other agents.

Tools: `torrenthub keygen` (prints a key pair, saves nothing), `torrenthub sign <repo> [--revision main] [--ref main] --key-file F` (or `THUB_SIGNING_KEY`; takes the file table from the creator's own hub, signs it, stores it locally so that hub serves it), `torrenthub manifests <repo>`, `torrenthub manifest-add <file> --key <npub>` (verify and import).

**What it does not do:**
- **Freshness.** A signature proves who said it, not that it is the latest. A hub can withhold a newer manifest and serve an older signed one, which rolls a branch back. Asking several hubs and taking the newest manifest from all of them fixes this as long as one honest hub has it. A pinned commit is not affected. Closing it properly needs something like a relay the creator publishes to, or a signed expiry, and neither is built.
- **Key distribution.** The agent has to know the creator's key. `THUB_TRUST` is that pinning. There is no key discovery, no rotation and no revocation. A lost or leaked key means every future manifest from it is accepted until you change the rule.
- **Getting a repo onto a hub.** Signing is built, and uploading is not. A hub gets a creator's files by mirroring from somewhere (the creator's own hub works) and gets manifests with `sign` or `manifest-add`. There is no upload API and no namespace ownership. A key in a rule is the only claim to a namespace.
- **Nostr relays.** The events are relay compatible but nothing talks to a relay.
- The signer here is a small pure Python BIP-340 implementation, checked against the official BIP-340 test vectors. It is not constant time. Fine for signing a manifest on your own machine, and worth replacing with a library if signing is ever done anywhere else.

**A change to file failover that came with this.** An upstream that answers 200 and then breaks before sending any byte is now skipped like one that answered an error, because the agent reads the first chunk before committing to it. Breaking after the first chunk is still not recovered by moving to another hub.

## 7. Cost model

Fill in your own prices, I have not assumed any:

```
monthly cost =  origin egress (bytes fetched from HF) x origin price
              + storage (bytes held) x storage price
              + gateway egress (bytes served over HTTP) x bandwidth price
              + index and tracker hosting
```

How each design lever moves it:

| Lever | Origin egress | Storage | Gateway egress |
|---|---|---|---|
| Content-addressed dedupe | down | down | none |
| Evict cold blobs, refill from swarm | down | down | none |
| Agent mode, big files from peers | none | none | down by the share of bytes peers supply |
| Agent mode, no peers (HTTP fallback) | none | none | same as a plain hub |
| Web seed to HF | up (HF pays) | none | none |

The size of the agent saving depends on how many agents stay online and reachable to seed, and on the hub having peers at all. That has not been measured. In tests the hub served under 200 KB over HTTP for a repo whose big file was 3.5 MiB, with all of that file arriving from peers, which shows the mechanism and says nothing about real ratios. A hub's own seeding uses upload bandwidth too, and that is cost the model above does not count separately.

The web seed to HF shifts cost onto Hugging Face. I have not checked their terms on mirroring or web-seeding at scale. Settle that before running this publicly. `THUB_WEBSEED_UPSTREAM=false` turns it off.

## 8. Trust and integrity

- Bytes are verified against upstream's advertised sha256 (LFS) or git blob id (plain files) before they are published or seeded. On mismatch nothing is kept, including the partial file.
- Peers cannot poison a swarm fetch into the catalogue: the whole-file sha256 is re-checked after a swarm download, and a mismatch deletes the file and the torrent. Tested with a torrent built over altered bytes, named as the real blob, seeded by a real peer: every piece passes the torrent's checks, and only the sha256 comparison catches it.
- Without an anchor, an agent trusts its hub (or the quorum of its upstreams) for metadata, which means the expected sha256, and a malicious hub can serve wrong content with a matching wrong sha256. In agent mode the anchor is on by default, so metadata comes from the origin and hubs are untrusted for hashes (section 6c). Signed manifests would remove the need to trust the origin's API as well, and are not built.
- Streaming a swarm download releases piece-verified bytes before the whole-file check, so a torrent built over bad content passes every piece check and can send a client most of a bad file before the connection is cut. The same caveat about clients that resume applies as in section 6.
- Weak spot: the expected hash comes from upstream over TLS. If you later publish natively (no upstream), you need creator signatures. Signed manifests over Nostr events would fit, but that is design only.
- Takedowns: content-addressed storage plus a public swarm means removal is not enforceable on peers. What this gateway can do: `THUB_DENY` and `THUB_ALLOW` globs on repo ids, and `torrenthub block <sha256>`, which deletes the bytes and torrent, stops seeding, cancels any in-flight download, and returns 451 for that content from then on. Peers who already have the file keep it. You still need a decision about what you will and will not mirror, and a process for receiving and recording takedown requests.
- Privacy: torrent peers see each other's IPs. Agent mode exposes users to that. A gateway-only deployment does not.

## 9. Prototype status

Tested (283 tests plus 1 opt-in live test, `python -m pytest`):
- Real `huggingface_hub` `snapshot_download` and `hf_hub_download` against the gateway, with a fake upstream.
- Second client and a dead upstream both served from the mirror, with no extra upstream file hits.
- Headers, HEAD, ranges (including suffix, open-ended and unsatisfiable), error code mapping.
- Torrent validity: piece hashes re-verified against the stored blob, deterministic infohash across independent gateways, web seed and tracker present.
- Corrupt upstream bytes: nothing published, nothing left behind, the client cannot receive a complete file, recovery afterwards.
- Streaming: first bytes reach the client before upstream has finished sending; concurrent clients cause one upstream download; a client disconnect does not stop mirroring; range requests work on an in-flight download.
- Holdback logic as unit tests: the tail is blocked until verified, a failed verification never releases it, files under the holdback are fully held.
- `refs/pr/1` through both the model-info path and the resolve path with the real client.
- LRU eviction under a disk budget, access order refreshing the LRU order, no eviction when no budget is set.
- Deny and allow globs, takedown (bytes, torrent, web seed and swarm listing all gone, 451 for the content, other files in the repo unaffected).
- Metrics values, background prefetch.
- Real libtorrent peer to peer transfer with all web seeds removed and upstream down.
- Gateway evicts a blob, upstream stops, client download is refilled from a peer and re-verified.
- Agent mode, real libtorrent, real HF client, loopback (`tests/test_agent.py`): an agent fetches a repo through a hub with the origin down, and the hub serves under 200 KB over HTTP while all 3.5 MiB of the big file arrives from peers; the first bytes reach the client while the swarm download is still running (hub upload throttled); with no peers the agent falls back to HTTP after the stall timeout; a torrent for the wrong blob is rejected; a poisoned torrent and seeder are caught by the sha256 check, nothing is published, and the retry succeeds over HTTP; a second agent fetches from the first with the hub and origin both gone.
- Torrent validation, web seed stripping (infohash unchanged), and the token-only-to-Hugging-Face rule as unit tests.
- Piece read-back verification as unit tests: correct bytes and ranges that cross piece boundaries, and a corrupted piece on disk that aborts the stream with nothing from that piece sent.
- Federation (`tests/test_consensus.py` as unit tests, `tests/test_federation.py` with real gateways and libtorrent): an agent skips a dead first upstream; file bytes fail over from a hub that has taken the file down (451) to one that has it; missing everywhere is 404, not 502; quorum 2 passes when two hubs agree and refuses when one lies; quorum 1 trusts whichever hub answers first; a hub is checked against the origin while the bytes come from peers; too few answers is reported as unavailable, not as a disagreement; a bad torrent from the first hub does not block the second; independent hubs share one infohash; settings from the environment.
- Anchor and lockfile (`tests/test_anchor_lock.py`): a hub lying about a hash is ignored when there is an anchor, and believed when there is not (the control); a hub with a corrupted copy under honest metadata is caught by the sha256 check; anchor down refuses by default and falls back when allowed; stored metadata outlives the anchor; anchor 404 wins; lockfile refuses a hub that changes its answer after the commit was recorded; strict, record and verify modes; per repo trust: rule order, a repo the anchor lacks (404 by default, served and labelled `hub` when a rule allows it, pinned in the lockfile), a `hub` rule never asking the anchor, an anchor outage refused even under `anchor-or-hub`, a stronger source label kept; mutation checks (anchor disabled, lock check disabled, fall-through disabled, first-sight pinning disabled) fail the right tests.
- A mutation check: re-enabling web seeds on an agent with no peers makes the "big file stayed off the hub's HTTP" assertion fail.

Not tested, and the real risks:
- **Real huggingface.co.** The sandbox network is allowlisted, so every test uses a fake upstream. Real redirects, CDN behaviour, rate limits and Xet-backed repos are unverified. `tests/test_live_hf.py` is written for this: run `THUB_LIVE=1 python -m pytest tests/test_live_hf.py -s` on a machine with internet. It compares a mirrored download of a small public repo, file by file, against a direct download. It has never been run, so treat its first result as a finding, not a regression.
- **Large files.** Tests use 3.5 MiB. Streaming removes the "wait for the whole file" problem in principle, but nothing has been run at multi-GB scale. Memory, disk throughput and client timeouts at that size are unknown. The holdback means the final 64 KiB arrives only after hashing finishes, which on a large file is a short pause at the end.
- **Real swarm conditions.** DHT, trackers, NAT traversal and seeder persistence over the internet. Every swarm test runs on loopback with static peer hints and DHT off. Peer discovery through a tracker or DHT has not been exercised at all, so whether agents find each other on a real network is unproven. An agent behind NAT that cannot accept connections will download but contribute little.
- **Streaming from a file libtorrent is still writing.** The gateway reads the file with ordinary reads while libtorrent writes it. Each piece is checked against the torrent's hash after the read, so a read that sees stale or missing bytes aborts the stream instead of sending them. That check is unit tested with a deliberately corrupted file, but it has never fired in a real run, so I do not know how often a real read-back races a write. Also untried: multi-GB files, other platforms, and other libtorrent disk I/O backends. Pieces up to 16 MiB are held in memory per reader.
- **Federation beyond loopback.** Every federation test uses one fake origin and hubs that mirror it. Real hubs that drift apart, partial outages, slow upstreams and hubs run by different people have not been seen. Colluding or jointly compromised hubs pass a quorum by definition.
- **A seeding race I did not explain.** In tests, an agent that connected to a hub within about half a second of the hub finishing its download got no peer handshake and fell back to HTTP, even though libtorrent reported the hub as seeding. The test helper now waits half a second after the hub reports seeding. I do not know whether this is a libtorrent seed_mode behaviour, something in how the seed is added, or a test artefact. In the field the effect is a safe fallback to HTTP, but it may cost the swarm saving for a freshly mirrored blob.
- **Concurrency and scale.** Hashing runs in a thread per 1 MiB chunk. One lock per blob. SQLite behind a mutex. Fine for a prototype, not tuned.
- **Eviction races.** Eviction skips in-flight downloads and the blob just finished, but a reader that opened a file just before it is evicted relies on the OS keeping the unlinked file readable (true on Linux and macOS).

## 10. Roadmap

Built (phases 1 to 5): the gateway, agent mode, federation, the trust model (anchor, lockfile, per repo trust, creator signatures), and the validation kit. See sections 6 to 6d.

The direction since then is **participants**: humans and AI agents on equal terms, publishing, checking each other's work, and asking for work. The full design is in `PROTOCOL.md` (v0.1, design only). It rests on four rules: correctness never depends on filtering, trust is local and computed from keys the consumer pins, claims are classed by how they can be verified (recompute, re-run, or self-reported), and control (signed events) is separate from bytes (BitTorrent).

| Phase | Work | Gate to move on |
|---|---|---|
| V | Run `validation/` on real Hugging Face (including Xet backed repos) and on two real machines. Measure the peer share. | Probe passes, live test matches, peers find each other, the peer share is worth having. If not, the design changes first. |
| P0 (passed 2026-10-16: kinds checked and assigned, policy format is TOML, decisions in section 11) | Review `PROTOCOL.md`, assign event kinds after rechecking the registry, decide the policy file format | Approval, and the open questions in `PROTOCOL.md` section 11 answered |
| P1 (built: events, trust evaluator with exact independence, store, admission, API, CLI, delegation in `signed:` rules, key rotation, hub sync, policy file; the rules that need derivations or manifest v2 wait for P3 and P4. See `PROTOCOL.md` section 12) | Event store and API, identity, delegation, endorsement and revocation events, the trust evaluator, policy engine, admission control | The sybil, collusion, revocation, taint and order independence simulations pass |
| P2 (built: see `PROTOCOL.md` section 13; `eval` and class R not built) | Attestations (`hash_verified`, `format_scan`), a verifier agent, replication events, a signer process with limits, and the MCP write tools (the read and download MCP server, `torrenthub mcp`, already exists; `PROTOCOL.md` section 8a) | A verifier agent publishes and a consumer's behaviour changes because of it. A bad attestor is caught. |
| P3 (built, see `PROTOCOL.md` section 14: derivation events, lineage, taint, synthetic depth, `[lineage]` policy, determinism harness; gate only partly met, one physical machine) | Reproducible derivations (first measure bit exactness of one tool across machines) | Measured on two machines, or the tool stays self-reported |
| P4 (built, see `PROTOCOL.md` section 15: manifest v2, publish endpoint and command, quotas; gate met against a firewalled publisher, not a real router) | Publishing path for artifacts, quotas, manifest v2 (`seq`, `valid_until`, large tables as blobs) | A publisher behind NAT gets an artifact onto a hub and an agent fetches it fully verified |
| P5 (built, see `PROTOCOL.md` section 16: request, claim and result events, the judging rule, `torrenthub request` and `work`, freshness rules; gate met on two machines with trust set up beforehand) | Requests, claims, results, freshness policies | Two agents complete a request cycle with no human step |
| P6 (built, see `PROTOCOL.md` section 17: relay client, push and pull, trust-following pull, a probe; gate met against a local strfry, not a public relay) | Nostr relay adapter | Events round trip through a real relay |

Still open from earlier work and carried into the plan: freshness and key rotation (P1, P4), an upload path (P4), a packaged daemon, scheduled `gc`, gated and private repos, datasets (all after V).

## 11. Decisions (P0, approved 2026-10-16)

Each can be revisited when validation or a real deployment gives data.

- **Who runs the index, and who pays for the first copy?** Whoever runs a hub pays for its own first copy. No shared index yet.
- **Public service or self-hosted tool?** Self-hosted first. A public service means takedown and abuse policy from day one, so it waits.
- **Which models first?** A small curated set of popular open-weight models, not all of Hugging Face.
- **Is agent mode acceptable given peer IP exposure?** Yes, as opt-in with a clear warning. The hub-only HTTP path stays the default.
