# Participants: a protocol sketch (v0.3, part built)

Status: P1 and P2 are built and tested (sections 12 and 13 say exactly what, and what is not): identity, delegation, endorsement, revocation and attestation events, the trust evaluator, the event store, admission control, the HTTP API, the CLI, the policy file, a verifier, replication, a signer and the MCP write tool. Derivations, requests, the publishing path and everything after P2 are still design only. Event kind numbers are provisional. Nothing has been run against a real network or real participants, and the validation work in `validation/README.md` still comes first.

## 1. The idea

Humans and AI agents take part on equal terms: both can publish models and datasets, check each other's work, vouch for each other, and ask for work to be done. Agents will often work with other agents and no human in the loop.

So the protocol does not know who is a human. A participant is a keypair. It may carry a label (`human`, `agent`, `org`, `unspecified`), and the label is a claim that nothing depends on. The difference between a person and an agent exists only in what a consumer decides to accept.

Four rules follow from that, and the rest of this document depends on them:

1. **Correctness never depends on filtering.** A consumer decides what to believe from signed events and its own trust policy. Junk and spam can cost bandwidth and storage. They cannot change an answer.
2. **Trust is local.** There is no global reputation score. Each consumer starts from keys it pins itself and follows signed endorsements outward, with limits.
3. **Claims are classed by how they can be checked.** The system is plain about which statements are verified by recomputation, which are verified by re-running, and which are just the author's word.
4. **Bytes and control are separate.** Signed events carry identity, announcements and attestations. Bytes travel by BitTorrent, referenced by hash and infohash.

## 2. Issues and solutions

Each issue was raised in discussion. "Not solved" says what stays open.

| # | Issue | Solution | Not solved |
|---|---|---|---|
| 1 | Pinning every key by hand does not scale to thousands of agents | Endorsement events and a local trust evaluator (section 5) | Someone must still choose the roots. Wrong roots mean wrong answers. |
| 2 | One operator runs many keys that vouch for each other | Keys outside your trust graph count for nothing. Several keys behind one endorser do not count as independent. Attestations need evidence others can re-check (sections 5, 6). | An operator that earns real trust and then abuses it. The answer there is revocation and sampling (item 6). |
| 3 | "Trained on X" and other provenance cannot be verified | Claims are classed D (recompute), R (re-run, within tolerance) or S (self-reported). The class comes from the event type. Policies can demand a class (section 4). | S claims stay unverifiable. Provenance of training data stays a claim. |
| 4 | Someone is accountable for what an agent publishes | Signed delegation chains from an identifiable root, with scope, limits and expiry. Consumers can require a chain that ends at a key they know. | Legal responsibility is a question for whoever runs the hub and the agent. A protocol cannot settle it. |
| 5 | A bad model becomes the base of many others quickly | Revocation events with taint. Descendants are found through derivation links, and the consumer's policy decides what to do with them (section 4.6). | A backdoor nobody has found is not covered. Absence of a backdoor cannot be proven. |
| 6 | Attestors may be wrong or become dishonest | Replication events: anyone re-runs an attestation and signs match or mismatch. Mismatches lower the attestor's standing through revocation of the endorsement. Consumers can sample. | Costs compute. Cheap to check is not the same as free. |
| 7 | Models training on each other's output | Derivations and datasets declare data origin (`human`, `synthetic`, `mixed`, `unknown`) and carry a synthetic generation depth. Policies can cap depth. | Undeclared synthetic data cannot be seen. The depth is a lower bound. |
| 8 | Floods, and hub load | Admission control at the hub: size limits, per key rate limits, a small quota for strangers, a larger one for keys in the hub's own graph (section 7). Clients ignore anything outside their graph. | A determined flood still costs the hub something. It costs availability, not correctness. |
| 9 | Unsafe weight formats | Mechanical checks, class D: a `format_scan` attestation, and a hub or consumer policy that refuses pickle based formats unless a trusted scan exists (section 4). | Scans catch known bad patterns, not all malicious content. |
| 10 | Licences on derivatives | Derivation events carry the licence of each input and the declared licence of the output. Policies can reject incompatible combinations. | Declared, not verified (class S), and the legal analysis is not something software decides. |
| 11 | Work coordination | Request, claim and result events (section 3.8). Payment is outside the protocol: a request may carry an opaque pointer for settlement. | Who pays for compute is unsolved. Claims are advisory and can be wasted. |
| 12 | Branch names go stale (a hub withholds a newer manifest) | Manifest v2 gets `seq` and `valid_until`. A policy can require a head newer than a maximum age. | The creator going offline makes a repo unfetchable once it expires. Optional per rule. |
| 13 | Key loss and compromise | Identity events with a recovery key declared in advance, and key rotation by supersession (section 3.1). | A key stolen before a recovery key was declared cannot be fixed by the protocol. Consumers re-pin. |
| 14 | Event size on relays | A manifest's file table moves into a blob when large. The event carries its hash and infohash. | I do not know relays' real size limits. To be checked before relying on relays. |

## 3. Event types

Common to all events: the NIP-01 layout already in `signing.py` (id, pubkey, created_at, kind, tags, content, sig). Kind numbers are assigned at implementation time, in the addressable range, after checking the NIPs registry again. 36777 is the manifest today and is provisional.

References to content use the tag names NIP-94 (file metadata) already uses, so existing tools can read them: `x` is a sha256 of a file, `i` is a torrent infohash, `magnet` is an optional magnet URI. References to other events use `e`. `content` is ASCII JSON with a version field, as the manifest already is.

### 3.1 `identity`
Key, optional recovery key, label, optional contact or operator note. `supersedes` points to an older identity event of the same key or of a key whose recovery key signs this. Only the first identity event of a key is taken on trust by anyone. After that, a change needs the old key or its declared recovery key.

### 3.2 `manifest` (exists)
A repo's file table at a commit, signed by the namespace owner. v2 adds `seq` (strictly increasing per repo and ref), `valid_until` (optional), and `files_x`/`files_i` to move a large table into a blob.

### 3.3 `delegation`
Issuer authorises a key to act for it. Fields: `subject` key, `scope` (a list such as `publish:acme/*`, `attest:*`), limits (`max_bytes_per_day`, `max_events_per_day`), `not_before`, `expires`, `revocable` (always true in v1). A manifest signed by a delegate is valid for a rule `acme/*=signed:ROOT` when a chain of unexpired, unrevoked delegations covers `publish:<repo>` from ROOT to the signer. Delegation transfers authority. Anyone can verify it from the root alone. It is not an opinion.

### 3.4 `endorsement`
"I trust key K for these scopes." Fields: `subject` key, `scope` list, `weight` in (0, 1], `delegable` (may K's own endorsements count onward), `expires`. An endorsement is an opinion and is weighed, never obeyed. Different from delegation: delegation says K acts as me, endorsement says I think K is reliable.

### 3.5 `derivation`
Outputs made from inputs. Fields: `inputs` (each with `x`), `outputs` (each with `x`, `i`, `size`), `recipe` (`tool`, `tool_x` hash of the tool or its container, `args`), `data_origin`, `synthetic_depth`, `licences`. Class D if and only if the consumer has the tool's hash on its list of tools it trusts to be bit exact. Otherwise class S.

### 3.6 `attestation`
A statement about a subject (`x` blob or `e` event). Claim types and classes:

| Claim | Meaning | Class |
|---|---|---|
| `hash_verified` | I fetched it and the sha256 matches | D |
| `format_scan` | It parses as the declared format and has no known unsafe constructs | D |
| `replication` | I re-ran attestation `e` and the result matched, or did not | D or R |
| `eval` | I ran code `x1` on data `x2` against model `x3`, seed `s`, and measured these values | R |
| `licence_check` | The licences of inputs and output are compatible | S |
| `review` | A human or agent looked at it and says this | S |

The class is a function of the claim type and is not written by the author. Fields: `claim`, `method` (tool and tool hash), `result`, `evidence` (an `x` and `i` for a file with outputs that others can check).

### 3.7 `revocation`
Target is an event id, a blob `x`, a key, or a delegation or endorsement. Fields: `reason`, `severity`, `taint` (true means descendants of a blob count as affected). Valid from the target's issuer, from the namespace owner for things in the namespace, or from a key the consumer trusts for scope `revoke`.

### 3.8 `request`, `claim`, `result`
Request: task type, inputs by hash, a spec hash, deadline, optional reward pointer. Claim: advisory "I am working on request `e`". Result: an artifact or attestation event referencing the request. A requester judges results by its own policy, usually by replication. NIP-90 (data vending machines) covers similar ground but the NIPs README marks it unrecommended, so this is its own small design, kept small on purpose.

## 4. Policy

A consumer's policy is a file. Rules say what must hold before a thing is used. The format is not decided. The rule types are:

- `root`: keys pinned with weight 1.
- `require signed(root[, ...])` for a namespace, as `THUB_TRUST` does now, including delegation chains.
- `require anchor` for a namespace (the existing anchor).
- `require attest(claim, trust >= t)` for a blob.
- `require independent(n, claim)`: n attestations of that claim from keys whose best trust paths share no intermediate key.
- `require class(D|R)` for the claim.
- `deny formats(...)` or `require attest(format_scan)` before using these file types.
- `max synthetic_depth(n)`.
- `on tainted(refuse|warn)`.
- `max_age(head, duration)`.
- `accept tools(hashes)` as bit exact for class D derivations.

Example in words: for `acme/*` take manifests signed by Matt's key or delegates of it. For everything else, use the Hugging Face anchor. Refuse any blob that a trusted key has revoked, or whose ancestor was revoked with taint. Refuse pickle based weights unless two independent trusted keys attest a clean `format_scan`.

## 5. Trust evaluation

Nodes are keys. Edges are unexpired, unrevoked endorsements from truster to subject, with a scope set, a weight and a `delegable` flag.

`trust(K, scope)` is the largest product of edge weights over any path from a root to K such that every edge covers `scope`, every edge except the last is `delegable`, and the path has at most H hops (default 3). Roots have trust 1. Because weights are below 1, trust falls with distance. It is computed by best-first search and is deterministic: the same events give the same answer in any order. The result carries the path, so any decision can be explained.

Independence for `independent(n)`: take the qualifying attestors and choose the best path for each. Two are independent if their paths share no intermediate key. The first version does this greedily. A max flow method would be exact, and is a later improvement.

Properties this is meant to have, each of which becomes a test:
- Keys with no path from your roots have trust 0, however many there are or what they say about each other.
- A cluster of colluding keys reachable through a single honest endorsement has trust at most that edge's weight, and its members all share that key, so they never satisfy `independent(2)`.
- Revoking one edge removes everything that depended on it and nothing else.
- Adding events never changes an answer except by adding trust paths or revocations that actually apply.

What this is not: PageRank or any score that more keys can inflate. That choice is deliberate.

## 6. Verification and the three classes

- **D, recompute.** The checker redoes the step and compares hashes. It works only for operations that are bit exact. I do not know yet which are: format conversion with no arithmetic probably is. Quantisation and merging may differ between CPUs and GPUs, and that has to be measured per tool before any tool is put on a trusted list.
- **R, re-run within tolerance.** Evals with a fixed code hash, data hash and seed. Different hardware can shift numbers slightly, so a replication states a tolerance.
- **S, self-reported.** Recorded, shown, never relied on by default.

A hub or agent can run a **verifier**: it watches for new blobs and attestations, performs the D checks and a sample of R checks, and publishes replication events. That is the first useful agent role and it needs no storage beyond the evidence it publishes.

## 7. Storage, API and admission

- Store events as JSON, indexed by id, kind, author, and the `x`, `i`, `e` tags they reference. SQLite is enough to start. The manifest folder today becomes one case of this.
- `GET /api/thub/events` with filters (kinds, authors, referenced `x`, `e`, `i`, since, limit). This generalises the manifest endpoint and has the same shape as a Nostr REQ filter, so a relay adapter is easy later.
- `POST /api/thub/events` is a new attack surface and the reason admission control exists. Order of checks: size limit, valid id and signature, known kind, per key token bucket, then tiering. A key in the hub's own trust graph goes in the main store with a large quota. A stranger goes to quarantine with a small quota and a short life. Quarantined events are served only on request.
- The delegation's `limits` are enforced by the hub that admits events for that delegate, since limits cannot be enforced by the signature itself.
- Publishing an artifact needs no upload API: the publisher seeds the torrent and posts a manifest or derivation event. A hub that admits it fetches by infohash and validates against the signed hashes, the same way agents do now. I have not tested a hub pulling from a publisher it has no direct connection to. NAT and discovery make that harder than it sounds.

## 8. Transport

HTTP hubs first. A Nostr relay adapter later: events are already in the relay format. I have not checked relays' event size limits, which is why item 14 above moves large tables into blobs. Where it fits, align with existing NIPs and do not reinvent them. From the NIPs README: NIP-94 gives the `x`, `i` and `magnet` tags. NIP-32 labels target events, people and topics, not blob hashes, so it is not a direct fit for attestations. NIP-85 shows the pattern of delegating trust computation to declared providers, but its kinds are for social metrics. NIP-13 proof of work is an optional extra for admission. NIP-26 delegated signing and NIP-90 data vending machines are marked unrecommended there.

## 8a. Agent interface (MCP is optional)

Nothing in the protocol needs MCP. Participants talk through signed events over HTTP (later relays), and bytes move over BitTorrent. A plain script or daemon can take part with an HTTP client and a key.

MCP is one way to give an LLM driven agent tools for it: for example `find_model`, `fetch_and_verify`, `check_policy`, `attest`, `publish`, `list_requests`. A read and download version is built now (`torrenthub mcp`, milestone M0): `repo_info`, `check_trust`, `fetch_file`, `verify_file`, `gateway_status`. It is a thin client of the gateway's HTTP API. `attest_file` and `get_verdict` are added in P2 (section 13). `publish` and request tools are not built. Agents do not talk to each other over MCP. They read and write events.

Two rules for the adapter:
1. **Everything fetched from other participants is untrusted data.** Model cards, dataset text, request descriptions and attestations may contain instructions aimed at the agent. The adapter returns them as data, labelled with their source and trust, and no tool call is made on the strength of such text. Signing or publishing happens only for what the agent's own task and policy call for.
2. **The model does not hold the secret key.** Signing goes through a signer process that holds a delegate key and checks each request against that key's delegation: scope, size and rate limits, expiry. A compromised or confused agent can then do no more than its delegation allows, and the operator revokes the delegation to stop it.

M0 is tested with an in-process MCP client and a stdio client against real gateways. I have not tried it with a real LLM client such as Claude Desktop. `fetch_file` blocks until the download finishes and I have not checked how clients handle a call that runs for many minutes, which matters for large files. Hash failures, path traversal and the size cap are tested.

## 9. Threats and the test that answers each

| Threat | Test |
|---|---|
| A thousand sybil keys endorse each other and attest a bad model | Consumer with roots R sees no change in any answer |
| A colluding cluster gets one honest endorsement | Trust is capped at that edge's weight, `independent(2)` fails |
| A trusted attestor goes bad | One replication mismatch plus a revocation removes its effect, others unchanged |
| A backdoored base model with five levels of fine-tunes | A taint revocation marks every descendant, and the policy refuses them |
| Event reordering or replay | Same event set gives the same answer in any order |
| A stolen delegate key | Revoking the delegation invalidates its events. `created_at` is chosen by the signer, so a thief can backdate. Events are therefore judged by when this consumer or hub first saw them, and anything first seen after the revocation is rejected. Events seen before it stay valid unless the revocation says otherwise. |
| A hub withholds a revocation | Revocation fetched from several hubs, newest wins, and old manifests expire if `valid_until` is used |
| A fetched model card tells an agent to sign or publish something | The adapter returns it as labelled data, no tool call follows from it, and the signer refuses anything outside the delegation |
| A flood of events at a hub | Stranger quota holds, memory and disk stay bounded, trusted keys unaffected |
| Large tables | A manifest over the size limit uses `files_x`, and verifies the same |

The last gap in that table is the first one to watch: revocation can be withheld, and no signature scheme alone fixes that. The mitigation is asking several hubs, and expiry for repos that matter.

## 10. Plan

Validation (`validation/README.md`) is the gate. Nothing below is started until the probe, the live test, the two machine swarm test, and the peer share measurement have come back and show the basic idea holds. If they do not, the design changes first.

| Phase | Work | Gate to move on |
|---|---|---|
| V | Run the validation kit on real Hugging Face and real machines | Probe passes (including Xet backed repos), live test matches, peers find each other, peer share is worth having |
| P0 | Review this document. Assign kind numbers after rechecking the registry. Policy format decided (section 11). | You approve, open questions in section 11 answered |
| P1 (partly built, section 12) | Generalise to an event store and API. Identity, delegation, endorsement and revocation events. The trust evaluator and policy engine. CLI. Admission control. | The simulation tests in section 9 pass, including order independence and the sybil and collusion cases, with timings for a large event set |
| P2 (built, section 13) | Attestations: `hash_verified` and `format_scan`, a verifier agent, replication events, `independent(n)`, a signer process, and the MCP write tools (read and download tools already exist, M0) | A verifier agent publishes, a consumer policy changes behaviour because of it, and a bad attestor is caught by replication |
| P3 | Derivations. First test determinism of one tool across machines. Only then put it on a trusted list. | Bit exactness measured on at least two different machines, or the tool stays class S |
| P4 | Publishing path for artifacts (seed, announce, hub pulls by infohash), quotas, manifest v2 with `seq`, `valid_until`, `files_x` | A publisher behind NAT gets an artifact onto a hub, and an agent fetches it with full verification |
| P5 | Requests, claims, results. Freshness policies. Payments stay outside. | Two agents complete a request cycle with no human step |
| P6 | Nostr relay adapter | Events round trip through a real relay, with size limits known |

Public service questions (who pays for the first copy, takedown and abuse policy, IP exposure) stay open in `ARCHITECTURE.md` and are not answered by any phase above.

## 11. Open questions and the practical answer for each

These are decisions for now, chosen to be the smallest thing that works. Each can change when P1 or P2 gives real data.

1. **Policy format and location.** One TOML file per gateway (`THUB_POLICY`), the same idea as `THUB_TRUST` but with the section 4 rules. Rules are ordered, matched by repo glob, first match wins. A request can only make the policy stricter, never looser. A per-user policy is just a gateway you run yourself, so there is no separate per-user layer.
2. **Bit exact tools.** Treat none as bit exact until measured. The trusted tools list starts empty, so every derivation is class S (self-reported) and a consumer cannot lean on it. Measurement is the P3 gate.
3. **Relay limits.** Skip relays at first. P1 uses HTTP hubs only, with the existing event size and per-repo caps. Add a relay adapter after the HTTP path works, and read each relay's real limits then.
4. **First endorsement for strangers.** Vouching only. An operator endorses a new key from their root, with a narrow scope and an expiry. A new key at trust 0 can still publish and be fetched with hash checks, but any rule that needs `signed` or `attest` ignores it. Replicated work does not promote a key automatically. It counts only through `independent(n)` from keys you already trust. Revisit once P2 shows how much work actually gets replicated.
5. **Weights below 1.** No new feature. Scopes already do this. Roots default to weight 1 and an endorsement carries its own scope.
6. **Agents holding their own roots.** By default no. An agent acts through a delegate key under its operator's root, with an expiry and limits, held by the signer process. The operator's policy and pinned roots live in a file the agent's tools cannot write, and no MCP tool edits policy. An agent may keep its own roots for its own private reading policy, but that does not change what the operator's gateway believes.
7. **An agent acting against its operator.** The protocol cannot see intent, so it only limits damage: delegation expiry, signer rate and size limits, a signer audit log, and operator revocation of the delegate key. Anything beyond that is the operator's job.

## 12. What is built (P1, first slice)

Code: `events.py`, `trust.py`, `eventstore.py`, `admission.py`, `cli_events.py`, and endpoints in `app.py`. Tests: `tests/test_trust.py`, `tests/test_events_api.py`, `tests/test_delegation_signed.py`.

**Built and tested**
- Four event kinds, provisional numbers 36778 identity, 36779 delegation, 36780 endorsement, 36781 revocation. A look at the NIPs README showed nothing in 36770 to 36799. The full kinds registry was not checked.
- The trust evaluator (section 5) with the properties as tests: strangers and sybil swarms get 0, a cluster behind one endorsement is capped and not independent, a revoked edge removes only what depended on it, and the same events give the same answers in any order and with duplicates.
- Delegation chains, with expiry, `not_before`, scope, revocation and onward delegation. I added a `redelegable` flag to the delegation event (section 3.3 did not have one), so a delegate cannot pass authority on unless the delegation says so.
- Revocation in two passes. The issuer of an event, a key itself, or a key's declared recovery key can revoke without anyone's say so. Revocations by anyone else count only if the consumer trusts that key for scope `revoke`. A consumer's own roots cannot be revoked by others. Only a key's first identity event can name its recovery key.
- Admission control (section 7) in the order: size, structure and signature, kind, clock, per key token bucket, tier. Members go to `main`, strangers to `quarantine` with a small stored count and a time to live. A member's daily allowance is lowered by any delegation limit that names it. A stranger's events move to `main` if the stranger later joins the graph, so the result does not depend on arrival order.
- `POST` and `GET /api/thub/events`, `GET /api/thub/trust/<key>`, and the CLI: `identity`, `delegate`, `endorse`, `revoke`, `events-add`, `events-pull`, `events`, `trust`.
- A `signed:ROOT` rule now accepts manifests from any key the root has delegated `publish:<repo>` to, and stops accepting them when the delegation expires or is revoked. Keys named in `signed:` rules are roots for the event store, so they do not need listing in `THUB_ROOTS` as well.

**Not built**
- The policy file (section 4 and decision 1 in section 11). `THUB_TRUST` and `THUB_ROOTS` still do this job.
- Attestation, derivation, request, claim and result events, `independent(n)` as a policy rule (the function exists in `trust.py`), taint reaching descendants (needs derivations), manifest v2.
- Key rotation by identity supersession. An identity event can name a recovery key, which can revoke the old key, but there is no event that moves a key's standing to a new key.
- Event sync between hubs beyond `events-pull`, which pulls on demand. No gossip, no push, no relay.
- Exact independence (max flow). The greedy version gives a lower bound.

**Known limits**
- Signature checks are pure Python, about 20 ms each on the machine used here. Admission checks each event once, so a hub handles roughly 50 new events a second per core at best. Stored events are not checked again when the graph is rebuilt. A compiled secp256k1 library would be much faster and is not used.
- The graph is rebuilt from the whole `main` tier whenever it changes. A timing test with about 9,000 unsigned stand in events (3,000 keys, 500 of them trusted) builds the graph in about 0.1 s and answers a trust query for every key in about 0.3 s in total. I have not tested a graph from real participants.
- A key that is revoked has all its past and future edges ignored, with no regard to dates. That is simple and safe, and it also means an honest early record from a compromised key disappears.
- A stranger's events wait in quarantine for the time to live (24 hours by default) for the key to be vouched for. After that they are gone and must be sent again.

## 13. What is built (P2)

Code: `verifier.py`, `policy.py`, `signer.py`, the attestation parts of `events.py` and `trust.py`, and `get_verdict` and `attest_file` in `mcp_server.py`. Tests: `tests/test_attestation.py` (events, verdicts, scanners, policy, signer) and `tests/test_p2_flow.py` (real gateways over HTTP, the CLI, the signer socket and the MCP server).

**Built and tested**
- Attestation events (kind 36782, provisional) for `hash_verified`, `format_scan`, `replication`, plus the `eval`, `licence_check` and `review` types, which parse and can be stored but nothing here acts on them. The class (D, R, S) comes from the claim type. A policy cannot be satisfied by an S claim.
- `Graph.verdict(x, claim, n, min_trust)`: enough independent attestors, each trusted for scope `attest:<claim>` at the given level, say the claim holds. One trusted attestor reporting a failure makes the verdict negative whatever else is said. Strangers, wrong scope, revoked attestations and attestors behind a single voucher do not count.
- Replication: a key trusted for `attest:replication` that publishes `match: false` for someone's attestation makes that attestor count for nothing, for every claim, in that consumer's view. An untrusted replicator, or the attestor itself, has no effect. This is how a bad attestor is caught. The protocol sketch said a mismatch would lower the attestor's standing "through revocation of the endorsement". Nothing here revokes anyone's endorsement, since only the endorser can. Each consumer drops the refuted attestor on its own.
- The policy file (`THUB_POLICY`, TOML, see `policy.py`): ordered rules by repo glob and file name glob, with `require` (a claim, `independent`, `min_trust`), `deny` and `allow`. The gateway checks it on every `resolve`, before any bytes are fetched, and answers 403 `PolicyRefused` with the reason. Content revoked by a key the gateway trusts for `revoke` is refused first, whatever the rules say (403 `Revoked`). A bad policy file stops startup.
- The verifier (`verify-blobs`, `replicate`): hash check and format scans. A scan is not a guarantee.
  - `.safetensors`: header parses, tensors are contiguous and fill the file exactly, byte counts agree with dtype and shape.
  - Pickle based files (including the pickle inside a torch zip file): read opcode by opcode and never run. Every import must be on a short list of tensor rebuild functions. Anything else, or an import that cannot be worked out, fails.
  - `.gguf`: magic and version only.
  - Other file types get no scan.
- The signer (`signer`): the only process that holds the key. It signs a fixed set of operations, recomputes the check itself from a file it is pointed at (so a caller cannot get a false pass signed), only reads files under one folder, has per hour and per day limits that survive a restart, can be given an end time, and logs every decision. Its Unix socket is mode 0600.
- MCP: `get_verdict` (always), and `attest_file` (only with `--signer SOCKET`). `attest_file` downloads the file, has the signer check it, and posts the signed result. The agent never sees a key and cannot choose the result. It returns `all_checks_passed` and a plain `summary` ("CHECK FAILED, do not load this file: ..."), because the gateway saying "accepted" only means it stored the statement. I found that gap by driving the real server over stdio as an agent would, after the scripted tests had passed. It has not been driven by a real LLM client yet.

**Not built, or limited**
- `eval` attestations and re-running evals (class R). No tolerance handling exists.
- A `require` rule cannot be met by a file without a sha256 (small files git stores directly). It refuses such a file and says why.
- Policy is enforced on `resolve` only. The web seed, torrent and swarm listing endpoints do not check it, so a gateway still seeds content its own policy would refuse to serve to its users. Use `block` to stop seeding.
- The pickle scan is a list of allowed imports. It will fail many legitimate non torch pickles (sklearn, numpy arrays) and it does not look inside the tensor data. Malicious content that uses only allowed imports is not detected.
- The signer protects against an agent. It does not protect against other code running as the same user, which can read the key file or use the socket. It has no per request approval step.
- A refuted attestor is dropped for every claim. There is no way back except the attestor's key being re-vouched under a new key.
- The verifier needs the bytes. Unattested content is refused before it is fetched, so a verifier must get it elsewhere (its own gateway without a policy, or `torrenthub mirror`). That is a deliberate order of checks, and it means a new file waits for someone to attest it.
- Everything ran on a fake origin on loopback. Nothing has been tried with real attestors, real models or real torch files.

