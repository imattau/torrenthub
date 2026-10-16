# Participants: a protocol sketch (v0.4, part built, P0 passed)

Status: P1 and P2 are built and tested (sections 12 and 13 say exactly what, and what is not): identity, delegation, endorsement, revocation and attestation events, the trust evaluator, the event store, admission control, the HTTP API, the CLI, the policy file, a verifier, replication, a signer and the MCP write tool. Derivations, requests, the publishing path and everything after P2 are still design only. Event kind numbers were checked against the NIPs registry on 2026-10-16 and are assigned in section 3. Nothing has been run against a real network or real participants, and the validation work in `validation/README.md` still comes first.

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
| 6 | Attestors may be wrong or become dishonest | Replication events: anyone re-runs an attestation and signs match or mismatch. A mismatch from a replicator the consumer trusts makes that consumer drop the attestor locally (section 13). Only the endorser can revoke an endorsement. Consumers can sample. | Costs compute. Cheap to check is not the same as free. |
| 7 | Models training on each other's output | Derivations and datasets declare data origin (`human`, `synthetic`, `mixed`, `unknown`) and carry a synthetic generation depth. Policies can cap depth. | Undeclared synthetic data cannot be seen. The depth is a lower bound. |
| 8 | Floods, and hub load | Admission control at the hub: size limits, per key rate limits, a small quota for strangers, a larger one for keys in the hub's own graph (section 7). Clients ignore anything outside their graph. | A determined flood still costs the hub something. It costs availability, not correctness. |
| 9 | Unsafe weight formats | Mechanical checks, class D: a `format_scan` attestation, and a hub or consumer policy that refuses pickle based formats unless a trusted scan exists (section 4). | Scans catch known bad patterns, not all malicious content. |
| 10 | Licences on derivatives | Derivation events carry the licence of each input and the declared licence of the output. Policies can reject incompatible combinations. | Declared, not verified (class S), and the legal analysis is not something software decides. |
| 11 | Work coordination | Request, claim and result events (section 3.8). Payment is outside the protocol: a request may carry an opaque pointer for settlement. | Who pays for compute is unsolved. Claims are advisory and can be wasted. |
| 12 | Branch names go stale (a hub withholds a newer manifest) | Manifest v2 gets `seq` and `valid_until`. A policy can require a head newer than a maximum age. | The creator going offline makes a repo unfetchable once it expires. Optional per rule. |
| 13 | Key loss and compromise | Identity events with a recovery key declared in advance, and key rotation by supersession (section 3.1). | A key stolen before a recovery key was declared cannot be fixed by the protocol. Consumers re-pin. |
| 14 | Event size on relays | A manifest's file table moves into a blob when large. The event carries its hash and infohash. | I do not know relays' real size limits. To be checked before relying on relays. |

## 3. Event types

Common to all events: the NIP-01 layout already in `signing.py` (id, pubkey, created_at, kind, tags, content, sig). Kinds are in the addressable range (30000 to 39999). On 2026-10-16 the NIPs README kinds table, and the repo's open and closed pull requests, issues and code, had no entry or mention of the numbers below (the table has no kinds in 36000 to 36999; its nearest rows are 37516 and 37517). Using a number does not reserve it: nobody has registered these, and anyone can publish a conflicting NIP. If this protocol is adopted outside this project, propose a NIP and move the numbers if asked. They are defined in one place each (`manifest.py`, `events.py`).

| Kind | Event | Status |
|---|---|---|
| 36777 | `manifest` | built |
| 36778 | `identity` | built |
| 36779 | `delegation` | built |
| 36780 | `endorsement` | built |
| 36781 | `revocation` | built |
| 36782 | `attestation` | built |
| 36783 | `derivation` | built |
| 36784 | `request` | built |
| 36785 | `claim` | built |
| 36786 | `result` | built |

A change to an event's fields that old readers cannot parse bumps its content `v` field. It does not get a new kind.

Every event built here carries a `d` tag made from its content (`d` = the first 32 hex characters of the sha256 of the content), unless it has one already (manifests do: `repo@commit`). This is not cosmetic. These kinds are in NIP-01's addressable range, where a relay keeps only the latest event per kind, key and `d` tag and treats a missing `d` as empty. Without the tag a relay holds one endorsement per key, one attestation per key, one request per key. Measured against strfry 1.1.3, which collapsed three tagless endorsements from one key into one and kept all three tagged ones (section 17). Events from before the change still parse and verify; they just must not be sent to a relay.

References to content use the tag names NIP-94 (file metadata) already uses, so existing tools can read them: `x` is a sha256 of a file, `i` is a torrent infohash, `magnet` is an optional magnet URI. References to other events use `e`. `content` is ASCII JSON with a version field, as the manifest already is.

### 3.1 `identity`
Key, optional recovery key, label, optional contact or operator note. `supersedes` points to an older identity event of the same key or of a key whose recovery key signs this. Only the first identity event of a key is taken on trust by anyone. After that, a change needs the old key or its declared recovery key. Moving a key's standing to a new key is done with a `revocation` that names a `successor` (section 3.7), not with this event.

### 3.2 `manifest` (exists)
A repo's file table at a commit, signed by the namespace owner. v2 (built, section 15) adds `seq` (strictly increasing per repo and ref), `valid_until` (optional), and `files_x`/`files_i` to move a large table into a blob. A consumer ranks manifests by `seq` first, so a replayed old manifest loses whatever its timestamp says.

### 3.3 `delegation`
Issuer authorises a key to act for it. Fields: `subject` key, `scope` (a list such as `publish:acme/*`, `attest:*`), limits (`max_bytes_per_day`, `max_events_per_day`), `not_before`, `expires`, `revocable` (always true in v1), `redelegable` (may the delegate pass the authority on; default false). A manifest signed by a delegate is valid for a rule `acme/*=signed:ROOT` when a chain of unexpired, unrevoked delegations covers `publish:<repo>` from ROOT to the signer. Delegation transfers authority. Anyone can verify it from the root alone. It is not an opinion.

### 3.4 `endorsement`
"I trust key K for these scopes." Fields: `subject` key, `scope` list, `weight` in (0, 1], `delegable` (may K's own endorsements count onward), `expires`. An endorsement is an opinion and is weighed, never obeyed. Different from delegation: delegation says K acts as me, endorsement says I think K is reliable.

### 3.5 `derivation`
Outputs made from inputs. Fields: `inputs` (each with `x`), `outputs` (each with `x`, `i`, `size`), `recipe` (`tool`, `tool_x` hash of the tool or its container, `args`), `data_origin`, `synthetic_depth`, `licences`. Class D if and only if the consumer has the tool's hash on its list of tools it trusts to be bit exact. Otherwise class S. Built (section 14): a consumer believes a derivation's lineage only from keys it trusts for scope `derive`, because a false one could taint an innocent blob.

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
Target is an event id, a blob `x`, a key, or a delegation or endorsement. Fields: `reason`, `severity`, `taint` (true means descendants of a blob count as affected), and for a key target an optional `successor`. A revocation with a successor is a key rotation: the old key is revoked, and the endorsements and delegations that pointed at it now point at the successor. What the old key issued stays revoked; the successor issues its own. If the old key declared a recovery key, only the recovery key can name the successor, so a thief holding the old key cannot. If it declared none, the key can name it. The earliest valid statement wins, and a consumer's own roots are never replaced this way. Valid from the target's issuer, from the namespace owner for things in the namespace, or from a key the consumer trusts for scope `revoke`.

### 3.8 `request`, `claim`, `result`
Request: task type, inputs by hash, a spec hash, deadline, optional reward pointer. Claim: advisory "I am working on request `e`". Result: an artifact or attestation event referencing the request. Built (section 16). A requester judges results by its own policy, usually by replication. NIP-90 (data vending machines) covers similar ground but the NIPs README marks it unrecommended, so this is its own small design, kept small on purpose.

## 4. Policy

A consumer's policy is a file. Rules say what must hold before a thing is used. The format is TOML, one file per gateway (`THUB_POLICY`, section 11 item 1), and the `[[file]]` rules for `require` (a claim, `independent`, `min_trust`), `deny` and `allow` are built (section 13). A `[lineage]` table with `on_tainted`, `max_synthetic_depth`, `min_trust` and `trusted_tools` is also built (section 14). A per-rule `max_age` and a `[freshness]` table with `manifest_max_age` are built too (section 16), so every rule type below is built. The rule types are:

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

Independence for `independent(n)`: take the qualifying attestors and choose the best path for each. Two are independent if their paths share no intermediate key. The search considers every admissible path of each attestor (hop limit, delegable edges, scope and weight all respected) and finds the largest set whose paths share no intermediate key, by branch and bound. Plain max flow does not fit because of the hop limit and the weight threshold. If the search passes a step budget it stops, says the answer is not exact, and returns at least the greedy answer.

Properties this is meant to have, each of which becomes a test:
- Keys with no path from your roots have trust 0, however many there are or what they say about each other.
- A cluster of colluding keys reachable through a single honest endorsement has trust at most that edge's weight, and its members all share that key, so they never satisfy `independent(2)`.
- Revoking one edge removes everything that depended on it and nothing else.
- Adding events never changes an answer except by adding trust paths or revocations that actually apply.

What this is not: PageRank or any score that more keys can inflate. That choice is deliberate.

## 6. Verification and the three classes

- **D, recompute.** The checker redoes the step and compares hashes. It works only for operations that are bit exact. First measurements are in section 14: an integer cast and a float reduction were bit exact everywhere tried, a float32 matrix product was not. Quantisation and merging may differ between CPUs and GPUs too, and that has to be measured per tool before any tool is put on a trusted list.
- **R, re-run within tolerance.** Evals with a fixed code hash, data hash and seed. Different hardware can shift numbers slightly, so a replication states a tolerance.
- **S, self-reported.** Recorded, shown, never relied on by default.

A hub or agent can run a **verifier**: it watches for new blobs and attestations, performs the D checks and a sample of R checks, and publishes replication events. That is the first useful agent role and it needs no storage beyond the evidence it publishes.

## 7. Storage, API and admission

- Store events as JSON, indexed by id, kind, author, and the `x`, `i`, `e` tags they reference. SQLite is enough to start. The manifest folder today becomes one case of this.
- `GET /api/thub/events` with filters (kinds, authors, referenced `x`, `e`, `i`, since, limit). This generalises the manifest endpoint and has the same shape as a Nostr REQ filter, so a relay adapter is easy later.
- `POST /api/thub/events` is a new attack surface and the reason admission control exists. Order of checks: size limit, valid id and signature, known kind, per key token bucket, then tiering. A key in the hub's own trust graph goes in the main store with a large quota. A stranger goes to quarantine with a small quota and a short life. Quarantined events are served only on request.
- The delegation's `limits` are enforced by the hub that admits events for that delegate, since limits cannot be enforced by the signature itself.
- Publishing an artifact (built, section 15): the publisher signs a v2 manifest, posts it to `POST /api/thub/publish` with the torrents of its big files, and seeds them. The hub validates, joins each swarm, and the publisher **dials the hub**, so the publisher needs no open port. The hub then checks every byte against the signed sha256 before anything becomes visible.

## 8. Transport

HTTP hubs first, and a Nostr relay adapter now (built, section 17): events are already in the relay format. Relays' real limits are measured in section 17, which is why item 14 above moves large tables into blobs. Where it fits, align with existing NIPs and do not reinvent them. From the NIPs README: NIP-94 gives the `x`, `i` and `magnet` tags. NIP-32 labels target events, people and topics, not blob hashes, so it is not a direct fit for attestations. NIP-85 shows the pattern of delegating trust computation to declared providers, but its kinds are for social metrics. NIP-13 proof of work is an optional extra for admission. NIP-26 delegated signing and NIP-90 data vending machines are marked unrecommended there.

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
| P0 (passed 2026-10-16: approved, decisions in `ARCHITECTURE.md` section 11) | Review this document. Assign kind numbers after rechecking the registry. Policy format decided (section 11). | You approve, open questions in section 11 answered |
| P1 (built, section 12; the rules that need derivations or manifest v2 wait for P3 and P4) | Generalise to an event store and API. Identity, delegation, endorsement and revocation events. The trust evaluator and policy engine. CLI. Admission control. | The simulation tests in section 9 pass, including order independence and the sybil and collusion cases, with timings for a large event set |
| P2 (built, section 13) | Attestations: `hash_verified` and `format_scan`, a verifier agent, replication events, `independent(n)`, a signer process, and the MCP write tools (read and download tools already exist, M0) | A verifier agent publishes, a consumer policy changes behaviour because of it, and a bad attestor is caught by replication |
| P3 (built, section 14; the gate is only partly met) | Derivations. First test determinism of one tool across machines. Only then put it on a trusted list. | Bit exactness measured on at least two different machines, or the tool stays class S |
| P4 (built, section 15; gate met in a simulation of NAT, not behind a real router) | Publishing path for artifacts (seed, announce, hub pulls by infohash), quotas, manifest v2 with `seq`, `valid_until`, `files_x` | A publisher behind NAT gets an artifact onto a hub, and an agent fetches it with full verification |
| P5 (built, section 16; gate met on two machines, with trust set up beforehand) | Requests, claims, results. Freshness policies. Payments stay outside. | Two agents complete a request cycle with no human step |
| P6 (built, section 17; gate met against a local strfry and a lenient relay, not a public one) | Nostr relay adapter | Events round trip through a real relay, with size limits known |
| H1 (built, section 18; `HOSTING.md`) | Git backed publishing: manifest v3, `publish --git`, the hub derives the file table from the git objects | A git repo with pointers is published from behind a firewall and fetched verified; hostile packs are refused |

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
- Policy rules that need other phases: `max synthetic_depth`, `on tainted` and `accept tools` need derivations (P3); `max_age` needs manifest v2 (P4). `identity` events carry a `supersedes` tag that nothing reads; rotation uses the revocation's `successor` instead.
- Gossip, automatic push and relays. Sync is on demand.

**Added after the first slice (2026-10-16)**
- Key rotation: `torrenthub revoke --kind key --target OLD --successor NEW`, signed by the old key or its recovery key. Rules in section 3.7. Chains of rotations are followed up to 8 deep, loops and revoked successors inherit nothing, and the answer does not depend on event order. A thief of a key with no declared recovery key can still rotate it to themselves, and can backdate (`created_at` is the signer's own clock). The protocol cannot fix that; declare a recovery key.
- Exact independence (section 5), checked against a separate brute force on random graphs. On a 9,000 event graph with 500 trusted keys, asking for 2 to 50 independent attestors answers exactly in under 10 ms. Asking for more than can exist runs out of budget after about 0.13 s and reports not exact.
- `torrenthub events-sync URL [--pull-only|--push-only]` (`sync.py`): pulls what the peer has, admitting trust edges first, then pushes the main-tier events the peer lacks. Every event is checked again on admission at the receiving end. An event whose author is not yet a member is quarantined and promoted when the author joins, so two hubs may need a few rounds to settle. Only the main tier travels. `events-pull` now includes attestations by default.

**Known limits**
- Sync pages with `until`, which is inclusive. More than 500 events in one second from one peer would stall the walk. Nothing has been synced between hubs on separate machines.
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
  - Pickle based files (including the pickles inside a torch zip file): scanned by running the real unpickler with every import routed to one function that returns inert stand-ins (`thub-scan-pickle/2`; the first version read opcodes with a simplified model and was replaced, see `SECURITY.md`). Every import must be on a short list of tensor rebuild functions. Every pickle a loader would read is scanned. Anything else, or anything unreadable, fails.
  - `.gguf`: magic and version only.
  - Other file types get no scan.
- The signer (`signer`): the only process that holds the key. It signs a fixed set of operations, recomputes the check itself from a file it is pointed at (so a caller cannot get a false pass signed), only reads files under one folder, has per hour and per day limits that survive a restart, can be given an end time, and logs every decision. Its Unix socket is mode 0600.
- MCP: `get_verdict` (always), and `attest_file` (only with `--signer SOCKET`). `attest_file` downloads the file, has the signer check it, and posts the signed result. The agent never sees a key and cannot choose the result. It returns `all_checks_passed` and a plain `summary` ("CHECK FAILED, do not load this file: ..."), because the gateway saying "accepted" only means it stored the statement. I found that gap by driving the real server over stdio as an agent would, after the scripted tests had passed. It has not been driven by a real LLM client yet.

**Not built, or limited**
- `eval` attestations and re-running evals (class R). No tolerance handling exists.
- A `require` rule cannot be met by a file without a sha256 (small files git stores directly). It refuses such a file and says why.
- Policy is enforced on `resolve` only. The web seed, torrent and swarm listing endpoints do not check it, so a gateway still seeds content its own policy would refuse to serve to its users. Use `block` to stop seeding.
- The pickle scan is a list of allowed imports. It will fail many legitimate non torch pickles (sklearn, numpy arrays) and it does not look inside the tensor data. It is exact for CPython's unpickler; another pickle library may read the same bytes differently. What an allowed function does with hostile arguments is not examined.
- The signer protects against an agent. It does not protect against other code running as the same user, which can read the key file or use the socket. It has no per request approval step.
- A refuted attestor is dropped for every claim. There is no way back except the attestor's key being re-vouched under a new key.
- The verifier needs the bytes. Unattested content is refused before it is fetched, so a verifier must get it elsewhere (its own gateway without a policy, or `torrenthub mirror`). That is a deliberate order of checks, and it means a new file waits for someone to attest it.
- Everything ran on a fake origin on loopback. Nothing has been tried with real attestors, real models or real torch files.

## 14. What is built (P3)

Code: the `derivation` event in `events.py` (kind 36783), lineage in `trust.py` (`Graph.parents`, `children`, `ancestors`, `tainted_descendants`, `synthetic_depth`, `derivation_class`), the `[lineage]` table in `policy.py`, `torrenthub derive` and `torrenthub lineage`, `GET /api/thub/lineage/<sha256>`, and `validation/determinism.py`. Tests: `tests/test_lineage.py`, `tests/test_determinism.py`. Raw measurements: `validation/results/determinism-2026-10-16.jsonl`.

**Built and tested**
- The derivation event: inputs and outputs by sha256 (outputs may carry an infohash and size), a recipe (tool name, `tool_x` hash, arguments up to 2000 bytes), `data_origin`, `synthetic_depth` (0 to 64) and licences. Signed tags must match the content, and events can be found by any blob they mention.
- Lineage counts only from keys that are roots or trusted for scope `derive`. A stranger's claim that an innocent blob came from a bad one cannot taint it (tested), and a stranger cannot lower a blob's synthetic depth.
- Taint: a blob revoked with `taint` makes every descendant, through trusted derivations and across any number of steps, `descended`. Revocation without taint does not reach descendants. Cycles end. The answers do not depend on event order.
- Synthetic depth is a lower bound: the largest depth a trusted derivation declares for a blob, or one more than an input's depth when the derivation's data is `synthetic` or `mixed`.
- `[lineage]` in the policy file: `on_tainted = "refuse" | "warn"` (default refuse; warn serves the file with an `X-Thub-Warning` header), `max_synthetic_depth`, `min_trust` for `derive`, and `trusted_tools`. These run before the file rules, so no `allow` rule overrides a taint. Refusals use error codes `Tainted` and `SyntheticDepth`.
- Class: a derivation is D for a gateway whose `trusted_tools` lists its `tool_x`, otherwise S. The lineage API shows each derivation's class.

**Measured: is a tool bit exact across environments?** Three tools, one input (a 4 tensor float32 safetensors file, sha256 `a768f6fc98f9...`), 117 runs:

| Tool | Result |
|---|---|
| `bf16_cast` (float32 to bfloat16, integer round to nearest even) | Bit exact in all 39 runs |
| `rms_norm` (a float reduction) | Bit exact in all 39 runs |
| `gram` (float32 `W @ W.T` through OpenBLAS) | 7 distinct outputs in 39 runs: not bit exact |

The 39 runs per tool covered: this host (numpy 2.5.4 and 2.4.6), a Debian 12 VM with the host's CPU model (Python 3.11), a VM whose CPU is a Nehalem class model without AVX or FMA, OpenBLAS kernels forced to Prescott, Nehalem, Sandybridge, Haswell and Zen, and 1, 4 and 20 threads. What decided `gram`: the BLAS kernel (the Nehalem class VM, choosing its own kernel, matched the host forced to Nehalem, so forcing is a fair stand in), and the thread count, even on one machine with one kernel. Single threaded runs with the same kernel agreed between the host and the VM. Multi threaded runs did not, because the VM has 2 cores and the host 20. So `gram` can only be class D in an environment that pins the kernel and one thread, and I would not list it. `bf16_cast` and `rms_norm` have no such dependence in these runs. The harness checks `bf16_cast` against the definition (ties to even, NaN, infinity, overflow) and against an independent rounding of random values.

**The P3 gate is only partly met.** It asks for bit exactness measured on at least two different machines. Everything here ran on one physical machine (a Core i5-14600K), with different operating system, Python and library builds, a different virtual CPU model and forced kernels. That is real evidence and it is not two machines: a different CPU vendor, a GPU, or a different BLAS build could still disagree. Until the harness has been run on a second physical machine, `bf16_cast` and `rms_norm` stay on no list, and every derivation is class S. To finish the gate, on the other machine:

```
python3 validation/determinism.py make-input input.safetensors
python3 validation/determinism.py run bf16_cast input.safetensors out.safetensors >> mine.jsonl   # and rms_norm
python3 validation/determinism.py compare validation/results/determinism-2026-10-16.jsonl mine.jsonl
```

`make-input` is seeded, so the input file should come out with the same sha256 (`a768f6fc...`). If it does not (a different numpy random generator), copy the input file from this repo's run instead. Then `BIT EXACT` for a tool on that line means it passed. The tool hash to list would be the sha256 of the exact `determinism.py` used (`0e907d9b...` for the file in this commit), since the tools share one file.

**Not built**
- Replication of derivations: a verifier that re-runs a class D tool on the inputs and signs match or mismatch against the derivation event. Without it, class D means "a consumer would accept a recomputation", and nobody has recomputed. `replication` attestations refer to attestation events only.
- Licence checks (`licences` is recorded and shown, nothing acts on it), data origin checks beyond the depth cap, and `max_age` (P4).
- Depth is only as good as the declared data: undeclared synthetic data is invisible, and a derivation nobody trusted never reaches the graph. Hiding lineage hides taint.
- The measured tools run on CPUs and numpy only. GPUs, quantisers such as GGUF and GPTQ, and merging tools are untested.

## 15. What is built (P4)

Code: `manifest.py` (version 2), `publish.py` (the hub's side), `publisher.py` and the `torrenthub publish` command (the publisher's side), `Store` tables `published` and `publish_charges`, and the consumer changes in `upstream.py`. Endpoints: `POST /api/thub/publish`, `GET /api/thub/publish/<job>`. Tests: `tests/test_manifest_v2.py`, `tests/test_publish.py`.

**Manifest v2**
- `seq` is a counter the creator controls (1 or more). Consumers pick the manifest with the highest `seq` for a branch name, then the newest timestamp, so a hub cannot make an old manifest win by replaying it (tested with an old `seq` carrying a fresher clock). Version 1 manifests count as `seq` 0.
- `valid_until` marks when a manifest stops being worth believing. A consumer ignores expired manifests when it resolves a **branch name**, and says `ManifestExpired` if none is left. A pinned commit sha is content addressed and is never refused for age. `THUB_MANIFEST_MAX_AGE` (seconds) additionally refuses a branch name whose newest manifest is older than that (`ManifestStale`).
- `files_x` replaces an inline file table with its sha256 once there are more than 200 rows. The table is a blob that the hub serves at `/blobs/<sha256>`; the consumer checks the bytes against the signed hash and the canonical encoding. `files_i` (an infohash for the table) is carried and checked for shape; nothing seeds the table by torrent yet.
- For a published repo the commit is the first 40 hex characters of the table's sha256, so it names the file table and two different tables cannot share a name.

**Publishing**
- The hub (`THUB_PUBLISH_QUOTA`, off at 0) checks, before taking any big file: the manifest signature; that the signer is a root or holds a delegation from one for `publish:<repo>` (a revoked signer is refused); that the manifest is v2, not expired and not dated in the future; that paths are safe and the commit names the table; that `seq` is above everything held for each branch name (an exact repeat is a no-op); each torrent against the piece policy, the signed size and the signed hash; and the signer's quota, counting only bytes the hub does not already hold. Small files (up to 3 MiB in all) travel in the request and are hashed on arrival.
- Big files: the hub starts a swarm download per torrent and the publisher, which has seeded and dialled the hub's swarm port, sends the bytes. Each finished file is hashed whole and compared with the signed sha256. Only when every file is in does the repo appear: charges, then commit and refs, then the manifest. A failed or stalled publication (`THUB_PUBLISH_STALL`, `THUB_PUBLISH_TIMEOUT`) leaves nothing a reader can see.
- Published blobs are never evicted by the disk budget, and a published repo is never re-asked of an upstream: the hub is where it lives.
- `torrenthub publish --repo OWNER/NAME --dir D --hub URL --key-file F` hashes the directory, signs, posts, seeds and waits. `--seq auto` asks the hub for the next number.

**Measured: the gate.** A publisher VM with a firewall dropping every inbound packet (the hub could not connect to it on any port, or ping it) published `Qwen/Qwen2.5-0.5B` (954 MB, 10 files) to a hub VM: 4.8 s of transfer, 10 s in all with hashing. An agent on the host that pins the publisher's key resolved it through the signed manifest and fetched it: 953 MiB at 258 MiB/s, 100% from the swarm, 0 fallbacks, 0 integrity failures, and all 10 files identical to the publisher's. An agent pinning a different key got `NoValidManifest`. This is a simulation of NAT: one virtual bridge, inbound blocked by the publisher's firewall, no address translation and no home router in between. What matters for the design (the hub cannot dial the publisher) is the same; things a real router adds (port mapping, timeouts of idle connections, carrier grade NAT) are untested. It also does not rely on discovery: the publisher knows the hub's address from the URL.

**Not built, or limited**
- No HTTP upload fallback. A hub with no swarm cannot take files over 3 MiB, and a publisher needs libtorrent.
- Quotas are per signing key on one hub. Nothing stops a publisher spending its quota on junk, there is no per-key request rate limit beyond two publications in flight, and a delegate shares nothing with its root.
- Removing a published repo or a branch name is not built (`block` removes a blob). Old commits stay pinnable after `seq` moves the branch.
- Publication jobs live in memory: a hub restart forgets one in flight (the publisher runs it again; held blobs are not charged twice).
- `THUB_MANIFEST_MAX_AGE` is an environment setting, not a rule in the policy file.
- A manifest the hub never receives cannot be told apart from one that does not exist, and a hub can still withhold the newest one. `valid_until`, a maximum age and asking several hubs reduce that; they do not remove it.
- Only publishing from the command line was exercised. Nothing signs or publishes through the signer process or the MCP server yet.

## 16. What is built (P5)

Code: the `request`, `claim` and `result` events in `events.py` (kinds 36784 to 36786), `Graph.request_status` and friends in `trust.py`, `workflow.py` (the requester, the worker and a participant's local view), `GET /api/thub/requests`, the commands `torrenthub request`, `requests` and `work`, and the freshness rules in `policy.py`. Tests: `tests/test_requests.py`, `tests/test_workflow.py`, plus one freshness test in `tests/test_publish.py`.

**The events**
- A request names a task (lowercase, up to 64 characters), up to 16 input blobs by sha256, arguments (up to 2000 bytes) or a spec hash, a deadline (after the request and within 30 days of it), what is wanted (`attestation` or `artifact`) and an optional `reward`: an opaque string, up to 200 characters, pointing at wherever settlement happens. The protocol moves no money and never reads the field.
- A claim says "I am working on this" until `expires`. It is advisory: it stops nobody else, proves nothing, and simply lapses.
- A result points at the request and carries a status (`done`, `failed`, `declined`). A `done` result carries attestation event ids the worker signed, or output blobs with an optional derivation event. Failed and declined results carry only a note.

**Who believes an answer** (`Graph.request_status`, judged by one consumer's own roots). A result counts when its author is trusted for scope `work:<task>`, it arrived by the deadline, and it holds up. For an attestation request, holding up means: every referenced attestation exists, was signed by the result's author, has the right claim, is about one of the request's inputs, and together they cover every input. For an artifact request it means the result lists outputs. An answer is accepted when `n` workers who are independent (the same test as for attestors: no shared voucher) gave the **same** answer; two different answers that each have enough backing are `disputed`, not resolved. Workers whose attestations a trusted replicator refuted count for nothing. States: `unknown`, `open`, `claimed`, `answered` (results exist, too few trusted workers agree), `accepted`, `disputed`, `expired`. Late results are ignored. A failed scan reported by a trusted worker is an accepted answer ("this file failed"), not a failure of the request.

**The cycle** (`workflow.py`). A requester posts a request and waits: it pulls events from the hub into its own store, so each event is checked again under its own roots, and judges there. A worker pulls the same way, takes requests whose author is a root or trusted for `request:<task>`, claims, fetches the blobs from the hub's `/blobs/<sha256>` (hashing as they arrive), runs the verifier's checks and posts the attestations and the result. Workers here do `hash_verified` and `format_scan`. The answer is an ordinary attestation, so a requester that does not trust a worker can still ask a trusted replicator, and the same attestation counts for any consumer's file policy. The hub lists requests at `GET /api/thub/requests` by its own roots; that is a convenience, and a stranger's requests stay in quarantine and out of the list.

**Freshness.** `max_age` on a `[[file]]` rule (seconds or `"30d"`, `"12h"`, `"90m"`, `"2w"`) means only attestations made within that long count, in both directions: an old failed scan stops blocking, an old pass stops satisfying, and a new one of either kind counts. `[freshness] manifest_max_age` in the policy file is the same limit as `THUB_MANIFEST_MAX_AGE` (P4), which wins if both are set. Request deadlines and claim expiries are the other freshness limits in this section.

**Measured.** Hub and worker on two VMs, requester on this host, a 954 MB published model on the hub, trust set up beforehand by an operator key (it endorsed the workers for `work:*` and `attest:*` and the requester for `request:*`):

| Cycle | Result |
|---|---|
| `hash_verified` of the 954 MB file, one worker (on a VM) | accepted in 11 s, states seen by the requester: open, claimed, accepted |
| `format_scan` of the same file (a real safetensors header check), two independent workers (one on a VM, one on this host) | accepted in 10 s, both keys named as the backing |
| A requester no one had endorsed | the hub put its request in quarantine, the command refused |

The gate asks for two agents to complete a request cycle with no human step. Nothing was approved while the cycle ran. The trust that lets it run (who may ask, who may answer) was set up by an operator beforehand, as everywhere else in this design; the protocol does not remove that step and a stranger cannot skip it.

**Not built, or limited**
- Workers do only the two verifier checks. Artifact requests (a worker making new blobs, publishing them with P4 and signing a derivation with P3) are judged by the same agreement rule and tested in the graph, but no worker implements one.
- Claims do not reserve anything. Two workers may do the same job, which is what a request for `n` independent answers wants and wasteful otherwise. A worker does not remember what it did across restarts, and skips a request only if it has answered it in this run or the hub already shows its result.
- Everything polls. There is no push, no relay, and a requester that goes away loses nothing but the wait.
- `disputed` is reported and left to the requester. The remedy this design offers is replication by a third trusted party, which a requester must ask for with another request.
- Request spam is limited only by admission control (a stranger's requests are quarantined; a member's are rate limited per key).
- A requester and the hub may disagree about a state, because the hub judges by its roots and the requester by its own.

## 17. What is built (P6)

Code: `relay.py` (the NIP-01 client, NIP-11 limits, NIP-42 answers, the probe), `relay_sync.py` (push, pull, pulling by following trust, manifests), the commands `relay-info`, `relay-check`, `relay-push` and `relay-pull`, and the `d` tag in `events.py`. Install the extra with `pip install 'torrenthub[relay]'` (it adds `websockets`). Tests: `tests/test_relay.py` (a strict fake relay, `tests/fake_relay.py`), `tests/test_relay_nak.py` (the `nak serve` relay), and `tests/test_relay_strfry.py` (opt in with `THUB_STRFRY_URL`). Raw measurements: `validation/results/strfry-1.1.3-probe-2026-10-16.json` and `nip11-public-relays-2026-10-16.json`.

**What it does**
- `relay-push` sends the main-tier events of a local store (and, with `--manifest-repo`, signed manifests) to a relay, waits for each OK, retries a "rate-limited" answer with backoff, and answers a NIP-42 `AUTH` challenge when given a key. Each event is first checked against the relay's published limits and a default 64 KiB event cap (below), so one that cannot fit is reported and skipped.
- `relay-pull` reads events and gives each to the same admission as an event from a hub: the signature is checked again and a stranger's event is quarantined. **The relay is trusted for nothing.** `--follow` asks only for keys the store's own roots already trust, and widens as trust grows (round one: the roots; round two: whom they endorsed; and so on). In a test with a stranger's events sitting on the relay, they were never requested. `--manifest-signer KEY --manifest-repo REPO` takes manifests from a named signer only.
- `relay-info` prints a relay's NIP-11 limits. `relay-check` sends probe events, signed by a throwaway key and tagged `t=torrenthub-probe`, to find what a relay really does, then asks it to delete them (NIP-09). Use it only on a relay you run.

**What was measured**

*The `d` tag.* Against strfry 1.1.3 (the relay software behind relay.damus.io, relay.primal.net and offchain.pub): three endorsements from one key with no `d` tag, strfry kept one; three with our content-derived `d` tag, it kept all three. `nak serve` (an in-memory relay on khatru) kept all of both, so a lenient relay would have hidden the problem. Every event kind (36777 to 36786) was accepted by both.

*Size limits, strfry 1.1.3 with its default configuration.* NIP-11 publishes `max_message_length` 131072 and nothing about event size. The probe found it takes a single event of at most about 64 KiB (65,541 bytes on the wire accepted, 69,646 refused with `invalid: event too large`) and up to somewhere between 1,026 and 4,098 tags (refused at 4,098 with `invalid: too many tags`). So the published limit is not the real one. The adapter's default guard skips events over 65,536 bytes; `--max-event-bytes 0` turns it off, and with it off strfry's refusal is reported (`{"invalid": 1}`), not hidden. A median OK took 3 ms on localhost.

*Published limits of public relays* (NIP-11 documents only; nothing was sent to them): relay.damus.io 1,000,000 bytes per message; relay.primal.net 1,000,000; relay.snort.social 524,288; nostr.wine 524,288, 4,000 tags, **payment required and writes restricted**; offchain.pub 131,072; nos.lol, relay.nostr.band and relay.nostr.bg publish no limits at all. Whether any of them takes these kinds was not tested.

*Our events against those limits* (wire size of `["EVENT", ...]`; typical, then the largest the parsers allow):

| Event | Typical | Largest legal |
|---|---|---|
| identity, revocation, attestation, claim | 0.5 to 0.7 KB | 1.0 to 1.3 KB |
| endorsement, delegation, request | 0.6 to 0.7 KB | 4.3 to 5.2 KB |
| result | 0.8 KB | 10.9 KB |
| derivation | 1.0 KB | 19.3 KB |
| manifest v2, file table in a blob | 0.8 KB at any repo size | n/a |
| manifest v2, 200 rows inline | 25 KB | n/a |
| manifest v1, 1,000 rows inline | 125 KB | n/a |

Every participant event fits under 64 KiB with room to spare. Manifests are the exception, and that is what `files_x` is for: a v1 manifest with 700 rows is over the 64 KiB cap that strfry enforces but under the 128 KiB it publishes, and the guard catches exactly that case.

*Round trips.* Every kind round-tripped through strfry into a second store (13 events, then again with all duplicates reported as such, then a second pull finding nothing new), manifests round-tripped with only the named signer taken, and `nak req` read back from strfry the same events we sent. The same held for `nak serve` and for the strict fake relay.

**How strfry was run, and why that matters.** The `docker.io/dockurr/strfry` image (215 MB) ships a configuration whose write policy rejects every key but a whitelist, which is not how open public relays behave. For these tests that plugin was switched off (`writePolicy.plugin = ""`) and every limit left at strfry's default. A public relay's own policy, rate limits and spam filters are unknown and may differ.

**Not built, or limited**
- Nothing was sent to a public relay, so whether relay.damus.io or any other accepts these kinds, or throttles them, is unknown. A relay that restricts writes or requires payment (nostr.wine does) will refuse unknown keys.
- No live subscription: a pull reads stored events and stops at EOSE. There is no follow-the-relay daemon and no background sync in the gateway; run the commands from a timer.
- NIP-42 `AUTH` was tested against the fake relay only. Proof of work (NIP-13) is not mined: a relay demanding it is reported as unfit. Relay discovery (NIP-65), paying relays and deletion of real events (NIP-09 is used only to clean up probes) are not built.
- Events stay valid forever on a relay that never deletes them. A revocation reaches a consumer only if the consumer asks a relay that holds it, which is the same withholding problem as with hubs.
- Pagination assumes a relay honours `until` and a `limit` up to its own cap; more than a page of events in one second from one key would stall the walk.
- Throughput and behaviour under load were not measured.

## 18. What is built (H1: git backed publishing)

Design and reasons: `HOSTING.md`. Code: `gitrepo.py` (running git safely, deriving a commit's file table, the publisher's helpers), `manifest.py` (`build_git_manifest`, version 3), the git branch of `publish.py`, `prepare_git` and `hub_heads` in `publisher.py`, `torrenthub publish --git`, and `GET /api/thub/git/<owner>/<name>/refs`. Tests: `tests/test_git_publish.py`.

**Manifest version 3.** `commit` is a git commit id. The signed content adds `git: {tree, parents, force}` and `table_sha256`, and keeps the file table (inline or as `files_x`) because readers use it. Readers verify it like version 2 (`seq`, `valid_until`, tags that must agree with the signed content). A version 3 manifest without a well formed `git` field, or whose `table_sha256` is not the hash of its table, is invalid.

**The table follows from the commit.** Big files are LFS pointer files in the tree (exactly three lines: version, `oid sha256:<64 lowercase hex>`, `size <decimal>`); anything that starts like a pointer and is not exactly one is refused. Every other file is a plain git blob and its row is its sha256. `gitrepo.derive` produces the rows the same way for the publisher and for the hub, and the hub refuses a manifest whose table differs.

**What the hub checks, in this order**, each with a test that fails when the check is removed: the manifest signature and the signer's authority (as before); the repo is not mixed (a repo is git backed or not from its first publication); `seq` (before any git runs); the pack is indexed in a throwaway repository with `git index-pack --strict --fix-thin` (no system or user config, no hooks, no templates, a time limit, a file size limit); the commit is present and the history complete; the tree has no symlinks, submodules, `.git` component, unsafe path, or two paths that differ only in case; no plain file is over `THUB_PUBLISH_GIT_BLOB_MAX`; the table, tree and parents match the manifest; each branch moves forward only (the new commit descends from the current head) unless the manifest says `force` **and** the hub has `THUB_PUBLISH_ALLOW_FORCE`. The branches are checked again after the transfer, immediately before they move, because another publication may have moved one meanwhile. Only when every file has arrived and been hashed does the hub keep the objects (a bare repository at `<data>/git/<owner>__<name>.git`, branches in `refs/heads`) and show the repo. The pack's size is charged to the signer's quota like a file.

**Publisher.** `prepare_git` reads the committed state of one commit (not the working tree), derives the table, builds a pack of what the hub lacks (the hub's branch heads come from the refs endpoint), and finds each big file's bytes in the working tree, in git-lfs's cache (`.git/lfs/objects`), in `.git/thub/objects`, or in a folder given with `--files-from`. Each file is hashed once and must match its pointer. A big file reachable from a commit the hub already holds is neither hashed nor sent.

**Measured.** On the VMs (publisher with every inbound packet dropped, as in section 15): a git repo of Qwen2.5-0.5B (9 files, 988 MB, weights as a pointer, the rest plain) published in 9.6 s in all, 4.0 s of it the hub pulling the weights; the served commit id was git's own, all nine files fetched through a stock `huggingface_hub` were identical to the publisher's, and the hub's repository passed `git fsck --strict`. A second commit (README edit) took under a second and sent no big file. A rewritten history was refused with `409 NotFastForward`.

**Not done, on purpose.**
- A consumer of the HF API cannot see the git objects. The table is still what readers verify; what the git objects add today is the history on the hub and the hub's refusal of a table that disagrees with the commit. The `commits` and `compare` endpoints, `torrenthub host`, a git remote helper and `git clone` are later stages (HOSTING.md).
- No `.gitattributes` filter writes pointers: use git-lfs, or write the three lines yourself. The hub needs no git-lfs.
- `index-pack` inflates what it receives. Measured: a 4.2 MB pack holding one 4 GiB file of zeros took 8.8 s to index; with a 3 s limit it was stopped after 3.0 s and left nothing (`THUB_PUBLISH_GIT_TIMEOUT`, default 60 s per command, two at a time; a test covers the limit). So a signer the hub has authorised can make it spend up to a minute of one core per publication. Strangers cannot: the authority check runs before any git command.
- A commit id is SHA-1. A colliding tree could carry different plain files under one id. Big files are bound by sha256. `table_sha256` is the second binding for the whole table.
- Removing a repo or rewriting it for a leaked file is not built. With `force` a branch can be moved, but the old objects stay in the hub's repository.
- Only the command line was exercised.
- A repo cannot change between git backed and not. Refused with `409 WrongKind`.
- Default limits: 100,000 objects of history, 32 MiB of pack, 8 MiB per plain file, 64 MiB of plain files in a commit, 5,000 files.
