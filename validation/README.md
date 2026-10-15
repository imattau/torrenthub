# Validating torrenthub against the real world

Everything so far has been tested on one machine, with a fake Hugging Face and 3.5 MiB files. These steps check the three things that decide whether the project is worth carrying on, and they need a real network. None of it has been run yet. The scripts themselves are tested against the fake origin (`tests/test_validation_kit.py`), so a surprise should be about the real world, not about the scripts.

You need Python 3.11 or newer for the gateway (the probe alone needs 3.9). Install with `pip install -e '.[swarm,dev]'` from the project folder. The `libtorrent` package is the BitTorrent engine.

## What each step decides

| Step | Question | If the answer is bad |
|---|---|---|
| 1. Probe | Does real Hugging Face give the mirror what it needs, including Xet-backed repos? | The mirror's core assumption (an advertised sha256 per large file) is wrong for some repos. The metadata and verification design changes. |
| 2. Live gateway test | Does a mirrored download match a direct one, byte for byte? | A real bug in redirect or header handling. Fix it first. |
| 3. Two machines | Do two real machines find each other and exchange data? | Peer discovery needs work (trackers, DHT, NAT, ports) before anything else matters. |
| 4. Measure | What share of bytes come from peers, and how fast? | A low peer share means there is no cost saving, and the idea needs rethinking or a smaller claim. |
| 5. Big model | Does it hold up at several GB? | Memory, disk or timeout problems that small files hide. |

Do them in order. Stop at the first bad answer and send me the output.

## 1. Probe the origin (5 minutes, no install)

Pick repos you have not used before. I have not checked that any particular repo exists or is Xet-backed. Use one that is old and one created recently, because recent repos are the more likely to be Xet-backed. Keep each under about 100 MB of its smallest large file.

```bash
python3 validation/probe_hf.py --repo OWNER/OLD_REPO --repo OWNER/RECENT_REPO --max-mb 100 --json probe.json
```

Read the output. `PASS` on R1 to R5 for every repo is what we need. Look at the `info` lines too: how many redirects, which hosts, whether the repo looks Xet-backed, and the first-hop headers. Send me `probe.json`.

## 2. Live gateway test

```bash
THUB_LIVE=1 THUB_LIVE_REPOS=OWNER/OLD_REPO,OWNER/RECENT_REPO python -m pytest tests/test_live_hf.py -s
```

This runs a gateway in the test, downloads each repo through it and directly, and compares every file. Add `HF_TOKEN=...` if you get rate limited (it is only ever sent to huggingface.co).

## 3. Two machines, real peer discovery

Machine H (hub) and machine A (agent), on different networks if you can. H needs to be reachable from A over HTTP and over the BitTorrent port (TCP and UDP). A does not need to be reachable by H, but it only contributes upload if it is.

On H:

```bash
export THUB_DATA=./hub-data
export THUB_PUBLIC_URL=http://H_ADDRESS:8080     # an address A can reach
export THUB_SWARM=libtorrent
export THUB_LISTEN_PORT=6881                     # open TCP and UDP 6881
export THUB_TRACKERS=udp://tracker.opentrackr.org:1337/announce   # is it up? I have not checked
torrenthub serve --port 8080
torrenthub mirror OWNER/OLD_REPO                 # download, verify, make torrents, start seeding
```

On A:

```bash
export THUB_DATA=./agent-data
export THUB_UPSTREAM=http://H_ADDRESS:8080
export THUB_SWARM=libtorrent
export THUB_SWARM_FIRST=true
export THUB_ANCHOR=none        # for this step only, so the origin is out of the picture
export THUB_PUBLIC_URL=http://A_ADDRESS:8080
torrenthub serve --port 8080
```

Check `curl http://H_ADDRESS:8080/metrics` and `curl http://H_ADDRESS:8080/healthz` from A first. Then run step 4. If the swarm never starts (the agent falls back to HTTP every time), separate "the transfer works" from "discovery works" by giving A a static hint:

```bash
export THUB_PEERS=H_ADDRESS:6881
```

If it works with `THUB_PEERS` and not without, discovery (tracker, DHT, firewall, NAT) is the problem, and that is a finding on its own.

## 4. Measure

On any machine that can reach A (not the cache that A uses):

```bash
python3 validation/measure.py --gateway http://A_ADDRESS:8080 --hub http://H_ADDRESS:8080 --repo OWNER/OLD_REPO --json measure.json
```

It prints the bytes the client got, how many came from peers and how many over HTTP, the peer share, fallbacks, and how much the hub served. A gateway must not already hold the repo, or the swarm is never asked (the script says "n/a" in that case). Use a fresh agent data directory for each run.

Then add a second agent B pointing at A instead of H and run it again. This is the case that matters for cost: the second download should lean on A and H together, and H's HTTP load should stay near zero.

Finally turn the anchor back on (remove `THUB_ANCHOR=none`, so agents ask huggingface.co for metadata) and repeat once, to check that the default agent setup works.

## 5. A big model

Choose something around 5 to 10 GB. You need that much disk on H, A and the client cache, so about three times the model size across the machines.

Run step 4's measure on it and watch:
- memory use of the `torrenthub` process on A (`ps` or `top`),
- time to first byte, and whether the last pause (the final 1 MiB is held back until the whole file is hashed) is noticeable,
- whether the client times out or retries,
- `thub_integrity_failures_total` and `thub_swarm_fallback_total` in `/metrics`.

## What to send back

- `probe.json` and the printed output of step 1
- the output of step 2
- for steps 3 to 5: the printed output and `measure.json` of each run, `curl http://A_ADDRESS:8080/metrics` and the same for H, and the last 100 lines of the agent and hub logs
- the two machines' rough network setup (home or datacentre, behind NAT or not, which ports are open)

I will not call anything proven until it has come back from a real run.

## Results so far

Run 2026-10-15/16 from one machine on a slow link (about 16 KB/s to 70 KB/s to huggingface.co).

| Step | Result |
|---|---|
| 1. Probe | PASS (R1 to R5) on `prajjwal1/bert-tiny`, `hf-internal-testing/tiny-random-LlamaForCausalLM`, `sshleifer/tiny-gpt2`. All three are Xet backed: `resolve` answers 302 to a CDN host with `x-xet-hash`, `x-linked-etag` equal to the advertised `lfs.sha256`, and Range requests work (206). |
| 2. Live gateway test | PASS on the same three repos, every file byte for byte. Needed two fixes first: 64 KiB upstream chunks and a 64 KiB holdback, because 1 MiB of each left slow-link clients without data for over 10s. |
| 3. Two machines | Not run |
| 4. Measure | Not run |
| 5. Big model | Not run. Largest file tested: 17.7 MB |

Not covered by the repos above: a recently created repo (the probe's own advice), gated repos, sharded weights, anything over 20 MB.
