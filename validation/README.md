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

Run 2026-10-15/16 from one machine. Steps 1 and 2 were first run over a congested Wi-Fi link (about 16 to 70 KB/s to huggingface.co, 75 to 140 ms to the router). That exposed real behaviour under slow links, fixed below. Once the machine was on Ethernet (about 5 MB/s to huggingface.co, 50 MB/s to CDNs, 0.5 ms to the router) the live check on the same three repos took 24 s instead of 194 s, with no client timeouts and a longest silence of 2.1 s.

| Step | Result |
|---|---|
| 1. Probe | PASS (R1 to R5) on `prajjwal1/bert-tiny`, `hf-internal-testing/tiny-random-LlamaForCausalLM`, `sshleifer/tiny-gpt2`. All three are Xet backed: `resolve` answers 302 to a CDN host with `x-xet-hash`, `x-linked-etag` equal to the advertised `lfs.sha256`, and Range requests work (206). |
| 2. Live gateway test | PASS on the same three repos, every file byte for byte. Needed two fixes first: 64 KiB upstream chunks and a 64 KiB holdback, because 1 MiB of each left slow-link clients without data for over 10s. |
| 3. Two machines | Partly. Two Debian 12 VMs (KVM, 2 vCPU, 2 GB) on a libvirt NAT network, hub and agent. **The transfer works. Discovery behind NAT does not, and I have not found out why.** See below. |
| 4. Measure | On the VMs: peer share **98.7%** on `bert-tiny` (the 1.3% is small files, which have no torrent), 0 fallbacks, 0 integrity failures. A second agent pulling through the first took 98.7% from peers and the hub served 0 bytes over HTTP. With the anchor on (metadata from huggingface.co) the same 98.7%. |
| 5. Big model | `Qwen/Qwen2.5-0.5B` (988 MB `model.safetensors`, Xet backed). Direct test through a gateway on this machine: byte for byte match, 27 s, longest silence 2.2 s. Over the swarm between the VMs: 953 MiB at 9.3 MiB/s, **98.9% from the peer**, no fallbacks, no integrity failures, peak memory 83 MiB (agent) and 87 MiB (hub). The same file over plain HTTP from the hub took 30 s (31.8 MiB/s), so the swarm path was about three times slower on this setup. Not tried above 1 GB. |

**What the VM runs showed about discovery.** With nothing blocked, the agent found the hub and took 98.7% from it. Blocking libtorrent's local network discovery (multicast 239.192.152.143, on the agent) and giving no hint dropped the peer share to 0%: the swarm found nobody within `THUB_SWARM_STALL` (20 s), fell back to HTTP, and counted one fallback. With `THUB_PEERS=hub:6881` and discovery still blocked it was back to 98.7%. So the first result came from local discovery on the shared virtual switch, not from the tracker or DHT. DHT was reachable from both VMs (40 to 120 nodes). The probable cause is NAT: both VMs leave through the host's address, so a tracker or DHT answer points the agent at the host, not the hub. That is a guess; I did not check it (no root on the host to watch traffic or add a port forward). It means this setup cannot say whether discovery works for real peers on separate networks. That needs a hub with a reachable address and an agent elsewhere.

**Lessons from the VM setup**, in case it is rebuilt: a cloud-init seed on a SATA CD-ROM made the Debian 12 cloud image hang early in boot with no network. A virtio-SCSI CD-ROM works (that is how the nostrhost VMs are built). The VMs were `thub-hub` (192.168.122.25) and `thub-agent` (192.168.122.222) with files in `~/torrenthub-vms`. `torrenthub mirror` seeds only while its own process lives, so mirror first and then start `serve`, which re-seeds stored blobs on startup.

Not covered: a recently created repo (the probe's own advice), gated repos, sharded weights, anything over 1 GB, peers on separate real networks.
