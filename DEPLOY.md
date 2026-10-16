# Running torrenthub

This is for whoever runs a hub, hosts a repository, or sets up a machine to use one. What the system is and why it is built this way is in
`README.md`, `PROTOCOL.md` and `ARCHITECTURE.md`; what has and has not been checked is in `SECURITY.md` and `validation/README.md`.
Read the last section of this file before you put anything on the internet.

## What you might be running

| You want to | You run | Needs |
|---|---|---|
| Serve models to other people (a public or private hub) | `torrenthub serve` | git, libtorrent, a public name, TCP 8080 behind TLS, TCP and UDP 6881 open |
| Share your own model repository from your own machine | `torrenthub host` | git, libtorrent, your signing key, a reachable HTTP port and swarm port |
| Fetch from and push to hubs with `git` | `git-remote-thub` and `torrenthub` on the client | git; libtorrent for big files by torrent |

A hub and a host are the same server. A host serves exactly one repository, read from your git repository, signed with your key, and takes
no uploads.

## Ports

| Port | Used for | Through the TLS proxy? |
|---|---|---|
| 8080/tcp | the HTTP API, git over HTTP, the tracker (`/announce`), web seeds (`/blobs`) | yes: expose 443 and proxy to it |
| 6881/tcp | BitTorrent peer connections | **no**: open it directly |
| 6881/udp | the DHT, and uTP peer connections | **no**: open it directly |

Outbound: whatever the upstream you mirror from needs (443), and peers on any port. If the swarm port visible from outside is not the one
the process listens on (a container with a mapped port, a router forwarding 51413 to 6881), set `THUB_SWARM_PUBLIC_PORT` to the outside
number. The hub tells clients that number, not the one it listens on.

## Install

**With pip.** Use the locked versions; they are the ones the tests and the audit ran against (Python 3.12, Linux x86-64).

```bash
python3 -m venv /opt/torrenthub
/opt/torrenthub/bin/pip install -c lock/runtime.txt './' 'torrenthub[swarm,fast,relay]'   # from a checkout
# or from a built wheel:  python -m build && pip install -c lock/runtime.txt 'dist/torrenthub-0.2.0-py3-none-any.whl[swarm,fast,relay]'
/opt/torrenthub/bin/torrenthub --version
```

`swarm` is libtorrent (without it nothing is shared over BitTorrent), `fast` is the constant time signing library (install it on
anything that signs), `relay` is for Nostr relays. `git` 2.32 or newer must be on the machine: the sandbox around hostile packs needs it.
`deploy/smoke-test.sh` builds the package, installs it into a clean virtualenv at the locked versions and starts it.

**As a container.** `deploy/Containerfile` builds an image that runs as an unprivileged user, installs the locked versions, keeps its data in
`/data`, and has a health check:

```bash
podman build --format docker -f deploy/Containerfile -t torrenthub .     # docker: omit --format docker
podman run -d --name hub -v thub-data:/data \
  -p 8080:8080 -p 6881:6881/tcp -p 6881:6881/udp \
  -e THUB_PUBLIC_URL=https://hub.example.org -e THUB_PUBLISH_QUOTA=20G -e THUB_ROOTS=<your public key> \
  --read-only --tmpfs /tmp --cap-drop=ALL --security-opt no-new-privileges torrenthub
```

Run with `--read-only`, because nothing outside `/data` and `/tmp` is written. Publish the swarm port at the same number inside and out.

## Check it: `torrenthub doctor`

```bash
THUB_PUBLIC_URL=https://hub.example.org THUB_SWARM=libtorrent THUB_PUBLISH_QUOTA=20G THUB_ROOTS=<key> torrenthub doctor
torrenthub doctor --probe        # and ask the running hub, at its public URL, what it believes
```

It reads the same `THUB_*` settings the hub would start with and prints `ok`, `warn` or `fail` for each thing that has gone wrong
before: a public URL that says localhost (the web seeds, LFS links and tracker address are built from it), publishing switched on with
nobody allowed to publish, git missing or too old, libtorrent missing, a data directory that cannot be written, a swarm port that is
taken, both discovery methods off, an unlimited disk budget. `--probe` also checks that the URL you gave reaches the hub, that the hub
agrees about its address, and that the swarm port it advertises accepts a TCP connection. The exit status is 1 if anything failed. The
systemd unit runs it before starting, and `torrenthub serve` logs the warnings at startup.

## A public hub

1. Pick the name and TLS: see "TLS" below. `THUB_PUBLIC_URL` is the https address clients will use.
2. Put your public key in `THUB_ROOTS` and set `THUB_PUBLISH_QUOTA`. Without a root nobody can publish; without a quota publishing is off.
3. Set `THUB_MAX_DISK` if the hub also mirrors from an upstream. Published content is never evicted; mirrored content is, oldest first.
4. Open TCP and UDP 6881. Run `torrenthub doctor --probe` from another machine.
5. Publish something with `git push` or `torrenthub publish` (README) and clone it from a third machine.

`deploy/systemd/torrenthub-hub.service` runs the hub as an unprivileged user with the filesystem read-only except
`/var/lib/torrenthub`, no capabilities, and the doctor as a start condition. Its address-family list must include `AF_NETLINK`: libtorrent
lists the machine's network interfaces over netlink, and without it the hub exits at startup. `deploy/systemd/hub.env.example` is the settings file.
The unit binds the server to 127.0.0.1 for a proxy on the same machine; use `--host 0.0.0.0` only if something else terminates TLS.

### A private network (no internet, no tracker you do not run)

The hub is a tracker and a DHT node. For a swarm that must not touch the public DHT:

```
THUB_DHT_PUBLIC=0     # the hub does not contact the public bootstrap routers
THUB_DHT_LOCAL=1      # libtorrent otherwise refuses private addresses in its DHT
```

and on each client `THUB_CLIENT_DHT_PUBLIC=0 THUB_CLIENT_DHT_LOCAL=1` (or `git config thub.dhtpublic false`, `thub.dhtlocal true`).
Clients learn the hub's tracker and DHT node from the hub itself.

## Hosting your own repository

```bash
torrenthub host --git ~/models/my-model --repo you/my-model --key-file ~/.config/torrenthub/key \
                --public-url http://my.host.example:8080 --port 8080 --listen-port 6881
```

It prints the line consumers use (`THUB_TRUST='you/my-model=signed:<your key>'`). `deploy/systemd/torrenthub-host.service` runs it as a
service of your own user (it needs to read your repository and key; keep git's own variables such as `GIT_DIR` out of its environment file, and the command refuses to start if they are set); `loginctl enable-linger` keeps it up after you log out. Keep the key
file mode 600; the tools warn if it is not. A host behind a home router is reachable only if its two ports are forwarded; the other way
to share from behind a router is to publish the same commit to a public hub (`git push`), which needs no open port on your side.

## A client

```bash
pip install -c lock/runtime.txt 'torrenthub[swarm,fast]'      # puts torrenthub and git-remote-thub on the PATH
torrenthub git-init                                            # in a repository with big files
git remote add hub thub://hub.example.org/you/model && git config thub.keyfile ~/.config/torrenthub/key
git push hub main
git clone -c thub.signer=<owner key> thub://hub.example.org/you/model
```

`git-remote-thub` must be on the PATH of the git that runs. The client settings (`thub.*` in git config, `THUB_CLIENT_*` in the
environment) are in `PROTOCOL.md` sections 22 to 24. A clone that has fetched files can share them with `torrenthub seed`.

## TLS

TLS is not built in: put a reverse proxy in front of port 8080. Only HTTP goes through it; the swarm port does not.
`deploy/proxy/Caddyfile` (certificates from Let's Encrypt, automatic) and `deploy/proxy/nginx.conf` are starting points. Set
`THUB_PUBLIC_URL` to the https address: LFS download links, web seed URLs and the tracker address in every torrent are built from it.
The hub trusts `X-Forwarded-For` only from loopback unless `FORWARDED_ALLOW_IPS` lists the proxy's address; without that every client
looks like the proxy to the per-address rate limits, and with a wrong list a client can claim any address. Raise the proxy's body limit to
at least 80 MB (a publication is up to `THUB_PUBLISH_MAX_BODY`, 64 MB) and its read timeout to minutes (a pack or a large download).

**What was tested.** The hub in a container (`THUB_PUBLIC_URL=https://localhost:9443`), Caddy in front of it with its own certificate authority
(`local_certs`), and a client that trusts that authority through `SSL_CERT_FILE` (git itself: `-c http.sslCAInfo=...`). `git push` and
`git clone` through `git-remote-thub` by name over HTTPS, a clone with the history and a 40 MB file over the swarm, stock `git clone
https://...`, and `torrenthub verify-git` all worked; the tracker received announces over HTTPS from clients that trusted the certificate.
A client that does **not** trust the certificate is refused by both our tools (`CERTIFICATE_VERIFY_FAILED`) and by git, and nothing falls back
to an unchecked connection. In that setup the hub saw every request as coming from the proxy's address, as described above, until
`FORWARDED_ALLOW_IPS` is set to it. Not tested: a certificate from a public authority (Let's Encrypt), nginx, HTTP/3, and renewals.

A hub reached by name is the normal case, and it matters that libtorrent only accepts IP addresses for the peers it is told about; the
tools resolve names themselves (0.2.0). Hubs reached by address, which is how everything before this was tested, hid that.

## Operating it

**Health and metrics.** `GET /healthz` (used by the container health check) and `GET /metrics` (Prometheus text). Worth graphing:
`thub_bytes_served_total` (bytes the hub sent over HTTP: it should stay small when the swarm is doing its job),
`thub_integrity_failures_total` (anything above zero means a peer or an upstream sent wrong bytes), `thub_swarm_fallback_total`,
`thub_publish_total{result}`, `thub_git_http_total{kind}`, `thub_git_pack_total`, `thub_tracker_announce_total{result}`,
`thub_events_total`. `GET /api/thub/tracker` shows the tracker's torrents, peers and seeders; `GET /api/thub/info` is what clients are
told about the hub; on a host `GET /api/thub/host` shows each branch's commit, sequence number and last error.

**Logs.** To stderr (systemd: `journalctl -u torrenthub-hub`), `--log-level debug|info|warning|error`. The loggers are `torrenthub.*`.

**Backups.** Everything is under `THUB_DATA`: `hub.db` (SQLite), `blobs/`, `torrents/`, `manifests/`, the event store, and `git/` (a bare
repository per published or hosted repo). Published repositories exist nowhere else, so back them up; mirrored blobs can be fetched
again. Copy the database with `sqlite3 hub.db ".backup hub.db.bak"` (or stop the hub); copy the rest as files. To restore, put the
directory back and start the hub. There is no schema versioning beyond the one migration the code already does: restore into the same
version or a newer one, never an older one.

**Upgrading.** `pip install -c lock/runtime.txt -U torrenthub`, restart. In-flight publications are forgotten on restart (the publisher
runs the command again; files the hub already holds are not charged twice). The tracker's table is in memory and refills as peers
announce again, within `THUB_TRACKER_INTERVAL` (10 minutes).

**Disk.** `THUB_MAX_DISK` plus `torrenthub gc` evict mirrored blobs, least recently used first. Published blobs and git history are never
evicted. `torrenthub block <sha256> --reason ...` removes a blob's bytes and torrent and refuses to serve it again (a takedown). A
force-pushed rewrite prunes the unreachable git objects, but the bytes of a big file the old history pointed to stay until you block them.

**Quotas and limits.** `THUB_PUBLISH_QUOTA` per signing key (the history pack and the git pack count). The rate limits and the sizes
are in the README table; every one of them was tested for being enforced, none for being the right number for your traffic.

**Keys.** The hub holds no signing key. Publishers and hosts do. A leaked key means anyone can publish as its owner until the key is
revoked (`torrenthub revoke`, with a successor for rotation: `PROTOCOL.md`).

## Hardening checklist

- [ ] TLS in front, `THUB_PUBLIC_URL` is the https address, `FORWARDED_ALLOW_IPS` is the proxy and nothing else.
- [ ] The hub runs as an unprivileged user; the unit or container flags in `deploy/` are on (read-only root, no capabilities).
- [ ] `THUB_ROOTS` holds only keys you control; `THUB_PUBLISH_ALLOW_FORCE` is off unless you want signers to be able to rewrite branches.
- [ ] `THUB_MAX_DISK` is set; the data volume has room for what is published.
- [ ] Signing key files are mode 600 and on the machine that signs, not on the hub.
- [ ] `torrenthub doctor --probe` is clean from outside.
- [ ] If the swarm must stay private: `THUB_DHT_PUBLIC=0` and the client settings above.

## When something is wrong

| You see | Likely cause |
|---|---|
| `doctor`: public url names this machine | `THUB_PUBLIC_URL` is unset or localhost; set the address clients use |
| `doctor --probe`: swarm port did not accept | closed in the firewall, or mapped to a different outside number (`THUB_SWARM_PUBLIC_PORT`) |
| A clone waits 30 seconds per file, then gets it over HTTP | the swarm has nobody for it: the hub's swarm port is closed, or `THUB_PUBLIC_URL` is wrong, or the tracker is off and there is no other peer. `thub.swarmStall` sets the wait |
| `git push`: `NotAuthorised` | the key is not in `THUB_ROOTS` and holds no `publish:<repo>` delegation |
| `git push`: `QuotaExceeded` | `THUB_PUBLISH_QUOTA` (the pack and the history pack count too) |
| `git push`: `WrongKind` | the repository was first published without git (or with it); use another name |
| `git push`: `NotFastForward` | the branch moved; a rewrite needs `--force` and a hub with `THUB_PUBLISH_ALLOW_FORCE=1` |
| `git push`: `Busy` (503) | git slots are full; try again in a moment |
| `git push` fails before the helper runs with `batch request: missing protocol` | git-lfs's own `pre-push` hook; run `torrenthub git-init --lfs` |
| `git clone`: `no signer is pinned` | add `-c thub.signer=<owner key>` to `git clone` (not `git -c ... clone`) |
| Everything works from one machine, nothing from another | the hub's address in `THUB_PUBLIC_URL`, a closed 6881/udp, or a DHT listening on `0.0.0.0` on a machine with several interfaces (fixed in 0.2.0) |

## What was tested, and what was not

Found by deploying it, not by the test suite, and fixed in 0.2.0: git 2.47's `show-index` crashes outside a repository (the container's
git; this machine's 2.43 did not); a hub reached by DNS name crashed every client, because libtorrent accepts only IP addresses (every
earlier run used an IP); the first host service file named a setting `GIT_DIR`, which git itself reads; and the hub's sandbox as first
written refused the network-interface lookup libtorrent needs, so the service would not start (`AF_NETLINK`).

- **Container:** built with podman 4.9.3 (rootless), run read-only with all capabilities dropped as uid 10001. It reached `healthy`, took a
  `git push` and served a clone over the swarm through mapped ports, served stock `git clone`, and kept its data across a restart. The whole
  test suite also passed inside the image (git 2.47.3, Debian): 760 passed, 11 skipped.
- **Packaging:** the wheel and sdist build; the wheel installs into a clean virtualenv at the locked versions; the installed hub starts and
  `doctor --probe` agrees with it (`deploy/smoke-test.sh`).
- **systemd:** `systemd-analyze verify` finds nothing wrong with either unit. The hub's sandbox settings were applied one by one to the real hub
  through transient user services (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`, the `Protect*` kernel and control
  group settings, `Restrict*`, `LockPersonality`, `SystemCallArchitectures`, an empty `CapabilityBoundingSet`, `LimitNOFILE`, `UMask`) and the
  hub then took a publish, served a clone and a stock `git clone`, with nothing in its journal. The host unit's `ExecStart`, with its
  variables from an environment file, was run the same way and served a clone. **Not tested:** the system-level unit itself on a real install
  (`User=`, `StateDirectory=`, `ProtectHome`, `ExecStartPre` running `doctor`), because that needs root.
- **TLS:** above.
- **Not run at all:** `.github/workflows/ci.yml` (it has never been run on GitHub), nginx, Docker (only podman), anything but Linux x86-64.

## What this does not do

- It is one process. There is no clustering, no shared storage between hubs, and the tracker and the publication jobs live in memory.
- Reading is anonymous: anyone who can reach the hub can read what it serves. There are no private repositories.
- TLS, certificates and renewals are your proxy's job.
- UPnP / NAT-PMP port mapping (`thub.upnp`) was never tried against a real router. Peers behind NAT with no forwarded port cannot be
  reached by other peers; the hub is the way in for them.
- Everything has been run on Linux. Nothing has been run on Windows or macOS.
- All the validation was done on one machine and a virtual network (`validation/README.md`). Discovery and transfer across the real
  internet, between separate networks and real routers, has not been tried.
- Nobody but the author has audited this (`SECURITY.md`).
- MIT licensed (`LICENSE`), which also means no warranty.
