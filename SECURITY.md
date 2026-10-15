# Security notes

Status: no external audit has been done. This file records what a self-review found and fixed, and
what is known to be weak. Treat the project as a prototype.

## Fixed in the 2026-10-16 review

| Finding | Fix |
|---|---|
| Signing in pure Python took 5.1 ms for a secret with 2 bits set and 10.1 ms for 255 set: its timing depends on the secret. The signer signs on request, so a client able to time its answers is exactly the party it must resist. | When `coincurve` is installed (`pip install 'torrenthub[fast]'`) all signing, verifying and key derivation use libsecp256k1, which is constant time and about a hundred times faster. Both backends are checked against the official BIP-340 vectors (the repo's copy is identical to bitcoin/bips master) and against each other on random, edge-case and malformed inputs. The signer reports its backend and warns when it is pure Python. The pure Python path remains the fallback. |
| A torrent received from another hub or a publisher could name any tracker or web seed, and the swarm engine would contact it. libtorrent refuses a local tracker unless its path ends in `/announce`; `http://internal-host/announce` still got a request carrying this machine's address and port. Measured, with a control. | `sanitize_torrent` keeps only the `info` dictionary, byte for byte, and adds only the operator's trackers and web seeds. It also refuses an `info` dictionary that is not in canonical form. Used for torrents fetched from hubs and for publisher torrents. |
| The event and publish endpoints read a whole request body before checking anything. A 400 MB body cost 8.3 s of CPU and hundreds of MB of memory without any credentials. | Per-endpoint body limits (`THUB_MAX_EVENT_BODY`, default 256 KiB; `THUB_PUBLISH_MAX_BODY`, default 64 MiB), enforced on the declared length and on streamed bodies. The same request is now refused in 0.33 s. Deeply nested JSON gives a clean 400. |

## Known weak, not fixed

- **The pickle scanner is not trustworthy yet.** It reads opcodes with a simplified model of the pickle machine instead of running the machine itself, and I have reason to think a determined author can make it say "clean" for a file that is not. That reasoning came from reading the code; I did not build test files to confirm it, and I won't. Until it is rewritten, do not treat `format_scan` on a pickle based file as a safety guarantee, and prefer safetensors. The planned fix is to scan with the real unpickler, with every import routed through a restricted `find_class` that returns inert stand-ins, as the Python documentation recommends for restricting globals, and to scan every pickle a loader would read.
- The safetensors check validates structure, not content. The GGUF check is magic and version only.
- The signer protects against an agent, not against other code running as the same user, which can read the key file.
- Admission verifies a signature per event; with the fast backend that is cheap, with the Python one it is about 20 ms, so a flood of invalid events is a CPU cost. There is no per-address rate limit.
- A hub or relay can withhold a revocation or a newer manifest. Expiry, maximum age and asking several sources reduce this; they cannot remove it.
- Dependencies were not audited.
