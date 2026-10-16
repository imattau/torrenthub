# Hosting your own repository, backed by git

Status: **all four stages are built** (`PROTOCOL.md` sections 18 to 21 say exactly what, how they were measured, and what is not done). H4 is still design only. Written 2026-10-16 after reading `publish.py`, `manifest.py` and `mirror.py`. Where the design below and section 18 differ, section 18 is what the code does.

## What exists, and what is missing

Today a publisher hashes a directory, signs a manifest (`manifest.py`, v2) and pushes it with the big files to a hub (`publish.py`). The repo's "commit" is the first 40 hex characters of the sha256 of the file table (`content_commit`). That works, but:

- There is no history. A branch is a signed `seq` number pointing at a table. Old commits stay pinnable, but nothing says one came from another, so there are no diffs, no parents and no fast-forward check.
- It is not git. People who already keep a model repo in git have to rebuild it as a directory snapshot to publish, and cannot `git clone` the result.
- A hub holds it. Someone with a machine and a key but no wish to depend on another operator cannot simply serve their own repo.

## The idea

Let the publisher's repo be a real git repository, and make **the git commit the thing the manifest signs**.

Big files live in the tree as LFS pointer files (`version https://git-lfs.github.com/spec/v1`, `oid sha256:...`, `size N`), exactly what Hugging Face repos already do. Small files are plain git blobs. So a git commit id transitively pins every file:

```
manifest (signed) -> commit sha1 -> tree -> pointer files -> sha256 + size of each big file
                                        -> git blobs     -> git blob id of each small file
```

That is the property the trust model needs, and `mirror.py` already verifies both kinds of key (`sha256` and `git-<blobId>`). The file table stops being something the publisher states and becomes something the hub **derives** from the git objects it received. A hub cannot be told a table that disagrees with the commit.

Bytes still travel by torrent. Git carries only the small objects: commits, trees, pointers and small files. A multi-GB model is a few kilobytes of git.

## Two ways to host, one format

1. **Self-hosted.** `torrenthub host --git ~/models/foo --repo alice/foo --key-file K` runs a hub for that repository. It reads refs from the git repo, derives the table from each commit, seeds big files from the working tree in place (no copy), and signs a manifest for each ref. Others add the host as an upstream and pin the owner's key as today. A host behind NAT is the existing problem; publishing the same commit to a public hub (below) solves it.
2. **Hosted by someone else.** `torrenthub publish --git ~/models/foo --ref main --hub URL` sends the missing git objects (a pack of commits since the hub's current head), the torrents of any new big files, and a manifest naming the new head. The publisher dials the hub as in P4, so no open port is needed.

Both produce the same manifest, so a repo can be self-hosted and mirrored by hubs, and a consumer cannot tell which it came from except by the key that signed.

## Manifest change (v3)

- `commit` is a real git commit id. A field `git: {"tree": "...", "parents": ["..."]}` repeats what is in the objects, so a reader can check it without the objects.
- `files` is optional and, when present, must equal what the tree gives (kept so older readers and `files_x` keep working).
- `seq`, `valid_until` and the `d` tag stay. `seq` still orders manifests for one ref name and defeats rollback by a hub that withholds a newer one.
- Existing content-commit repos stay valid. A reader tells them apart by `git` being absent.

## What the hub checks on a git publish

In addition to the P4 checks (signature, signer's authority, quotas, torrents against the signed size and hash, `seq`):

1. Objects are fed to `git index-pack --strict` and `git fsck` in a throwaway repo, with `GIT_CONFIG_NOSYSTEM`, no hooks, no templates, a size cap on the pack and a cap on object count. Git is never run in a repo the publisher controls.
2. The head commit named in the manifest exists, and every object it needs is present (a connected pack).
3. The tree is walked. Refused: symlinks and submodules (path escapes), paths git itself forbids or that collide on case-insensitive disks, `.git` components, and the path rules `mirror.py` already applies (`safe_file_name`).
4. Every blob over a size threshold (say 1 MiB) must be an LFS pointer. A multi-GB blob committed directly is refused, since it would pass through git objects instead of the swarm.
5. A pointer must parse strictly (three lines, lowercase hex oid, decimal size) and its big file must be one the hub holds or is receiving.
6. **Fast-forward.** The new head must descend from the hub's current head for that ref, unless the manifest carries `force: true` and the signer's policy allows it. This is stronger than `seq` alone: the hub has the history, so a rollback to an earlier commit is visible as such.

Then the existing path runs: pull the swarm bytes, check sha256 of every file, and only then make refs and manifest visible.

## What consumers see

- Everything an HF client does today works unchanged. `huggingface_hub` treats a revision as an opaque string.
- New endpoints, read only: `GET /api/models/{repo}/commits/{ref}` (history from the stored objects) and `GET /api/models/{repo}/compare/{a}..{b}` (changed paths with old and new sha256). Cheap to add once the commit objects are stored.
- **SHA-1.** A git commit id is SHA-1 (git's hardened sha1dc). A chosen-prefix collision against a tree is far more expensive than against a torrent piece, and the pointers inside carry sha256, so an attacker cannot swap big-file content. They could in principle swap small git blobs under a colliding id. The hub keeps a `table_sha256` in the manifest as a second binding, so a consumer who cares checks both. Say so in the docs rather than hide it.

## Making the commits

Users should not need git-lfs. It is not installed here, and a pointer is three lines:

- `torrenthub git-init` sets `.gitattributes` and a `filter.thub` clean/smudge driver that writes the same pointer format. A user who already has git-lfs installed can use that instead, and the hub cannot tell the difference.
- `torrenthub` reads the pointers itself. No git-lfs binary on a hub.

## Staged plan

| Stage | Adds | Done when |
|---|---|---|
| H1 | Manifest v3, `publish --git`, the checks above, derive the table from a pack | A real git repo with LFS-style pointers is published to a hub from behind a firewall, and an HF client fetches it fully verified. A hostile pack (symlink, giant blob, disconnected, non-fast-forward) is refused, each tested. |
| H2 | `torrenthub host`: serve a local repo in place, seed from the working tree, sign on ref change | Two machines: one hosts, the other fetches from it with no third party. |
| H3 | `git-remote-thub`, so `git push hub main` and `git clone thub://...` work with our signing | A user pushes with plain git. |
| H4 | Optional smart-HTTP clone and the LFS batch endpoint, if people want HF-style `git clone https://...` | Not decided; H3 may be enough. |

## Not decided / open

- **Who may create a repo on a shared hub.** Today a repo name is checked against the signer's delegation (`publish:<repo>`). A public hub that lets strangers claim `alice/*` first needs a rule for namespaces: first-come with the key bound to the name, or an operator's endorsement. This is a policy question more than a technical one.
- **Deleting and rewriting.** Removing a repo, a ref, or a leaked file from history is not built even for P4. Git makes it harder (history is immutable by design). A signed tombstone plus `block` on the blob is the likely answer; it needs a decision on what a mirror owes the original publisher.
- **Large histories.** Repos with thousands of commits make the first publish a big pack. Shallow publication (head only, parents by id) is possible but loses the fast-forward check.
- **Tags and releases.** Signed tags map naturally to manifest refs. Not needed for H1.
- **Windows and case-insensitive file systems**: refused collisions are the safe default, but it needs testing.
