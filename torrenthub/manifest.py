"""Signed manifests: a creator vouches for the file table of a commit.

A manifest is a Nostr style event (see signing.py), so it can be passed around as plain JSON
and also published to a relay. Its content says: in repo R, commit C has exactly these files
with these sizes and hashes, and these branch names pointed at it at created_at.

An agent that pins the creator's public key for a repo namespace can then take hashes from
any hub and know they are the creator's, without trusting the hub or any origin.

Kind 36777 is provisional. It is in the addressable range (30000 to 39999) and was not listed
in the NIPs README when this was written, but nobody has registered it for this. Change
MANIFEST_KIND if that matters to you.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

from .federation import fingerprint
from .signing import sign_event, verify_event

MANIFEST_KIND = 36777
MAX_EVENT_BYTES = 8 * 1024 * 1024
MAX_EVENTS_PER_REPO = 200
SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ManifestInvalid(Exception):
    pass


@dataclass(frozen=True)
class Manifest:
    id: str
    pubkey: str
    created_at: int
    repo: str
    commit: str
    refs: tuple[str, ...]
    rows: tuple
    event: dict


def build_manifest(secret: bytes, repo_id: str, info: dict, refs: list[str], created_at: int | None = None) -> dict:
    commit = info.get("sha")
    if not isinstance(commit, str) or not SHA40.match(commit):
        raise ValueError("info has no 40 hex commit sha")
    content = json.dumps(
        {
            "v": 1,
            "repo": repo_id,
            "commit": commit,
            "refs": sorted(set(refs)),
            "files": [list(r) for r in fingerprint(info)],
        },
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=True,  # pure ASCII, so escaping can never differ between implementations
    )
    tags = [["d", f"{repo_id}@{commit}"], ["repo", repo_id], ["commit", commit]] + [["ref", r] for r in sorted(set(refs))]
    return sign_event(secret, MANIFEST_KIND, tags, content, int(created_at if created_at is not None else time.time()))


def verify_manifest(ev: dict, allowed: set[str], repo_id: str) -> Manifest:
    """Return the parsed manifest if it is validly signed by one of `allowed` public keys and is
    about `repo_id`. Raises ManifestInvalid otherwise."""
    try:
        if len(json.dumps(ev)) > MAX_EVENT_BYTES:
            raise ManifestInvalid("event too large")
        if ev.get("kind") != MANIFEST_KIND:
            raise ManifestInvalid("wrong kind")
        if ev.get("pubkey") not in allowed:
            raise ManifestInvalid("not signed by a key trusted for this repo")
        if not verify_event(ev):
            raise ManifestInvalid("bad id or signature")
        body = json.loads(ev["content"])
        if body.get("v") != 1 or body.get("repo") != repo_id:
            raise ManifestInvalid("not a version 1 manifest for this repo")
        commit = body["commit"]
        if not isinstance(commit, str) or not SHA40.match(commit):
            raise ManifestInvalid("bad commit")
        refs = body["refs"]
        files = body["files"]
        if not isinstance(refs, list) or not all(isinstance(r, str) for r in refs):
            raise ManifestInvalid("bad refs")
        tag_refs = sorted(t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "ref")
        tag_commit = [t[1] for t in ev["tags"] if len(t) >= 2 and t[0] == "commit"]
        if tag_commit != [commit] or tag_refs != sorted(refs):
            raise ManifestInvalid("tags disagree with the signed content")
        rows = tuple(tuple(r) for r in files)
        return Manifest(ev["id"], ev["pubkey"], int(ev["created_at"]), repo_id, commit, tuple(refs), rows, ev)
    except ManifestInvalid:
        raise
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise ManifestInvalid(f"malformed: {type(e).__name__}") from e
