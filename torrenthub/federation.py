"""Deciding what several upstream hubs agree on.

A hub tells an agent the file table for a commit: for each path, its size and the sha256 the
bytes must have. Everything the agent later accepts is checked against those hashes, so whoever
supplies the table decides what counts as correct. With one upstream you trust that one. With
several you can require agreement, so one lying or compromised hub is not enough.

Rules, in order:

1. A commit sha names a tree. Two upstreams that report the same commit with different file
   tables are in conflict, and the answer is refused, whatever the quorum. This is checked
   among the answers actually received, so it can only catch a liar who is asked.
2. A request for a specific commit (a 40 hex revision) must only get answers for that commit.
3. Answers are grouped by commit sha. A group counts when at least `quorum` upstreams are in it.
4. If several groups count (hubs lagging behind a branch that moved), the group containing the
   highest-priority upstream wins, then that upstream's answer is used. Priority is list order.

What this does not give you: a majority or reputation scheme. Upstreams that all copy from the
same source can all be wrong together, and a quorum of colluding hubs passes.
"""

from __future__ import annotations

import re
from typing import Any

SHA40 = re.compile(r"^[0-9a-f]{40}$")


class ConsensusError(Exception):
    pass


class Disagreement(ConsensusError):
    """Upstreams gave answers that cannot all be right."""


class NotEnoughAnswers(ConsensusError):
    """Fewer upstreams answered than the quorum needs. Nothing contradicts anything."""


def fingerprint(info: dict) -> tuple:
    """The part of a model-info document that decides what bytes are correct."""
    rows = []
    for s in info.get("siblings", []):
        lfs = s.get("lfs")
        rows.append(
            (
                s["rfilename"],
                int(lfs["size"]) if lfs else int(s.get("size", -1)),
                lfs["sha256"] if lfs else None,
                s.get("blobId"),
            )
        )
    return tuple(sorted(rows))


def choose_consensus(answers: list[tuple[int, dict]], quorum: int, revision: str = "") -> tuple[int, dict]:
    """Pick the answer to use. `answers` is (priority index, model-info document); a lower index
    means a higher priority. Returns the chosen (index, document)."""
    if not answers:
        raise NotEnoughAnswers("no upstream answered")

    pinned = revision if SHA40.match(revision or "") else None
    by_sha: dict[str, list[tuple[int, dict, tuple]]] = {}
    for idx, info in answers:
        sha = info.get("sha")
        if not isinstance(sha, str):
            raise Disagreement(f"upstream #{idx} gave no commit sha")
        if pinned and sha != pinned:
            raise Disagreement(f"upstream #{idx} answered {sha[:12]} for the pinned commit {pinned[:12]}")
        by_sha.setdefault(sha, []).append((idx, info, fingerprint(info)))

    for sha, group in by_sha.items():
        if len({fp for _, _, fp in group}) > 1:
            who = sorted(i for i, _, _ in group)
            raise Disagreement(f"upstreams {who} report different file tables for commit {sha[:12]}")

    counted = [g for g in by_sha.values() if len(g) >= quorum]
    if not counted:
        if len(answers) < quorum:
            raise NotEnoughAnswers(f"{len(answers)} of the {quorum} upstreams needed answered")
        sizes = {sha[:12]: len(g) for sha, g in by_sha.items()}
        raise Disagreement(f"no commit is reported by {quorum} upstreams (answers by commit: {sizes})")

    best = min(counted, key=lambda g: min(i for i, _, _ in g))
    idx, info, _ = min(best, key=lambda t: t[0])
    return idx, info
