"""The consumer's policy file: what must hold before this gateway serves a file.

TOML, one file (THUB_POLICY). Rules are tried in order and the first one that matches the repo
and the file name decides. No rule means the file is served, apart from the one fixed check
below.

    [[file]]
    repo = "*"                              # repo glob, default "*"
    match = ["*.bin", "*.pt", "*.pkl", "*.ckpt", "*.pickle"]   # file name globs, default ["*"]
    action = "require"                      # require | deny | allow, default require
    claim = "format_scan"                   # for require
    independent = 2                         # how many independent trusted attestors, default 1
    min_trust = 0.5                         # each must have at least this trust for attest:<claim>
    reason = "pickle weights need two scans"   # optional text shown to the user

Always checked first, whatever the rules say: a blob that a key this gateway trusts for scope
"revoke" has revoked is refused.

`require` needs a sha256 to attach attestations to. Files without one (small files git stores
directly) can only be matched by `deny` or `allow`. A `require` rule that matches one refuses it,
and says why, rather than letting it through unchecked.
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .trust import Graph

ACTIONS = ("require", "deny", "allow")


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    repo: str = "*"
    match: tuple[str, ...] = ("*",)
    action: str = "require"
    claim: str = ""
    independent: int = 1
    min_trust: float = 0.0
    reason: str = ""

    def applies(self, repo: str, path: str) -> bool:
        name = path.rsplit("/", 1)[-1]
        return fnmatch.fnmatchcase(repo, self.repo) and any(
            fnmatch.fnmatchcase(name, m) or fnmatch.fnmatchcase(path, m) for m in self.match)


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    rule: int | None = None  # index of the rule that decided, if any
    attested_by: tuple = ()
    code: str = "PolicyRefused"
    notes: list = field(default_factory=list)


def parse_policy(text: str) -> list[Rule]:
    from .events import CLAIM_CLASS

    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise PolicyError(f"policy is not valid TOML: {e}") from e
    unknown = set(doc) - {"file"}
    if unknown:
        raise PolicyError(f"unknown policy section(s): {sorted(unknown)}")
    rules = []
    for i, r in enumerate(doc.get("file", [])):
        bad = set(r) - {"repo", "match", "action", "claim", "independent", "min_trust", "reason"}
        if bad:
            raise PolicyError(f"rule {i + 1}: unknown key(s) {sorted(bad)}")
        action = r.get("action", "require")
        if action not in ACTIONS:
            raise PolicyError(f"rule {i + 1}: action must be one of {ACTIONS}")
        match = r.get("match", ["*"])
        if isinstance(match, str):
            match = [match]
        if not isinstance(match, list) or not match or not all(isinstance(m, str) for m in match):
            raise PolicyError(f"rule {i + 1}: match must be a list of file name patterns")
        claim = r.get("claim", "")
        n = r.get("independent", 1)
        mt = r.get("min_trust", 0.0)
        if action == "require":
            if claim not in CLAIM_CLASS:
                raise PolicyError(f"rule {i + 1}: claim must be one of {sorted(CLAIM_CLASS)}")
            if claim in ("review", "licence_check"):
                raise PolicyError(f"rule {i + 1}: {claim} is self reported (class S) and cannot satisfy a requirement")
        if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= 20:
            raise PolicyError(f"rule {i + 1}: independent must be a whole number from 1 to 20")
        if isinstance(mt, bool) or not isinstance(mt, (int, float)) or not 0 <= mt <= 1:
            raise PolicyError(f"rule {i + 1}: min_trust must be between 0 and 1")
        rules.append(Rule(str(r.get("repo", "*")), tuple(match), action, claim, n, float(mt), str(r.get("reason", ""))[:300]))
    return rules


def load_policy(path: str | Path | None) -> list[Rule]:
    if not path:
        return []
    return parse_policy(Path(path).read_text())


def check_file(rules: list[Rule], graph: Graph, repo: str, path: str, sha256: str | None) -> Decision:
    """Decide whether this gateway may serve `path` of `repo`, whose content hash is `sha256`
    (None for files git stores directly)."""
    if sha256:
        st = graph.blob_status(sha256)
        if st:
            return Decision(False, f"this content was revoked by a key this gateway trusts ({st})", code="Revoked")
    for i, rule in enumerate(rules):
        if not rule.applies(repo, path):
            continue
        if rule.action == "allow":
            return Decision(True, rule=i)
        if rule.action == "deny":
            return Decision(False, rule.reason or f"policy rule {i + 1} denies {path}", rule=i)
        why = rule.reason or f"policy rule {i + 1} requires {rule.independent} independent {rule.claim} attestation(s)"
        if not sha256:
            return Decision(False, f"{why}; {path} has no sha256 to attach attestations to", rule=i)
        v = graph.verdict(sha256, rule.claim, rule.independent, rule.min_trust)
        if v.ok:
            return Decision(True, rule=i, attested_by=v.keys)
        return Decision(False, f"{why} ({v.detail})", rule=i, attested_by=v.keys)
    return Decision(True)
