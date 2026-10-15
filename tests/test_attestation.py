"""Attestations, verdicts, scanners, the policy file and the signer. No network."""

from __future__ import annotations

import io
import json
import os
import pickle
import random
import struct
import sys
import types
import zipfile
from collections import OrderedDict

import pytest

from tests.test_trust import A, B, C, D, NOW, ROOT, X, Y, Z, endorse, graph, key, pub
from torrenthub import events as E
from torrenthub import verifier as V
from torrenthub.policy import PolicyError, check_file, parse_policy

XH = "ab" * 32


def attest(n, claim="format_scan", x=XH, ok=True, at=200):
    return E.build_attestation(key(n), claim, "x", x, ok=ok, tool="t", created_at=at)


def replication(n, att, match, at=300):
    return E.build_attestation(key(n), "replication", "e", att["id"], match=match, created_at=at)


def vouch(frm, to, claims=("format_scan",), w=0.8, delegable=False):
    return E.build_endorsement(key(frm), pub(to), [f"attest:{c}" for c in claims], w, delegable=delegable, created_at=100)


# -------------------------------------------------------------- event format

def test_attestation_round_trip_and_classes():
    p = E.parse_event(attest(2))
    assert (p.claim, p.cls, p.ok, p.subject_kind) == ("format_scan", "D", True, "x")
    assert E.parse_event(E.build_attestation(key(2), "eval", "x", XH, detail="d")).cls == "R"
    assert E.parse_event(E.build_attestation(key(2), "review", "x", XH)).cls == "S"
    r = E.parse_event(replication(2, attest(3), True))
    assert (r.claim, r.match, r.subject_kind) == ("replication", True, "e")


@pytest.mark.parametrize("args", [
    ("nope", "x", XH), ("hash_verified", "e", XH), ("hash_verified", "x", "short"), ("hash_verified", "x", XH),  # last: no ok
    ("replication", "x", XH),
])
def test_bad_attestations_cannot_be_built(args):
    with pytest.raises(ValueError):
        E.build_attestation(key(2), *args)


def test_a_forged_class_or_changed_result_does_not_parse():
    ev = attest(2)
    body = json.loads(ev["content"])
    body["claim"] = "review"
    from torrenthub.signing import sign_event

    forged = sign_event(key(2), E.ATTESTATION, ev["tags"], json.dumps(body), 5)  # signed, but tags say format_scan
    with pytest.raises(E.EventInvalid):
        E.parse_event(forged)
    assert not E.parse_event(attest(2, ok=False)).ok


# ------------------------------------------------------------------- verdicts

def test_two_independent_trusted_attestors_satisfy_a_requirement():
    g = graph([vouch(1, 2), vouch(1, 3), attest(2), attest(3)])
    v = g.verdict(XH, "format_scan", 2, 0.5)
    assert v.ok and set(v.keys) == {A, B}


def test_attestors_behind_one_vouch_are_not_independent():
    evs = [vouch(1, 2, delegable=True), vouch(2, 3), vouch(2, 4), attest(3), attest(4)]
    g = graph(evs)
    v = g.verdict(XH, "format_scan", 2)
    assert v.status == "unsatisfied" and len(v.keys) == 1


def test_strangers_and_wrong_scope_do_not_count():
    g = graph([vouch(1, 2, claims=("hash_verified",)), attest(2), attest(9), attest(10)])
    assert g.verdict(XH, "format_scan", 1).status == "unsatisfied"
    assert graph([vouch(1, 2, claims=("hash_verified",)), attest(2, "hash_verified")]).verdict(XH, "hash_verified", 1).ok


def test_min_trust_is_respected_per_attestor():
    g = graph([vouch(1, 2, w=0.4), vouch(1, 3, w=0.9), attest(2), attest(3)])
    assert g.verdict(XH, "format_scan", 2, 0.5).status == "unsatisfied"
    assert g.verdict(XH, "format_scan", 2, 0.4).ok  # at least, not more than


def test_one_trusted_failed_scan_settles_it_whatever_else_is_said():
    g = graph([vouch(1, 2), vouch(1, 3), vouch(1, 4), attest(2), attest(3), attest(4, ok=False)])
    v = g.verdict(XH, "format_scan", 2)
    assert v.status == "negative" and v.keys == (C,)


def test_an_untrusted_failed_scan_cannot_block_anything():
    g = graph([vouch(1, 2), attest(2), attest(9, ok=False)])
    assert g.verdict(XH, "format_scan", 1).ok


def test_a_trusted_replicator_catching_a_lie_removes_that_attestor():
    lie = attest(2)  # says ok
    evs = [vouch(1, 2), vouch(1, 3), vouch(1, 5, claims=("replication",)), lie, attest(3)]
    assert graph(evs).verdict(XH, "format_scan", 2).ok
    caught = graph(evs + [replication(5, lie, match=False)])
    assert caught.verdict(XH, "format_scan", 2).status == "unsatisfied"
    assert A in caught.refuted_attestors()
    # a refuted attestor counts for nothing on any claim
    other = attest(2, "format_scan", x="cd" * 32)
    assert not graph(evs + [other, replication(5, lie, False)]).verdict("cd" * 32, "format_scan", 1).ok


def test_replications_that_do_not_count():
    lie = attest(2)
    base = [vouch(1, 2), vouch(1, 3), lie, attest(3)]
    untrusted = replication(9, lie, False)
    assert graph(base + [untrusted]).verdict(XH, "format_scan", 2).ok, "an untrusted replicator"
    self_rep = replication(2, lie, False)
    self_trusted = base + [vouch(1, 2, claims=("replication",)), self_rep]
    assert graph(self_trusted).verdict(XH, "format_scan", 2).ok, "an attestor cannot refute itself"
    agreeing = base + [vouch(1, 5, claims=("replication",)), replication(5, lie, True)]
    assert graph(agreeing).verdict(XH, "format_scan", 2).ok


def test_revoked_attestations_and_revoked_attestors_drop_out():
    a2 = attest(2)
    evs = [vouch(1, 2), a2]
    assert graph(evs).verdict(XH, "format_scan", 1).ok
    assert not graph(evs + [E.build_revocation(key(2), "event", a2["id"], created_at=300)]).verdict(XH, "format_scan", 1).ok
    assert not graph(evs + [E.build_revocation(key(2), "key", A, created_at=300)]).verdict(XH, "format_scan", 1).ok


def test_verdicts_do_not_depend_on_event_order():
    lie = attest(2)
    evs = [vouch(1, 2), vouch(1, 3), vouch(1, 5, claims=("replication",)), lie, attest(3), attest(4, ok=False), replication(5, lie, False)]
    want = graph(evs).verdict(XH, "format_scan", 1)
    rng = random.Random(3)
    for _ in range(15):
        s = evs[:]
        rng.shuffle(s)
        assert graph(s).verdict(XH, "format_scan", 1) == want


# ------------------------------------------------------------------ scanners

def st_file(tmp_path, tensors=None, meta=None, name="m.safetensors", mutate=None):
    tensors = tensors if tensors is not None else {"a": ("F32", [2, 3]), "b": ("F16", [4])}
    header, data, pos = {}, b"", 0
    for k, (dt, shape) in tensors.items():
        n = 1
        for d in shape:
            n *= d
        size = n * V.ST_BYTES[dt]
        header[k] = {"dtype": dt, "shape": shape, "data_offsets": [pos, pos + size]}
        data += b"\0" * size
        pos += size
    if meta is not None:
        header["__metadata__"] = meta
    if mutate:
        header, data = mutate(header, data)
    h = json.dumps(header).encode()
    p = tmp_path / name
    p.write_bytes(struct.pack("<Q", len(h)) + h + data)
    return p


def test_safetensors_good_and_bad(tmp_path):
    assert V.scan_safetensors(st_file(tmp_path, meta={"format": "pt"}))[0]

    def gap(h, d):
        h["b"]["data_offsets"] = [h["a"]["data_offsets"][1] + 4, h["b"]["data_offsets"][1] + 4]
        return h, d + b"\0" * 4

    def wrong_size(h, d):
        h["a"]["shape"] = [2, 4]
        return h, d

    def trailing(h, d):
        return h, d + b"\0" * 8

    def overlap(h, d):
        h["b"]["data_offsets"] = [0, 8]
        return h, d

    def bad_meta(h, d):
        h["__metadata__"] = {"k": 1}
        return h, d

    for i, m in enumerate((gap, wrong_size, trailing, overlap, bad_meta)):
        assert not V.scan_safetensors(st_file(tmp_path, mutate=m, name=f"bad{i}.safetensors"))[0], m.__name__


def test_safetensors_garbage(tmp_path):
    p = tmp_path / "x.safetensors"
    for blob in (b"", b"\x01\x02", struct.pack("<Q", 10**12) + b"{}", struct.pack("<Q", 5) + b"notjs", struct.pack("<Q", 2) + b"[]"):
        p.write_bytes(blob)
        assert not V.scan_safetensors(p)[0]


def fake_torch():
    """Stand in modules so a pickle can reference torch.* by name without torch installed."""
    mods = {}
    for name in ("torch", "torch._utils"):
        mods[name] = types.ModuleType(name)
        sys.modules[name] = mods[name]

    def _rebuild_tensor_v2(*a):
        return a

    _rebuild_tensor_v2.__module__ = "torch._utils"
    _rebuild_tensor_v2.__qualname__ = "_rebuild_tensor_v2"
    mods["torch._utils"]._rebuild_tensor_v2 = _rebuild_tensor_v2

    class FloatStorage:
        pass

    FloatStorage.__module__ = "torch"
    FloatStorage.__qualname__ = "FloatStorage"
    mods["torch"].FloatStorage = FloatStorage
    return mods


class Evil:
    def __reduce__(self):
        return (os.system, ("echo pwned > " + str(Evil.sentinel),))


@pytest.mark.parametrize("proto", [2, 4])
def test_pickle_scan_passes_tensor_pickles_and_flags_code_execution(tmp_path, proto):
    mods = fake_torch()
    try:
        good = tmp_path / "good.bin"
        good.write_bytes(pickle.dumps(OrderedDict(w=(mods["torch._utils"]._rebuild_tensor_v2, mods["torch"].FloatStorage)), protocol=proto))
        ok, detail = V.scan_pickle(good)
        assert ok, detail
        Evil.sentinel = tmp_path / "sentinel"
        bad = tmp_path / "bad.bin"
        bad.write_bytes(pickle.dumps(OrderedDict(w=Evil()), protocol=proto))
        ok, detail = V.scan_pickle(bad)
        assert not ok and ("system" in detail), detail
        assert not Evil.sentinel.exists(), "scanning must never run the pickle"
    finally:
        sys.modules.pop("torch", None)
        sys.modules.pop("torch._utils", None)


def test_pickle_inside_a_zip_like_torch_saves_it(tmp_path):
    Evil.sentinel = tmp_path / "s2"
    for payload, want in ((OrderedDict(a=1), True), (Evil(), False)):
        p = tmp_path / f"{want}.pt"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("arch/data.pkl", pickle.dumps(payload, protocol=2))
            z.writestr("arch/data/0", b"\0" * 16)
        assert V.scan_pickle(p)[0] is want
    empty = tmp_path / "empty.pt"
    with zipfile.ZipFile(empty, "w") as z:
        z.writestr("readme.txt", "x")
    assert not V.scan_pickle(empty)[0]
    assert not Evil.sentinel.exists()


def test_pickle_scan_fails_closed_on_junk_and_unknown_globals(tmp_path):
    junk = tmp_path / "j.bin"
    junk.write_bytes(os.urandom(200))
    assert not V.scan_pickle(junk)[0]
    other = tmp_path / "o.pkl"
    other.write_bytes(pickle.dumps(io.StringIO))
    assert not V.scan_pickle(other)[0]


def test_gguf_and_scan_file_dispatch(tmp_path):
    g = tmp_path / "m.gguf"
    g.write_bytes(b"GGUF" + struct.pack("<I", 3) + b"\0" * 8)
    assert V.scan_file(g, "m.gguf")[0] is True
    g.write_bytes(b"GGUX" + b"\0" * 12)
    assert V.scan_file(g, "m.gguf")[0] is False
    assert V.scan_file(g, "README.md") is None
    assert V.scan_file(st_file(tmp_path), "w.safetensors")[2] == V.TOOL_ST


def test_attest_and_replicate_events(tmp_path):
    p = st_file(tmp_path)
    sha = V.sha256_file(p)
    evs = V.attest_file_events(key(2), p, sha, ["w.safetensors"])
    assert [E.parse_event(e).claim for e in evs] == ["hash_verified", "format_scan"] and all(E.parse_event(e).ok for e in evs)
    wrong = V.attest_file_events(key(2), p, "00" * 32, ["w.safetensors"])
    assert len(wrong) == 1 and E.parse_event(wrong[0]).ok is False, "no scan of bytes that are not what they should be"
    rep = V.replicate_event(key(3), evs[1], p, ["w.safetensors"])
    assert E.parse_event(rep).match is True
    lie = E.build_attestation(key(4), "format_scan", "x", sha, ok=False, detail="made up")
    assert E.parse_event(V.replicate_event(key(3), lie, p, ["w.safetensors"])).match is False
    assert V.replicate_event(key(3), E.build_attestation(key(4), "review", "x", sha), p, []) is None


# ---------------------------------------------------------------------- policy

POLICY = """
[[file]]
match = ["*.bin", "*.pt"]
claim = "format_scan"
independent = 2
min_trust = 0.5

[[file]]
repo = "acme/*"
match = ["*.exe"]
action = "deny"
reason = "no executables"

[[file]]
repo = "trusted/*"
action = "allow"

[[file]]
match = ["*.safetensors"]
claim = "hash_verified"
"""


def test_policy_parsing_errors():
    for bad in ("not toml [", "[x]\na=1", "[[file]]\naction='maybe'", "[[file]]\nclaim='nope'", "[[file]]\nclaim='review'",
                "[[file]]\nclaim='format_scan'\nindependent=0", "[[file]]\nclaim='format_scan'\nmin_trust=2",
                "[[file]]\nclaim='format_scan'\nsurprise=1", "[[file]]\nclaim='format_scan'\nmatch=[]"):
        with pytest.raises(PolicyError):
            parse_policy(bad)
    assert parse_policy("") == []


def test_policy_decisions():
    rules = parse_policy(POLICY)
    g = graph([vouch(1, 2), vouch(1, 3), attest(2), attest(3), vouch(1, 4), attest(4, x="cd" * 32)])
    assert check_file(rules, g, "o/m", "pytorch_model.bin", XH).allowed
    d = check_file(rules, g, "o/m", "pytorch_model.bin", "cd" * 32)
    assert not d.allowed and "1 of 2" in d.reason and d.rule == 0
    d = check_file(rules, g, "o/m", "pytorch_model.bin", None)
    assert not d.allowed and "no sha256" in d.reason
    assert check_file(rules, g, "o/m", "config.json", None).allowed  # no rule matches
    d = check_file(rules, g, "acme/x", "bin/tool.exe", None)
    assert not d.allowed and d.reason == "no executables"
    assert not check_file(rules, g, "trusted/x", "w.bin", None).allowed  # rule 1 comes before the allow rule, so it wins
    assert check_file(rules, g, "trusted/x", "notes.txt", None).allowed  # the allow rule is reached for other files


def test_policy_first_match_wins_and_allow_works():
    rules = parse_policy("[[file]]\nrepo='trusted/*'\naction='allow'\n[[file]]\nmatch=['*.bin']\nclaim='format_scan'")
    assert check_file(rules, graph([]), "trusted/x", "w.bin", XH).allowed
    assert not check_file(rules, graph([]), "other/x", "w.bin", XH).allowed


def test_revoked_content_is_refused_before_any_rule():
    mod = E.build_endorsement(key(1), pub(4), ["revoke"], 0.9, created_at=100)
    rev = E.build_revocation(key(4), "x", XH, taint=True, created_at=200)
    g = graph([mod, rev])
    d = check_file([], g, "o/m", "w.bin", XH)
    assert not d.allowed and d.code == "Revoked" and "tainted" in d.reason
    allow = parse_policy("[[file]]\naction='allow'")
    assert not check_file(allow, g, "o/m", "w.bin", XH).allowed


# ---------------------------------------------------------------------- signer

from torrenthub.signer import Signer, SignerConfig  # noqa: E402


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def make_signer(tmp_path, **kw):
    root = tmp_path / "root"
    root.mkdir(parents=True, exist_ok=True)
    clock = kw.pop("clock", Clock())
    cfg = SignerConfig(root, tmp_path / "audit" / "log.jsonl", **kw)
    return Signer(key(7), cfg, clock), root, clock


def test_signer_signs_what_it_computes_itself(tmp_path):
    s, root, _ = make_signer(tmp_path)
    p = st_file(root)
    sha = V.sha256_file(p)
    r = s.handle({"op": "attest_file", "path": str(p), "sha256": sha, "filenames": ["w.safetensors"]})
    assert r["ok"] and [E.parse_event(e).claim for e in r["events"]] == ["hash_verified", "format_scan"]
    assert all(e["pubkey"] == s.pubkey for e in r["events"])
    # asked to vouch for a hash the file does not have: it reports the failure, it does not sign a pass
    r = s.handle({"op": "attest_file", "path": str(p), "sha256": "00" * 32, "filenames": ["w.safetensors"]})
    assert [E.parse_event(e).ok for e in r["events"]] == [False]
    assert s.handle({"op": "pubkey"})["pubkey"] == s.pubkey


def test_signer_refuses_what_its_limits_do_not_allow(tmp_path):
    s, root, clock = make_signer(tmp_path, max_per_hour=3)
    p = st_file(root)
    sha = V.sha256_file(p)
    req = {"op": "attest_file", "path": str(p), "sha256": sha, "filenames": ["w.safetensors"]}
    outside = tmp_path / "outside.safetensors"
    outside.write_bytes(p.read_bytes())
    for bad in (
        {"op": "sign_anything", "event": {}},
        dict(req, path=str(outside)),
        dict(req, path=str(root / ".." / "outside.safetensors")),
        dict(req, path=str(root / "missing")),
        dict(req, path=""),
        dict(req, sha256="nothex"),
        dict(req, filenames="a"),
        {"op": "replicate", "path": str(p), "filenames": [], "event": "x"},
        "not a dict",
    ):
        assert s.handle(bad)["ok"] is False, bad
    assert s.handle(req)["ok"]  # 2 events
    r = s.handle(req)  # 2 more would pass the limit of 3 an hour
    assert not r["ok"] and "rate" in r["error"]
    clock.t += 3601
    assert s.handle(req)["ok"]


def test_signer_claims_and_expiry(tmp_path):
    s, root, clock = make_signer(tmp_path, allowed_claims=("hash_verified",))
    p = st_file(root)
    r = s.handle({"op": "attest_file", "path": str(p), "sha256": V.sha256_file(p), "filenames": ["w.safetensors"]})
    assert [E.parse_event(e).claim for e in r["events"]] == ["hash_verified"]
    s2, root2, clock2 = make_signer(tmp_path / "b", not_after=1_000_100)
    p2 = st_file(root2)
    req = {"op": "attest_file", "path": str(p2), "sha256": V.sha256_file(p2), "filenames": []}
    assert s2.handle(req)["ok"]
    clock2.t = 1_000_100
    r = s2.handle(req)
    assert not r["ok"] and "expired" in r["error"]


def test_signer_replicates_from_a_file(tmp_path):
    s, root, _ = make_signer(tmp_path)
    p = st_file(root)
    sha = V.sha256_file(p)
    lie = E.build_attestation(key(4), "format_scan", "x", sha, ok=False)
    r = s.handle({"op": "replicate", "path": str(p), "filenames": ["w.safetensors"], "event": lie})
    assert r["ok"] and E.parse_event(r["events"][0]).match is False
    assert not s.handle({"op": "replicate", "path": str(p), "filenames": [], "event": E.build_attestation(key(4), "review", "x", sha)})["ok"]


def test_every_decision_is_audited_and_limits_survive_a_restart(tmp_path):
    s, root, clock = make_signer(tmp_path, max_per_day=2)
    p = st_file(root)
    req = {"op": "attest_file", "path": str(p), "sha256": V.sha256_file(p), "filenames": ["w.safetensors"]}
    assert s.handle(req)["ok"]
    assert not s.handle(dict(req, path="/etc/passwd"))["ok"]
    log = [json.loads(l) for l in s.cfg.audit_path.read_text().splitlines()]
    assert [r["decision"] for r in log] == ["signed", "refused"]
    assert len(log[0]["events"]) == 2 and log[1]["reason"]
    again = Signer(key(7), s.cfg, clock)  # restart: the day's count comes back from the log
    assert not again.handle(req)["ok"]
    assert "secret" not in s.cfg.audit_path.read_text()


def test_a_signer_at_its_limit_refuses_before_reading_anything(tmp_path):
    s, root, clock = make_signer(tmp_path, max_per_hour=2)
    p = st_file(root)
    assert s.handle({"op": "attest_file", "path": str(p), "sha256": V.sha256_file(p), "filenames": ["w.safetensors"]})["ok"]
    r = s.handle({"op": "attest_file", "path": str(root / "does-not-exist"), "sha256": "00" * 32, "filenames": []})
    assert "rate limit" in r["error"]
