"""Manifest version 2: seq, valid_until and tables moved into blobs. Version 1 keeps working."""

from __future__ import annotations

import json

import pytest

from torrenthub import signing as sg
from torrenthub.manifest import (
    INLINE_ROWS, MANIFEST_KIND, ManifestInvalid, build_manifest, content_commit, table_bytes, table_sha256, verify_manifest,
    with_table,
)

SK = bytes.fromhex("00" * 31 + "2a")
PK = sg.public_key(SK).hex()
REPO = "acme/mine"
COMMIT = "ab" * 20


def info(n=3, commit=COMMIT):
    return {"sha": commit, "siblings": [{"rfilename": f"f{i:04d}.bin", "size": 10 + i, "lfs": {"size": 10 + i, "sha256": f"{i:064x}"}}
                                         for i in range(n)]}


def test_v1_is_unchanged_and_ranks_as_seq_zero():
    m = verify_manifest(build_manifest(SK, REPO, info(), ["main"], created_at=100), {PK}, REPO)
    assert (m.seq, m.valid_until, m.files_x, m.needs_table) == (0, None, None, False) and len(m.rows) == 3
    assert json.loads(build_manifest(SK, REPO, info(), ["main"])["content"])["v"] == 1


def test_v2_carries_seq_and_valid_until_inline():
    ev = build_manifest(SK, REPO, info(), ["main"], created_at=100, seq=7, valid_until=500)
    m = verify_manifest(ev, {PK}, REPO)
    assert (m.seq, m.valid_until, m.needs_table) == (7, 500, False) and len(m.rows) == 3
    assert not m.expired(499) and m.expired(500) and m.expired(10_000)
    assert ["seq", "7"] in ev["tags"]
    assert not verify_manifest(build_manifest(SK, REPO, info(), ["main"], created_at=100, seq=1), {PK}, REPO).expired(10**12)


def test_a_large_table_moves_into_a_blob_and_must_match_its_signed_hash():
    inf = info(INLINE_ROWS + 5)
    ev = build_manifest(SK, REPO, inf, ["main"], created_at=100, seq=1)
    assert len(ev["content"]) < 2000, "the event stays small"
    m = verify_manifest(ev, {PK}, REPO)
    assert m.needs_table and m.rows is None and m.files_x == table_sha256(verify_manifest(
        build_manifest(SK, REPO, inf, ["main"], seq=1, table_blob=False), {PK}, REPO).rows)
    from torrenthub.federation import fingerprint

    table = table_bytes(fingerprint(inf))
    full = with_table(m, table)
    assert full.rows == fingerprint(inf) and not full.needs_table
    assert verify_manifest(ev, {PK}, REPO, table=table).rows == fingerprint(inf)
    with pytest.raises(ManifestInvalid):
        with_table(m, table.replace(b"f0001", b"f0002"))
    with pytest.raises(ManifestInvalid):
        with_table(m, table + b" ")  # right content, wrong bytes: not the signed hash
    with pytest.raises(ManifestInvalid):
        verify_manifest(ev, {PK}, REPO, table=b"{}")


def test_a_table_blob_can_be_forced_on_or_off():
    assert verify_manifest(build_manifest(SK, REPO, info(2), ["main"], seq=1, table_blob=True), {PK}, REPO).needs_table
    assert not verify_manifest(build_manifest(SK, REPO, info(INLINE_ROWS + 1), ["main"], seq=1, table_blob=False), {PK}, REPO).needs_table


def resign(ev, content=None, tags=None):
    return sg.sign_event(SK, MANIFEST_KIND, tags if tags is not None else ev["tags"], content if content is not None else ev["content"], ev["created_at"])


def test_bad_v2_manifests_are_rejected():
    ev = build_manifest(SK, REPO, info(), ["main"], created_at=100, seq=3)
    body = json.loads(ev["content"])

    def bad(**changes):
        b = dict(body, **changes)
        b = {k: v for k, v in b.items() if v is not ...}
        return resign(ev, json.dumps(b, separators=(",", ":"), sort_keys=True))

    for ev2 in (bad(seq=0), bad(seq=True), bad(seq="3"), bad(valid_until="soon"), bad(files_x="ab" * 32),  # both files and files_x
                bad(files=...), bad(files_x="zz"), bad(files_i="nothex")):
        with pytest.raises(ManifestInvalid):
            verify_manifest(ev2, {PK}, REPO)
    with pytest.raises(ManifestInvalid):  # the seq tag must agree with the signed content
        verify_manifest(resign(ev, tags=[t for t in ev["tags"] if t[0] != "seq"] + [["seq", "4"]]), {PK}, REPO)
    with pytest.raises(ManifestInvalid):
        verify_manifest(resign(ev, tags=[t for t in ev["tags"] if t[0] != "seq"]), {PK}, REPO)
    with pytest.raises(ManifestInvalid):  # unknown version
        verify_manifest(resign(ev, json.dumps(dict(body, v=3), separators=(",", ":"), sort_keys=True)), {PK}, REPO)


def test_builder_refuses_nonsense():
    for kw in (dict(seq=0), dict(seq=-1), dict(seq=True), dict(seq=1, valid_until=50), dict(valid_until=500), dict(table_blob=True),
               dict(seq=1, table_blob=True, files_i="nope")):
        with pytest.raises(ValueError):
            build_manifest(SK, REPO, info(), ["main"], created_at=100, **kw)


def test_the_content_commit_names_the_table():
    from torrenthub.federation import fingerprint

    rows = fingerprint(info())
    c = content_commit(rows)
    assert len(c) == 40 and c == table_sha256(rows)[:40]
    assert content_commit(fingerprint(info(4))) != c
