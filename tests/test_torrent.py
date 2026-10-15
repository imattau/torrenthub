import hashlib

import pytest

from torrenthub.torrent import (
    PieceHasher,
    bdecode,
    bencode,
    build_torrent,
    choose_piece_length,
    infohash_of,
)


def test_bencode_roundtrip():
    obj = {b"a": 1, b"b": [b"x", 2, {b"c": b"d"}], b"e": b""}
    assert bdecode(bencode(obj)) == obj


def test_bencode_sorts_keys():
    assert bencode({"b": 1, "a": 2}) == b"d1:ai2e1:bi1ee"


def test_bencode_rejects_bool():
    with pytest.raises(TypeError):
        bencode(True)


@pytest.mark.parametrize(
    "size,expected",
    [
        (0, 256 * 1024),
        (100 * 1024**2, 256 * 1024),
        (1024**3, 512 * 1024),
        (10 * 1024**3, 8 * 1024 * 1024 // 1),  # 10 GiB needs 8 MiB pieces for <= 2048 pieces
        (500 * 1024**3, 16 * 1024 * 1024),  # capped
    ],
)
def test_piece_length_policy(size, expected):
    assert choose_piece_length(size) == expected


def test_piece_hasher_matches_naive():
    data = bytes(range(256)) * 5000
    pl = 256 * 1024
    h = PieceHasher(pl)
    for i in range(0, len(data), 7777):  # awkward chunk size on purpose
        h.update(data[i:i + 7777])
    naive = b"".join(hashlib.sha1(data[i:i + pl]).digest() for i in range(0, len(data), pl))
    assert h.finish() == naive


def test_infohash_independent_of_trackers_and_webseeds():
    pieces = hashlib.sha1(b"x").digest()
    a, ha = build_torrent(name="n", length=1, piece_length=262144, pieces=pieces, trackers=["udp://a"], webseeds=["http://a/x"])
    b, hb = build_torrent(name="n", length=1, piece_length=262144, pieces=pieces, trackers=["udp://b"], webseeds=["http://b/y"])
    assert a != b
    expected = infohash_of({"name": "n", "length": 1, "piece length": 262144, "pieces": pieces})
    assert ha == hb == expected


# ------------------------------------------------------------------ validation of foreign torrents

import hashlib as _hashlib

from torrenthub.torrent import (
    TorrentRejected,
    infohash_from_torrent,
    strip_webseeds,
    validate_torrent,
)
from torrenthub.upstream import Upstream, token_allowed_for

_DATA = bytes(range(256)) * 4096  # 1 MiB
_KEY = _hashlib.sha256(_DATA).hexdigest()


def _good(**over):
    pl = choose_piece_length(len(_DATA))
    h = PieceHasher(pl)
    h.update(_DATA)
    args = dict(name=_KEY, length=len(_DATA), piece_length=pl, pieces=h.finish(),
                trackers=["udp://t.example:1/announce"], webseeds=["http://hub.example/blobs/x"])
    args.update(over)
    return build_torrent(**args)[0]


def test_validate_accepts_a_correct_torrent():
    meta = validate_torrent(_good(), _KEY, len(_DATA))
    assert meta[b"info"][b"name"] == _KEY.encode()


@pytest.mark.parametrize(
    "over",
    [
        {"name": "other"},
        {"length": len(_DATA) + 1},
        {"piece_length": 512 * 1024},  # not what the piece policy gives for this size
        {"pieces": b"\x00" * 20},  # wrong number of hashes
        {"pieces": b"\x00" * 7},
    ],
)
def test_validate_rejects_mismatched_torrents(over):
    with pytest.raises(TorrentRejected):
        validate_torrent(_good(**over), _KEY, len(_DATA))


def test_validate_rejects_garbage_multifile_and_oversize():
    with pytest.raises(TorrentRejected):
        validate_torrent(b"not bencoding at all", _KEY, len(_DATA))
    with pytest.raises(TorrentRejected):
        validate_torrent(bencode({"info": {"name": _KEY, "files": []}}), _KEY, len(_DATA))
    with pytest.raises(TorrentRejected):
        validate_torrent(b"x" * (5 * 1024 * 1024), _KEY, len(_DATA))


def test_strip_webseeds_keeps_infohash_and_trackers():
    full = _good()
    stripped = strip_webseeds(full)
    assert b"url-list" in full and b"url-list" not in stripped
    assert infohash_from_torrent(stripped) == infohash_from_torrent(full)
    assert bdecode(stripped)[b"announce"] == b"udp://t.example:1/announce"


def test_token_only_goes_to_huggingface():
    assert token_allowed_for("https://huggingface.co")
    assert token_allowed_for("https://cdn-lfs.huggingface.co/x")
    assert not token_allowed_for("https://hub.example.org")
    assert not token_allowed_for("https://huggingface.co.evil.example")
    assert not token_allowed_for("http://127.0.0.1:8080")
    assert "authorization" not in Upstream("https://hub.example.org", token="hf_secret").client.headers
    assert Upstream("https://huggingface.co", token="hf_x").client.headers["authorization"] == "Bearer hf_x"
