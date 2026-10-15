"""Minimal BitTorrent v1 metainfo support: bencode, piece hashing, .torrent building.

Design rule: the infohash must be a pure function of the file content. Two gateways
that mirror the same blob independently must produce the same infohash, so their
peers join one swarm. That means the info dict contains only:
  name (the content sha256 or git blob id), length, piece length, pieces.
Nothing time-based or gateway-specific goes in there. Trackers and web seeds live
outside the info dict and do not change the infohash.

The piece length policy is part of that contract. Changing it changes every infohash,
so it is versioned (PIECE_POLICY_VERSION) and must not be edited casually.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any
from urllib.parse import quote

PIECE_POLICY_VERSION = 1
MIN_PIECE = 256 * 1024
MAX_PIECE = 16 * 1024 * 1024
TARGET_MAX_PIECES = 2048


def choose_piece_length(size: int) -> int:
    """Smallest power-of-two piece length (256 KiB to 16 MiB) giving <= 2048 pieces."""
    pl = MIN_PIECE
    while pl < MAX_PIECE and size / pl > TARGET_MAX_PIECES:
        pl *= 2
    return pl


# ---------------------------------------------------------------- bencode

def bencode(x: Any) -> bytes:
    if isinstance(x, bool):
        raise TypeError("bool is not bencodable")
    if isinstance(x, int):
        return b"i%de" % x
    if isinstance(x, str):
        x = x.encode()
    if isinstance(x, (bytes, bytearray)):
        return b"%d:%s" % (len(x), bytes(x))
    if isinstance(x, (list, tuple)):
        return b"l" + b"".join(bencode(i) for i in x) + b"e"
    if isinstance(x, dict):
        items = sorted(((k.encode() if isinstance(k, str) else k), v) for k, v in x.items())
        return b"d" + b"".join(bencode(k) + bencode(v) for k, v in items) + b"e"
    raise TypeError(f"cannot bencode {type(x)!r}")


def bdecode(data: bytes) -> Any:
    value, end = _decode(data, 0)
    if end != len(data):
        raise ValueError("trailing data after bencoded value")
    return value


def _decode(data: bytes, i: int) -> tuple[Any, int]:
    c = data[i:i + 1]
    if c == b"i":
        j = data.index(b"e", i)
        return int(data[i + 1:j]), j + 1
    if c == b"l":
        i += 1
        out = []
        while data[i:i + 1] != b"e":
            v, i = _decode(data, i)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while data[i:i + 1] != b"e":
            k, i = _decode(data, i)
            v, i = _decode(data, i)
            out[k] = v
        return out, i + 1
    if c.isdigit():
        j = data.index(b":", i)
        n = int(data[i:j])
        return data[j + 1:j + 1 + n], j + 1 + n
    raise ValueError(f"bad bencode at offset {i}")


# ---------------------------------------------------------------- hashing

class PieceHasher:
    """Streaming SHA-1 per piece, as BitTorrent v1 requires."""

    def __init__(self, piece_length: int):
        self.piece_length = piece_length
        self._pieces: list[bytes] = []
        self._cur = hashlib.sha1()
        self._filled = 0
        self.total = 0

    def update(self, data: bytes) -> None:
        mv = memoryview(data)
        while len(mv):
            room = self.piece_length - self._filled
            chunk = mv[:room]
            self._cur.update(chunk)
            self._filled += len(chunk)
            mv = mv[len(chunk):]
            if self._filled == self.piece_length:
                self._pieces.append(self._cur.digest())
                self._cur = hashlib.sha1()
                self._filled = 0
        self.total += len(data)

    def finish(self) -> bytes:
        if self._filled:
            self._pieces.append(self._cur.digest())
            self._cur = hashlib.sha1()
            self._filled = 0
        return b"".join(self._pieces)


# ---------------------------------------------------------------- building

def build_torrent(
    *,
    name: str,
    length: int,
    piece_length: int,
    pieces: bytes,
    trackers: list[str] | None = None,
    webseeds: list[str] | None = None,
    comment: str = "",
) -> tuple[bytes, str]:
    """Return (.torrent bytes, infohash hex). Single-file torrent, BEP-3 plus BEP-19."""
    info = {
        "name": name,
        "length": length,
        "piece length": piece_length,
        "pieces": pieces,
    }
    meta: dict[str, Any] = {
        "info": info,
        "created by": "torrenthub",
        "creation date": int(time.time()),
    }
    if trackers:
        meta["announce"] = trackers[0]
        meta["announce-list"] = [[t] for t in trackers]
    if webseeds:
        meta["url-list"] = list(webseeds)
    if comment:
        meta["comment"] = comment
    return bencode(meta), infohash_of(info)


def infohash_of(info: dict) -> str:
    return hashlib.sha1(bencode(info)).hexdigest()


def magnet(infohash: str, name: str, trackers: list[str], webseeds: list[str]) -> str:
    parts = [f"xt=urn:btih:{infohash}", f"dn={quote(name)}"]
    parts += [f"tr={quote(t, safe='')}" for t in trackers]
    parts += [f"ws={quote(w, safe='')}" for w in webseeds]
    return "magnet:?" + "&".join(parts)


MAX_TORRENT_BYTES = 4 * 1024 * 1024


class TorrentRejected(ValueError):
    """A torrent obtained from outside this process failed validation."""


def validate_torrent(data: bytes, key: str, size: int) -> dict:
    """Check a torrent received from an index before trusting it with a download.

    The torrent must describe exactly the blob we asked for, built with our piece policy,
    so it joins the common swarm. It cannot prove the content is right: the sha256 check
    after download does that. What it prevents is wasting a download, or joining an
    unrelated swarm, on a torrent that was never about this blob.
    """
    if len(data) > MAX_TORRENT_BYTES:
        raise TorrentRejected("torrent too large")
    try:
        meta = bdecode(data)
    except Exception as e:  # noqa: BLE001
        raise TorrentRejected(f"not valid bencoding: {e}") from e
    if not isinstance(meta, dict) or not isinstance(meta.get(b"info"), dict):
        raise TorrentRejected("no info dict")
    info = meta[b"info"]
    if b"files" in info or b"meta version" in info or b"file tree" in info:
        raise TorrentRejected("only single-file v1 torrents are accepted")
    if info.get(b"name") != key.encode():
        raise TorrentRejected("torrent name does not match the blob key")
    if info.get(b"length") != size:
        raise TorrentRejected("torrent length does not match the blob size")
    pl = info.get(b"piece length")
    if pl != choose_piece_length(size):
        raise TorrentRejected("piece length does not follow the piece policy")
    pieces = info.get(b"pieces")
    if not isinstance(pieces, bytes) or len(pieces) != 20 * -(-size // pl):
        raise TorrentRejected("piece hash list has the wrong length")
    return meta


def sanitize_torrent(data: bytes, trackers: list[str] | None = None, webseeds: list[str] | None = None) -> bytes:
    """Keep what defines the content and nothing else the sender chose.

    A torrent from another hub or a publisher can name any tracker, DHT node or web seed, and our
    swarm engine would contact them: libtorrent refuses a tracker on a local address unless its
    path ends in /announce, but `http://10.0.0.5/announce` still gets a request carrying this
    machine's address and port, and a UDP tracker gets a packet. So only the `info` dictionary is
    kept, copied byte for byte (so the infohash cannot change), and the trackers and web seeds are
    the ones the caller, which is configured by the operator, passes in.

    The `info` dictionary must already be in canonical form (sorted keys, no extra whitespace),
    because infohash_from_torrent re-encodes it and the two must agree with libtorrent's, which
    hashes the original bytes. Raises TorrentRejected otherwise.
    """
    if len(data) > MAX_TORRENT_BYTES:
        raise TorrentRejected("torrent too large")
    try:
        if data[:1] != b"d":
            raise ValueError("not a dictionary")
        i = 1
        info_raw = None
        while data[i:i + 1] != b"e":
            k, i = _decode(data, i)
            start = i
            v, i = _decode(data, i)
            if k == b"info":
                if not isinstance(v, dict):
                    raise ValueError("info is not a dictionary")
                info_raw, info = data[start:i], v
        if i + 1 != len(data) or info_raw is None:
            raise ValueError("no info dictionary, or trailing data")
    except Exception as e:  # noqa: BLE001  (RecursionError, IndexError and ValueError all mean: not a torrent)
        raise TorrentRejected(f"not a usable torrent: {type(e).__name__}") from e
    if bencode(info) != info_raw:
        raise TorrentRejected("the info dictionary is not in canonical form")
    out = b"d"
    if trackers:
        out += b"8:announce" + bencode(trackers[0]) + b"13:announce-list" + bencode([[t] for t in trackers])
    out += b"4:info" + info_raw
    if webseeds:
        out += b"8:url-list" + bencode(list(webseeds))
    return out + b"e"


def strip_webseeds(data: bytes) -> bytes:
    """Remove web seed URLs from a torrent. The infohash does not change, because web
    seeds live outside the info dict. Used so a client downloads from peers only."""
    meta = bdecode(data)
    meta.pop(b"url-list", None)
    meta.pop(b"httpseeds", None)
    return bencode(meta)


def infohash_from_torrent(data: bytes) -> str:
    return hashlib.sha1(bencode(bdecode(data)[b"info"])).hexdigest()


def verify_file_against_info(info: dict, path: str) -> bool:
    """Re-hash a file and compare against the piece hashes in an info dict."""
    pl = info[b"piece length"] if b"piece length" in info else info["piece length"]
    pieces = info[b"pieces"] if b"pieces" in info else info["pieces"]
    hasher = PieceHasher(pl)
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            hasher.update(chunk)
    return hasher.finish() == pieces
