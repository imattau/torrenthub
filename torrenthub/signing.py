"""Schnorr signatures (BIP-340), bech32 keys (npub / nsec) and Nostr style signed events.

This is the same signature scheme and event layout Nostr uses (NIP-01), so a signed manifest can
also be published to a relay. Nothing here talks to a relay.

The code is small and slow (pure Python, a few milliseconds per signature). It is checked against
the official BIP-340 test vectors in tests/data. Do not use it for anything that needs constant
time behaviour: signing here is for a creator signing a manifest on their own machine.
"""

from __future__ import annotations

import hashlib
import json
import os

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)

Point = tuple[int, int] | None


def _add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and a[1] != b[1]:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(pt: Point, k: int) -> Point:
    r: Point = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _tagged(tag: str, *parts: bytes) -> bytes:
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + b"".join(parts)).digest()


def _lift_x(x: int) -> Point:
    if x >= P:
        return None
    y_sq = (pow(x, 3, P) + 7) % P
    y = pow(y_sq, (P + 1) // 4, P)
    if pow(y, 2, P) != y_sq:
        return None
    return x, y if y % 2 == 0 else P - y


def public_key(secret: bytes) -> bytes:
    d = int.from_bytes(secret, "big")
    if not 1 <= d < N:
        raise ValueError("secret key out of range")
    pt = _mul(G, d)
    assert pt is not None
    return pt[0].to_bytes(32, "big")


def sign(msg: bytes, secret: bytes, aux: bytes | None = None) -> bytes:
    d0 = int.from_bytes(secret, "big")
    if not 1 <= d0 < N:
        raise ValueError("secret key out of range")
    aux = os.urandom(32) if aux is None else aux
    pt = _mul(G, d0)
    assert pt is not None
    d = d0 if pt[1] % 2 == 0 else N - d0
    px = pt[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(_tagged("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(_tagged("BIP0340/nonce", t, px, msg), "big") % N
    if k0 == 0:
        raise ValueError("nonce is zero, retry with other aux data")
    r_pt = _mul(G, k0)
    assert r_pt is not None
    k = k0 if r_pt[1] % 2 == 0 else N - k0
    rx = r_pt[0].to_bytes(32, "big")
    e = int.from_bytes(_tagged("BIP0340/challenge", rx, px, msg), "big") % N
    sig = rx + ((k + e * d) % N).to_bytes(32, "big")
    if not verify(msg, px, sig):  # cheap self check
        raise RuntimeError("produced an invalid signature")
    return sig


def verify(msg: bytes, pub: bytes, sig: bytes) -> bool:
    if len(pub) != 32 or len(sig) != 64:
        return False
    pt = _lift_x(int.from_bytes(pub, "big"))
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if pt is None or r >= P or s >= N:
        return False
    e = int.from_bytes(_tagged("BIP0340/challenge", sig[:32], pub, msg), "big") % N
    r_pt = _add(_mul(G, s), _mul(pt, N - e))
    return r_pt is not None and r_pt[1] % 2 == 0 and r_pt[0] == r


# ---------------------------------------------------------------- bech32 (BIP-173), for npub / nsec

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convert_bits(data: list[int], frm: int, to: int, pad: bool) -> list[int]:
    acc = bits = 0
    out = []
    maxv = (1 << to) - 1
    for v in data:
        if v < 0 or v >> frm:
            raise ValueError("bad value")
        acc = (acc << frm) | v
        bits += frm
        while bits >= to:
            bits -= to
            out.append((acc >> bits) & maxv)
    if pad:
        if bits:
            out.append((acc << (to - bits)) & maxv)
    elif bits >= frm or ((acc << (to - bits)) & maxv):
        raise ValueError("bad padding")
    return out


def bech32_encode(hrp: str, data: bytes) -> str:
    vals = _convert_bits(list(data), 8, 5, True)
    chk = _polymod(_hrp_expand(hrp) + vals + [0] * 6) ^ 1
    checksum = [(chk >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(_CHARSET[v] for v in vals + checksum)


def bech32_decode(s: str) -> tuple[str, bytes]:
    if s != s.lower() and s != s.upper():
        raise ValueError("mixed case")
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        raise ValueError("bad bech32 string")
    hrp, rest = s[:pos], s[pos + 1:]
    if any(c not in _CHARSET for c in rest):
        raise ValueError("bad bech32 character")
    vals = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + vals) != 1:
        raise ValueError("bad bech32 checksum")
    return hrp, bytes(_convert_bits(vals[:-6], 5, 8, False))


def parse_pubkey(s: str) -> str:
    """A public key as 64 hex characters, from hex or an npub. Raises ValueError otherwise."""
    s = s.strip()
    if s.lower().startswith("npub1"):
        hrp, data = bech32_decode(s)
        if hrp != "npub" or len(data) != 32:
            raise ValueError("not a valid npub")
        return data.hex()
    if len(s) == 64:
        try:
            raw = bytes.fromhex(s)
        except ValueError:
            raise ValueError("public key is not hex") from None
        if _lift_x(int.from_bytes(raw, "big")) is None:
            raise ValueError("public key is not a point on the curve")
        return raw.hex()
    raise ValueError("public key must be 64 hex characters or an npub")


def parse_secret(s: str) -> bytes:
    s = s.strip()
    if s.lower().startswith("nsec1"):
        hrp, data = bech32_decode(s)
        if hrp != "nsec" or len(data) != 32:
            raise ValueError("not a valid nsec")
        return data
    raw = bytes.fromhex(s)
    if len(raw) != 32:
        raise ValueError("secret key must be 32 bytes")
    return raw


# ---------------------------------------------------------------- Nostr style events (NIP-01 layout)

def event_id(ev: dict) -> str:
    body = [0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]]
    return hashlib.sha256(json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def sign_event(secret: bytes, kind: int, tags: list[list[str]], content: str, created_at: int) -> dict:
    ev = {
        "pubkey": public_key(secret).hex(),
        "created_at": int(created_at),
        "kind": kind,
        "tags": tags,
        "content": content,
    }
    ev["id"] = event_id(ev)
    ev["sig"] = sign(bytes.fromhex(ev["id"]), secret).hex()
    return ev


def verify_event(ev: dict) -> bool:
    """The id matches the contents and the signature matches the id and the public key."""
    try:
        if ev["id"] != event_id(ev):
            return False
        return verify(bytes.fromhex(ev["id"]), bytes.fromhex(ev["pubkey"]), bytes.fromhex(ev["sig"]))
    except (KeyError, TypeError, ValueError):
        return False
