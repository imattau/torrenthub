import csv
from pathlib import Path

import pytest

from torrenthub import signing as sg

VECTORS = Path(__file__).parent / "data" / "bip340-test-vectors.csv"


def rows():
    with open(VECTORS, newline="") as f:
        return list(csv.DictReader(f))


@pytest.mark.parametrize("row", rows(), ids=lambda r: f"vector{r['index']}")
def test_official_bip340_vectors(row):
    pub = bytes.fromhex(row["public key"])
    msg = bytes.fromhex(row["message"])
    sig = bytes.fromhex(row["signature"])
    assert sg.verify(msg, pub, sig) == (row["verification result"] == "TRUE")
    if row["secret key"]:
        sk = bytes.fromhex(row["secret key"])
        assert sg.public_key(sk) == pub
        assert sg.sign(msg, sk, bytes.fromhex(row["aux_rand"])) == sig


def test_bech32_roundtrip_and_known_npub():
    # Example key pair from NIP-19.
    hexkey = "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
    npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
    assert sg.bech32_encode("npub", bytes.fromhex(hexkey)) == npub
    assert sg.parse_pubkey(npub) == hexkey
    assert sg.parse_pubkey(hexkey) == hexkey
    assert sg.parse_pubkey(npub.upper()) == hexkey


def test_bech32_spec_vector_and_rejections():
    assert sg.bech32_decode("A12UEL5L") == ("a", b"")
    for bad in ["npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptX", "npub1", "short", "x" * 63 + "!"]:
        with pytest.raises(ValueError):
            sg.parse_pubkey(bad)
    with pytest.raises(ValueError):
        sg.bech32_decode("a12uel5L")  # mixed case


def test_events_sign_verify_and_detect_tampering():
    sk = bytes.fromhex("00" * 31 + "07")
    ev = sg.sign_event(sk, 1, [["t", "x"]], "hello é \"q\"\n", 1700000000)
    assert sg.verify_event(ev)
    for field, value in [("content", "other"), ("created_at", 1), ("kind", 2), ("tags", []), ("pubkey", "aa" * 32)]:
        assert not sg.verify_event({**ev, field: value}), field
    assert not sg.verify_event({k: v for k, v in ev.items() if k != "sig"})
    assert not sg.verify_event({**ev, "sig": "00" * 64})


def test_secret_parsing():
    sk = bytes.fromhex("11" * 32)
    nsec = sg.bech32_encode("nsec", sk)
    assert sg.parse_secret(nsec) == sk and sg.parse_secret(sk.hex()) == sk
    with pytest.raises(ValueError):
        sg.parse_secret("11" * 31)
    with pytest.raises(ValueError):
        sg.public_key(bytes(32))


# --------------------------------------------------------- the two backends agree

import os  # noqa: E402
import random  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

needs_fast = pytest.mark.skipif(sg.backend() != "libsecp256k1", reason="coincurve is not installed")


@needs_fast
def test_official_vectors_pass_on_the_python_backend_too():
    for row in csv.DictReader(open(VECTORS)):
        pub, msg, sig = (bytes.fromhex(row[k]) for k in ("public key", "message", "signature"))
        assert sg.verify_py(msg, pub, sig) == (row["verification result"] == "TRUE"), row["index"]
        if row["secret key"]:
            sk, aux = bytes.fromhex(row["secret key"]), bytes.fromhex(row["aux_rand"])
            assert sg.sign_py(msg, sk, aux) == sig and sg.public_key_py(sk) == pub


@needs_fast
def test_both_backends_give_identical_keys_and_signatures():
    rng = random.Random(11)
    for _ in range(150):
        sk = rng.randrange(1, sg.N).to_bytes(32, "big")
        msg, aux = rng.randbytes(32), rng.randbytes(32)
        assert sg.public_key(sk) == sg.public_key_py(sk)
        assert sg.sign(msg, sk, aux) == sg.sign_py(msg, sk, aux), "deterministic given the same aux data"
    edge = [1, 2, sg.N - 1, sg.N - 2, (sg.N + 1) // 2]
    for d in edge:
        sk = d.to_bytes(32, "big")
        assert sg.public_key(sk) == sg.public_key_py(sk)
        assert sg.sign(b"\x07" * 32, sk, b"\x00" * 32) == sg.sign_py(b"\x07" * 32, sk, b"\x00" * 32)


@needs_fast
def test_both_backends_agree_on_valid_tampered_and_malformed_signatures():
    rng = random.Random(12)
    for _ in range(120):
        sk = rng.randrange(1, sg.N).to_bytes(32, "big")
        pub, msg = sg.public_key(sk), rng.randbytes(32)
        sig = sg.sign(msg, sk)
        cases = [(msg, pub, sig, True)]
        i = rng.randrange(64)
        bad = bytearray(sig)
        bad[i] ^= 1 << rng.randrange(8)
        cases += [(msg, pub, bytes(bad), False), (rng.randbytes(32), pub, sig, False), (msg, rng.randbytes(32), sig, None)]
        cases += [(msg, pub, sig[:63], False), (msg, pub, sig + b"\0", False), (msg, pub[:31], sig, False)]
        for m, p, s, want in cases:
            a, b = sg.verify(m, p, s), sg.verify_py(m, p, s)
            assert a == b, (want, a, b)
            if want is not None:
                assert a is want
    # structurally invalid values: r or s out of range, x not on the curve, x at or above p
    sk = rng.randrange(1, sg.N).to_bytes(32, "big")
    pub, msg = sg.public_key(sk), b"\x01" * 32
    good = sg.sign(msg, sk)
    for sig in (sg.P.to_bytes(32, "big") + good[32:], good[:32] + sg.N.to_bytes(32, "big"), b"\0" * 64, b"\xff" * 64):
        assert sg.verify(msg, pub, sig) == sg.verify_py(msg, pub, sig) == False  # noqa: E712
    for p in (sg.P.to_bytes(32, "big"), b"\xff" * 32, b"\0" * 32, (5).to_bytes(32, "big")):
        assert sg.verify(msg, p, good) == sg.verify_py(msg, p, good) == False  # noqa: E712


@needs_fast
def test_messages_that_are_not_32_bytes_still_work_through_the_python_path():
    sk = (7).to_bytes(32, "big")
    for n in (0, 1, 17, 33, 100):
        msg = bytes(range(n % 256)) * 1 if n else b""
        msg = (msg + b"x" * n)[:n]
        sig = sg.sign(msg, sk, b"\x01" * 32)
        assert sg.verify(msg, sg.public_key(sk), sig) and sg.verify_py(msg, sg.public_key(sk), sig)


def test_secret_keys_of_the_wrong_size_or_range_are_refused_by_every_path():
    for bad in (b"", b"\x01" * 31, b"\x01" * 33, (0).to_bytes(32, "big"), sg.N.to_bytes(32, "big"), b"\xff" * 32):
        with pytest.raises(ValueError):
            sg.public_key(bad)
        with pytest.raises(ValueError):
            sg.sign(b"\0" * 32, bad)


def test_the_backend_can_be_forced_to_python():
    out = subprocess.run([sys.executable, "-c", "from torrenthub import signing as s; print(s.backend())"], capture_output=True, text=True,
                         env=dict(os.environ, THUB_PURE_PYTHON_CRYPTO="1"), timeout=30)
    assert out.stdout.strip() == "python"


@needs_fast
def test_the_fast_backend_is_much_faster():
    import time

    sk = (9).to_bytes(32, "big")
    msg = b"\x02" * 32
    sig = sg.sign(msg, sk)
    pub = sg.public_key(sk)
    t0 = time.perf_counter()
    for _ in range(200):
        sg.verify(msg, pub, sig)
    fast = time.perf_counter() - t0
    t0 = time.perf_counter()
    for _ in range(20):
        sg.verify_py(msg, pub, sig)
    slow = (time.perf_counter() - t0) * 10
    assert slow > 20 * fast, (fast, slow)
