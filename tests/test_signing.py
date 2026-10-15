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
