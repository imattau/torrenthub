"""The determinism harness: its tools are correct, its files are canonical, and compare tells the truth."""

from __future__ import annotations

import importlib.util
import json
import struct
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")

spec = importlib.util.spec_from_file_location("determinism", Path(__file__).parent.parent / "validation" / "determinism.py")
det = importlib.util.module_from_spec(spec)
spec.loader.exec_module(det)


def f32(*vals):
    return np.array(vals, dtype="<f4")


def bf16_of(x: float) -> int:
    return int(det.bf16_cast({"t": f32(x)})["t"][1][0])


def test_bf16_cast_matches_the_definition_on_known_values():
    assert bf16_of(1.0) == 0x3F80 and bf16_of(-2.0) == 0xC000 and bf16_of(0.0) == 0
    # 1 + 2^-8 is exactly halfway between two bfloat16 values: ties go to the even one (0x3F80)
    assert bf16_of(1.00390625) == 0x3F80
    # 1 + 3 * 2^-8 is halfway between 0x3F81 and 0x3F82: even is 0x3F82
    assert bf16_of(1.01171875) == 0x3F82
    # just above halfway rounds up, just below rounds down
    assert bf16_of(float(np.nextafter(np.float32(1.00390625), np.float32(2)))) == 0x3F81
    assert bf16_of(float(np.nextafter(np.float32(1.00390625), np.float32(0)))) == 0x3F80
    assert bf16_of(float("inf")) == 0x7F80 and bf16_of(float("-inf")) == 0xFF80
    assert bf16_of(float("nan")) == 0x7FC0
    # the largest finite float32 rounds up into infinity, as round to nearest even says
    assert bf16_of(3.4028235e38) == 0x7F80


def test_bf16_cast_agrees_with_an_independent_rounding_of_random_values():
    rng = np.random.default_rng(5)
    xs = rng.standard_normal(5000).astype("<f4") * np.float32(10) ** rng.integers(-20, 20, 5000).astype("<f4")
    got = det.bf16_cast({"t": xs})["t"][1]
    for x, g in zip(xs[:500], got[:500]):
        bits = struct.unpack("<I", struct.pack("<f", float(x)))[0]
        lower = bits & 0xFFFF
        up = bits >> 16
        want = up + 1 if lower > 0x8000 or (lower == 0x8000 and up & 1) else up
        assert int(g) == want & 0xFFFF


def test_written_files_are_canonical_and_round_trip(tmp_path):
    a = {"b": ("F32", f32(1, 2, 3)), "a": ("F32", f32(4, 5))}
    det.write_safetensors(str(tmp_path / "x"), a)
    det.write_safetensors(str(tmp_path / "y"), dict(reversed(list(a.items()))))
    assert (tmp_path / "x").read_bytes() == (tmp_path / "y").read_bytes(), "tensor order must not matter"
    raw = (tmp_path / "x").read_bytes()
    (n,) = struct.unpack("<Q", raw[:8])
    assert n % 8 == 0 and list(json.loads(raw[8:8 + n])) == ["a", "b"]
    back = det.read_safetensors(str(tmp_path / "x"))
    assert back["a"].tolist() == [4.0, 5.0] and back["b"].tolist() == [1.0, 2.0, 3.0]


def test_tools_are_repeatable_in_one_environment(tmp_path):
    det.make_input(str(tmp_path / "in"), 3)
    t = det.read_safetensors(str(tmp_path / "in"))
    for name, tool in det.TOOLS.items():
        det.write_safetensors(str(tmp_path / "o1"), tool(t))
        det.write_safetensors(str(tmp_path / "o2"), tool(t))
        assert (tmp_path / "o1").read_bytes() == (tmp_path / "o2").read_bytes(), name


def test_compare_reports_agreement_and_disagreement(tmp_path, capsys):
    def row(tool, out, label):
        env = {"host": "h", "OPENBLAS_CORETYPE": "", "OPENBLAS_NUM_THREADS": "", "label": label}
        return json.dumps({"tool": tool, "input_sha256": "aa" * 32, "output_sha256": out, "env": env})

    f = tmp_path / "r.jsonl"
    f.write_text("\n".join([row("t1", "11" * 32, "A"), row("t1", "11" * 32, "B"), row("t2", "22" * 32, "A"), row("t2", "33" * 32, "B")]))
    assert det.compare([str(f)]) == 1
    out = capsys.readouterr().out
    assert "t1  input aaaaaaaaaaaa  2 runs: BIT EXACT" in out and "t2  input aaaaaaaaaaaa  2 runs: DIFFERS" in out
    f.write_text(row("t1", "11" * 32, "A"))
    assert det.compare([str(f)]) == 0
