#!/usr/bin/env python3
"""Is a tool bit exact across machines? Run it everywhere, compare the output hashes.

PROTOCOL.md section 6: a derivation is class D (anyone can recompute it) only for a tool whose
output is the same bytes on every machine. Quantisation, merging and anything that sums floats may
differ between CPUs and BLAS builds, so nothing goes on a trusted tools list until this says so.

    python3 validation/determinism.py make-input input.safetensors [--seed 1]
    python3 validation/determinism.py run TOOL input.safetensors out.safetensors >> results.jsonl
    python3 validation/determinism.py compare results.jsonl [more.jsonl ...]

`run` prints one JSON line: the tool, the sha256 of its output, and what this machine is (CPU
flags numpy uses, numpy and BLAS versions, thread count). `compare` groups lines by tool and input
and says whether every environment agreed. Needs only numpy. To make the same machine behave like
a different CPU, set OPENBLAS_CORETYPE (for example Haswell, SkylakeX, Zen, Nehalem) and
OPENBLAS_NUM_THREADS before `run`.

Tools:
  bf16_cast  float32 -> bfloat16 by integer round to nearest even. No float arithmetic.
  rms_norm   x / sqrt(mean(x*x) + 1e-6) along the last axis. A float reduction.
  gram       W @ W.T for each 2D tensor. A float32 matrix product through BLAS.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import struct
import sys

import numpy as np


# ----------------------------------------------------------------------------- safetensors

def read_safetensors(path: str) -> dict[str, np.ndarray]:
    raw = open(path, "rb").read()
    (n,) = struct.unpack("<Q", raw[:8])
    header = json.loads(raw[8:8 + n])
    body = memoryview(raw)[8 + n:]
    out = {}
    for name, meta in header.items():
        if name == "__metadata__":
            continue
        if meta["dtype"] != "F32":
            raise SystemExit(f"{name}: only F32 inputs are supported, got {meta['dtype']}")
        a, b = meta["data_offsets"]
        out[name] = np.frombuffer(body[a:b], dtype="<f4").reshape(meta["shape"]).copy()
    return out


def write_safetensors(path: str, tensors: dict[str, tuple[str, np.ndarray]]) -> None:
    """Canonical layout: tensors in name order, header with sorted keys and no spaces, padded with
    spaces to a multiple of 8. The same tensors always give the same bytes."""
    header, offset, blobs = {}, 0, []
    for name in sorted(tensors):
        dtype, arr = tensors[name]
        data = np.ascontiguousarray(arr).tobytes()
        header[name] = {"dtype": dtype, "shape": list(arr.shape), "data_offsets": [offset, offset + len(data)]}
        offset += len(data)
        blobs.append(data)
    h = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    h += b" " * (-len(h) % 8)
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(h)) + h)
        for b in blobs:
            f.write(b)


# ----------------------------------------------------------------------------------- tools

def bf16_cast(t: dict[str, np.ndarray]) -> dict:
    out = {}
    for name, x in t.items():
        bits = x.astype("<f4").view("<u4").astype(np.uint64)
        rounded = ((bits + 0x7FFF + ((bits >> 16) & 1)) >> 16).astype("<u2")
        nan = (bits & 0x7FFFFFFF) > 0x7F800000
        rounded[nan] = 0x7FC0
        out[name] = ("BF16", rounded)
    return out


def rms_norm(t: dict[str, np.ndarray]) -> dict:
    out = {}
    for name, x in t.items():
        x2 = x.reshape(-1, x.shape[-1]) if x.ndim else x.reshape(1, 1)
        y = x2 / np.sqrt(np.mean(x2 * x2, axis=-1, keepdims=True) + np.float32(1e-6))
        out[name] = ("F32", y.astype("<f4").reshape(x.shape))
    return out


def gram(t: dict[str, np.ndarray]) -> dict:
    return {name: ("F32", (x @ x.T).astype("<f4")) for name, x in t.items() if x.ndim == 2}


TOOLS = {"bf16_cast": bf16_cast, "rms_norm": rms_norm, "gram": gram}


# ------------------------------------------------------------------------------ environment

def cpu_flags() -> list[str]:
    try:
        from numpy._core._multiarray_umath import __cpu_features__ as f
    except ImportError:  # numpy 1.x
        from numpy.core._multiarray_umath import __cpu_features__ as f
    return sorted(k for k, v in f.items() if v)


def blas_info() -> str:
    try:
        cfg = np.show_config(mode="dicts")
        b = cfg.get("Build Dependencies", {}).get("blas", {})
        return f"{b.get('name', '?')} {b.get('version', '')}".strip()
    except Exception:  # noqa: BLE001
        return "?"


def cpu_model() -> str:
    try:
        for line in open("/proc/cpuinfo"):
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "?"


def environment() -> dict:
    return {
        "host": platform.node(), "os": f"{platform.system()} {platform.release()}", "python": platform.python_version(),
        "numpy": np.__version__, "blas": blas_info(), "cpu": cpu_model(),
        "numpy_cpu_features": [f for f in cpu_flags() if f.startswith(("AVX", "FMA", "SSE4", "SSSE3", "F16C"))],
        "OPENBLAS_CORETYPE": os.environ.get("OPENBLAS_CORETYPE", ""),
        "OPENBLAS_NUM_THREADS": os.environ.get("OPENBLAS_NUM_THREADS", ""),
        "label": os.environ.get("DETERMINISM_LABEL", ""),
    }


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------------- commands

def make_input(path: str, seed: int) -> None:
    rng = np.random.default_rng(seed)
    t = {
        "attn.q": ("F32", rng.standard_normal((192, 1536), dtype=np.float32)),
        "mlp.up": ("F32", (rng.standard_normal((256, 2048), dtype=np.float32) * np.float32(0.02))),
        "embed": ("F32", rng.standard_normal((300, 512), dtype=np.float32)),
        "bias": ("F32", rng.standard_normal((4096,), dtype=np.float32)),
    }
    write_safetensors(path, t)
    print(json.dumps({"input": path, "sha256": sha256_file(path), "seed": seed}))


def run(tool: str, src: str, dst: str) -> None:
    out = TOOLS[tool](read_safetensors(src))
    write_safetensors(dst, out)
    print(json.dumps({"tool": tool, "input_sha256": sha256_file(src), "output_sha256": sha256_file(dst), "env": environment()}))


def compare(files: list[str]) -> int:
    rows = [json.loads(line) for f in files for line in open(f) if line.strip()]
    groups: dict[tuple, list[dict]] = {}
    for r in rows:
        groups.setdefault((r["tool"], r["input_sha256"]), []).append(r)
    bad = 0
    for (tool, inp), rs in sorted(groups.items()):
        hashes: dict[str, list[str]] = {}
        for r in rs:
            e = r["env"]
            name = e.get("label") or f"{e['host']} {e['OPENBLAS_CORETYPE'] or 'auto'} t{e['OPENBLAS_NUM_THREADS'] or 'auto'}"
            hashes.setdefault(r["output_sha256"], []).append(name)
        verdict = "BIT EXACT" if len(hashes) == 1 else f"DIFFERS ({len(hashes)} distinct outputs)"
        print(f"\n{tool}  input {inp[:12]}  {len(rs)} runs: {verdict}")
        for h, names in sorted(hashes.items(), key=lambda kv: -len(kv[1])):
            print(f"  {h[:16]}  x{len(names)}: {', '.join(names)}")
        bad += len(hashes) > 1
    return 1 if bad else 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("make-input")
    m.add_argument("path")
    m.add_argument("--seed", type=int, default=1)
    r = sub.add_parser("run")
    r.add_argument("tool", choices=sorted(TOOLS))
    r.add_argument("input")
    r.add_argument("output")
    c = sub.add_parser("compare")
    c.add_argument("files", nargs="+")
    a = p.parse_args()
    if a.cmd == "make-input":
        make_input(a.path, a.seed)
    elif a.cmd == "run":
        run(a.tool, a.input, a.output)
    else:
        return compare(a.files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
