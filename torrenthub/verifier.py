"""Checks a participant can run on a blob and sign: hash_verified and format_scan.

Both are class D: anyone with the bytes can redo them and get the same answer. A format scan
is not a guarantee. It checks that the file parses as the format it claims and has none of the
unsafe constructs this code knows to look for. It does not find every bad file.

Formats:
  .safetensors     header parses, tensors are contiguous and fill the file exactly, sizes agree
                   with dtype and shape for the dtypes known here
  pickle based     (.bin .pt .pth .ckpt .pkl .pickle .joblib) the file is run through the real
                   unpickler, so its own bookkeeping decides what gets imported, with every import
                   routed to one function that returns inert stand-ins and notes any name outside a
                   short list of tensor rebuild functions. Nothing is imported or called for real.
                   Every pickle a loader would read is scanned: all the entries of a zip, and up to
                   five in a row in an older file. Anything unreadable fails the scan.
  .gguf            magic and version only. That is a weak check and the tool name says so.
Other files get no format_scan.
"""

from __future__ import annotations

import hashlib
import json
import pickle
import struct
import zipfile
from pathlib import Path

from . import events as E
from .store import Store

TOOL_ST = "thub-scan-safetensors/1"
TOOL_PICKLE = "thub-scan-pickle/2"
TOOL_GGUF = "thub-scan-gguf-magic/1"
TOOL_HASH = "thub-sha256/1"

PICKLE_EXT = (".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib")
ST_BYTES = {"F64": 8, "F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4, "I16": 2, "I8": 1, "U64": 8, "U32": 4, "U16": 2, "U8": 1, "BOOL": 1,
            "F8_E4M3": 1, "F8_E5M2": 1}
MAX_ST_HEADER = 100_000_000

SAFE_GLOBALS = {
    ("collections", "OrderedDict"), ("torch._utils", "_rebuild_tensor_v2"), ("torch._utils", "_rebuild_tensor"),
    ("torch._utils", "_rebuild_parameter"), ("torch._tensor", "_rebuild_from_type_v2"), ("torch", "Size"),
    ("torch", "device"),
}
SAFE_TORCH_NAMES = {"float16", "float32", "float64", "bfloat16", "int8", "int16", "int32", "int64", "uint8", "bool", "complex64", "complex128"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def hash_check(path: Path, sha256: str) -> tuple[bool, str]:
    got = sha256_file(path)
    return got == sha256, "" if got == sha256 else f"bytes hash to {got[:16]}, not {sha256[:16]}"


def scan_safetensors(path: Path) -> tuple[bool, str]:
    size = path.stat().st_size
    with open(path, "rb") as f:
        raw = f.read(8)
        if len(raw) < 8:
            return False, "too short for a safetensors header"
        n = struct.unpack("<Q", raw)[0]
        if n == 0 or n > MAX_ST_HEADER or 8 + n > size:
            return False, f"header length {n} does not fit the file"
        try:
            header = json.loads(f.read(n))
        except (ValueError, UnicodeDecodeError):
            return False, "header is not valid JSON"
    if not isinstance(header, dict):
        return False, "header is not an object"
    meta = header.get("__metadata__", {})
    if not isinstance(meta, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in meta.items()):
        return False, "__metadata__ must map strings to strings"
    spans = []
    for name, t in header.items():
        if name == "__metadata__":
            continue
        if not isinstance(t, dict) or not isinstance(t.get("dtype"), str) or not isinstance(t.get("shape"), list):
            return False, f"tensor {name!r} is malformed"
        shape, off = t["shape"], t.get("data_offsets")
        if not all(isinstance(d, int) and not isinstance(d, bool) and d >= 0 for d in shape):
            return False, f"tensor {name!r} has a bad shape"
        if not (isinstance(off, list) and len(off) == 2 and all(isinstance(o, int) and not isinstance(o, bool) for o in off) and 0 <= off[0] <= off[1]):
            return False, f"tensor {name!r} has bad data_offsets"
        per = ST_BYTES.get(t["dtype"])
        if per is not None:
            count = 1
            for d in shape:
                count *= d
            if count * per != off[1] - off[0]:
                return False, f"tensor {name!r} size does not match its dtype and shape"
        spans.append((off[0], off[1], name))
    spans.sort()
    pos = 0
    for b, e, name in spans:
        if b != pos:
            return False, f"tensor {name!r} leaves a gap or overlaps at byte {b}"
        pos = e
    if pos != size - 8 - n:
        return False, f"tensor data ends at {pos}, file has {size - 8 - n} data bytes"
    return True, f"{len(spans)} tensors"


def _global_ok(mod: str, name: str) -> bool:
    if (mod, name) in SAFE_GLOBALS:
        return True
    return mod == "torch" and (name.endswith("Storage") or name in SAFE_TORCH_NAMES)


MAX_PICKLE_BYTES = 512 * 1024 * 1024   # most of a file, or of a zip entry, that is read as pickle data
MAX_SEQUENTIAL_PICKLES = 5             # an older torch file holds this many pickles one after another


class _TooBig(Exception):
    pass


class _Inert:
    """Stands in for every global a pickle asks for. It accepts whatever the pickle machine does to
    an object (call it, set its state, append to it) and does nothing, so no real code runs."""

    def __new__(cls, *args, **kwargs):
        return object.__new__(cls)

    def __init__(self, *args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        return _Inert()

    def __setstate__(self, state):
        pass

    def __setitem__(self, key, value):
        pass

    def append(self, *args):
        pass

    def extend(self, *args):
        pass

    def add(self, *args):
        pass

    def update(self, *args, **kwargs):
        pass


class _Seen:
    def __init__(self):
        self.imports: set[tuple[str, str]] = set()
        self.bad: set[tuple[str, str]] = set()


def _unpickler(f, seen: _Seen) -> pickle.Unpickler:
    class Restricted(pickle.Unpickler):
        def find_class(self, module, name):  # every import the pickle machine can make comes through here
            seen.imports.add((str(module), str(name)))
            if not _global_ok(str(module), str(name)):
                seen.bad.add((str(module), str(name)))
            return _Inert

        def persistent_load(self, pid):
            return _Inert()

    return Restricted(f, fix_imports=False, encoding="latin1", errors="replace")


class _Capped:
    """Reads from a file object but never more than `left` bytes in all."""

    def __init__(self, f, left: int = MAX_PICKLE_BYTES):
        self.f, self.left = f, left

    def _ask(self, n) -> int:
        """How many bytes to request. A request for no particular amount gets one byte more than
        the cap allows, so that running into the cap is noticed."""
        if n is None or n < 0:
            return self.left + 1
        if n > self.left:
            raise _TooBig
        return n

    def _took(self, data: bytes) -> bytes:
        if len(data) > self.left:
            raise _TooBig
        self.left -= len(data)
        return data

    def read(self, n=-1):
        return self._took(self.f.read(self._ask(n)))

    def readline(self, n=-1):
        return self._took(self.f.readline(self._ask(n)))

    def readinto(self, buf):
        data = self._took(self.f.read(self._ask(len(buf))))
        buf[:len(data)] = data
        return len(data)


def _scan_stream(f, seen: _Seen, *, sequential: bool) -> None:
    """Run the restricted unpickler over what a loader would read from `f`. The first pickle must
    be readable. Later ones (older torch files) are scanned while they parse; once something that
    is not a pickle follows, the rest is tensor data. Names noticed before a failure still count."""
    reader = _Capped(f)
    for count in range(MAX_SEQUENTIAL_PICKLES if sequential else 1):
        try:
            _unpickler(reader, seen).load()
        except _TooBig:
            raise
        except EOFError:
            if count == 0:
                raise
            return
        except Exception:  # noqa: BLE001  (a malformed pickle can raise nearly anything)
            if count == 0:
                raise
            return


def scan_pickle(path: Path) -> tuple[bool, str]:
    seen = _Seen()
    try:
        with open(path, "rb") as probe:
            head = probe.read(4)
        if zipfile.is_zipfile(path):
            if head[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
                return False, "ambiguous: a zip archive that does not start like one, so loaders may read it as something else"
            with zipfile.ZipFile(path) as zf:
                infos = zf.infolist()
                names = [i.filename for i in infos]
                if len(set(names)) != len(names):
                    return False, "zip archive has two entries with the same name"
                pkls = [i for i in infos if i.filename.endswith(".pkl")]
                if not pkls:
                    return False, "zip archive holds no pickle to check"
                for info in pkls:
                    if info.file_size > MAX_PICKLE_BYTES:
                        return False, f"pickle {info.filename!r} is larger than the {MAX_PICKLE_BYTES} byte scan limit"
                    with zf.open(info) as f:
                        _scan_stream(f, seen, sequential=False)
        else:
            with open(path, "rb") as f:
                _scan_stream(f, seen, sequential=True)
    except _TooBig:
        return False, f"more than {MAX_PICKLE_BYTES} bytes of pickle data; not scanned"
    except Exception as e:  # noqa: BLE001
        return False, f"cannot read as a pickle: {type(e).__name__}"
    bad = sorted(f"{m}.{n}" for m, n in seen.bad)
    if bad:
        return False, "asks the loader to import: " + ", ".join(bad[:6])
    return True, f"{len(seen.imports)} known tensor rebuild imports"


def scan_gguf(path: Path) -> tuple[bool, str]:
    with open(path, "rb") as f:
        head = f.read(8)
    if len(head) < 8 or head[:4] != b"GGUF":
        return False, "missing GGUF magic"
    version = struct.unpack("<I", head[4:8])[0]
    return (version in (1, 2, 3)), f"version {version} (magic and version only)"


def scan_file(path: Path, filename: str) -> tuple[bool, str, str] | None:
    """(ok, detail, tool) or None when this code has no scan for that kind of file."""
    low = filename.lower()
    if low.endswith(".safetensors"):
        return (*scan_safetensors(path), TOOL_ST)
    if low.endswith(PICKLE_EXT):
        return (*scan_pickle(path), TOOL_PICKLE)
    if low.endswith(".gguf"):
        return (*scan_gguf(path), TOOL_GGUF)
    return None


def attest_file_events(secret: bytes, path: Path, sha256: str, filenames: list[str], created_at: int | None = None) -> list[dict]:
    """hash_verified for the bytes at `path`, and format_scan if the bytes are what they should be
    and some file name gives a format this code can scan."""
    ok, detail = hash_check(path, sha256)
    out = [E.build_attestation(secret, "hash_verified", "x", sha256, ok=ok, detail=detail, tool=TOOL_HASH, created_at=created_at)]
    if not ok:
        return out  # the bytes are not what the name says, so a scan of them means nothing
    for name in filenames:
        r = scan_file(path, name)
        if r:
            out.append(E.build_attestation(secret, "format_scan", "x", sha256, ok=r[0], detail=r[1], tool=r[2], created_at=created_at))
            break
    return out


def replicate_event(secret: bytes, att_event: dict, path: Path, filenames: list[str], created_at: int | None = None) -> dict | None:
    """Redo someone's hash_verified or format_scan on the bytes at `path` and say whether the
    answer matches. None if it cannot be redone (not that kind of attestation, or no scan)."""
    try:
        att = E.parse_event(att_event)
    except E.EventInvalid:
        return None
    if not isinstance(att, E.Attestation) or att.claim not in ("hash_verified", "format_scan") or att.subject_kind != "x":
        return None
    if att.claim == "hash_verified":
        mine, detail, tool = (*hash_check(path, att.subject), TOOL_HASH)
    else:
        res = None
        for name in filenames:
            res = scan_file(path, name)
            if res:
                break
        if res is None:
            return None
        mine, detail, tool = res
    return E.build_attestation(secret, "replication", "e", att.id, match=(mine == att.ok),
                               detail=f"I get ok={mine}; they said ok={att.ok}. {detail}", tool=tool, created_at=created_at)


class Verifier:
    """Signs hash_verified and format_scan attestations for blobs held in a store, and
    replications of other people's attestations."""

    def __init__(self, secret: bytes, store: Store):
        self.secret = secret
        self.store = store

    def attest_blob(self, sha256: str, created_at: int | None = None) -> list[dict]:
        if not self.store.blob_complete(sha256):
            return []
        return attest_file_events(self.secret, self.store.blob_path(sha256), sha256, self.store.names_for_blob(sha256), created_at)

    def replicate(self, att_event: dict, created_at: int | None = None) -> dict | None:
        x = att_event.get("tags") and next((t[1] for t in att_event["tags"] if len(t) >= 2 and t[0] == "x"), None)
        if not x or not self.store.blob_complete(x):
            return None
        return replicate_event(self.secret, att_event, self.store.blob_path(x), self.store.names_for_blob(x), created_at)
