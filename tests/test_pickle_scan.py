"""The pickle scanner runs the real unpickler with every import routed to one function, so the
machine's own bookkeeping decides what is imported. These tests use ordinary pickles of harmless
classes: what matters is which names are reported and that nothing is ever imported or called."""

from __future__ import annotations

import os
import pickle
import sys
import types
import warnings
import zipfile
from collections import OrderedDict

import pytest

from torrenthub import verifier as V

PROTOCOLS = range(0, pickle.HIGHEST_PROTOCOL + 1)


class Marker:
    """A harmless class outside the allowlist. Its module is removed before scanning."""

    calls: list = []

    def __init__(self, *a):
        Marker.calls.append("init")

    def __reduce__(self):
        return (_build_marker, ())


def _build_marker():
    Marker.calls.append("built")
    return Marker()


def marker_pickle(proto=4) -> bytes:
    mod = types.ModuleType("thub_scan_probe")
    mod.Thing = type("Thing", (), {"__module__": "thub_scan_probe", "__reduce__": lambda self: (mod.Thing, ())})
    sys.modules["thub_scan_probe"] = mod
    try:
        return pickle.dumps(OrderedDict(a=mod.Thing()), protocol=proto)
    finally:
        del sys.modules["thub_scan_probe"]


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_plain_data_passes_under_every_protocol(tmp_path, proto):
    p = tmp_path / "a.pkl"
    p.write_bytes(pickle.dumps(OrderedDict(a=1, b=[1, 2, {"c": (3, 4.5, None, "y")}], n=-(2 ** 70)), protocol=proto))
    ok, detail = V.scan_pickle(p)
    assert ok, detail


@pytest.mark.parametrize("proto", PROTOCOLS)
def test_an_import_outside_the_list_is_reported_by_name_and_never_made(tmp_path, proto):
    p = tmp_path / "t.pkl"
    p.write_bytes(marker_pickle(proto))
    assert "thub_scan_probe" not in sys.modules
    ok, detail = V.scan_pickle(p)
    assert not ok and "thub_scan_probe.Thing" in detail, detail
    assert "thub_scan_probe" not in sys.modules, "scanning must not import anything"


def test_nothing_the_pickle_names_is_called(tmp_path):
    p = tmp_path / "m.pkl"
    p.write_bytes(pickle.dumps(OrderedDict(m=Marker())))  # references this test module's Marker and _build_marker
    Marker.calls.clear()  # forget the construction the test itself just did
    ok, detail = V.scan_pickle(p)
    assert not ok and "_build_marker" in detail
    assert Marker.calls == [], "neither the class nor its reduce function ran"


def test_every_pickle_in_a_row_is_scanned_but_trailing_data_is_not_mistaken_for_one(tmp_path):
    good = pickle.dumps(OrderedDict(a=1), protocol=2)
    other = marker_pickle(2)
    (tmp_path / "ok.bin").write_bytes(good + good + good + os.urandom(5000))
    assert V.scan_pickle(tmp_path / "ok.bin")[0], "tensor data after the pickles is data"
    (tmp_path / "second.bin").write_bytes(good + other + os.urandom(100))
    ok, detail = V.scan_pickle(tmp_path / "second.bin")
    assert not ok and "thub_scan_probe.Thing" in detail, "a later pickle is read too"
    (tmp_path / "fifth.bin").write_bytes(good * 4 + other)
    assert not V.scan_pickle(tmp_path / "fifth.bin")[0], "up to five are read, the way an older torch file is loaded"
    (tmp_path / "sixth.bin").write_bytes(good * 5 + other)
    assert V.scan_pickle(tmp_path / "sixth.bin")[0], "past five a loader reads no more"


def test_bytes_under_old_protocols_are_an_import_and_are_reported_as_one(tmp_path):
    p = tmp_path / "b.pkl"
    p.write_bytes(pickle.dumps(OrderedDict(a=b"x"), protocol=2))
    ok, detail = V.scan_pickle(p)
    assert not ok and "_codecs.encode" in detail
    p.write_bytes(pickle.dumps(OrderedDict(a=b"x"), protocol=3))
    assert V.scan_pickle(p)[0]


def test_sets_are_reported_under_old_protocols_because_they_are_imports_there(tmp_path):
    p = tmp_path / "s.pkl"
    p.write_bytes(pickle.dumps({1, 2}, protocol=2))
    ok, detail = V.scan_pickle(p)
    assert not ok and "set" in detail
    p.write_bytes(pickle.dumps({1, 2}, protocol=4))
    assert V.scan_pickle(p)[0], "protocol 4 has a set opcode and needs no import"


def test_unreadable_files_fail_closed(tmp_path):
    for name, data in (("empty", b""), ("junk", os.urandom(300)), ("cut", pickle.dumps(OrderedDict(a=list(range(50))))[:-10]),
                       ("zeros", b"\0" * 100), ("text", b"hello there\n")):
        (tmp_path / f"{name}.pkl").write_bytes(data)
        ok, detail = V.scan_pickle(tmp_path / f"{name}.pkl")
        assert not ok and "cannot read" in detail, (name, detail)


def write_zip(path, entries):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about the duplicate names some tests use on purpose
        with zipfile.ZipFile(path, "w") as z:
            for name, data in entries:
                z.writestr(name, data)


def test_every_pickle_entry_of_a_zip_is_scanned(tmp_path):
    good = pickle.dumps(OrderedDict(a=1), protocol=2)
    write_zip(tmp_path / "two.pt", [("a/data.pkl", good), ("a/extra.pkl", marker_pickle(2)), ("a/data/0", b"\0" * 8)])
    ok, detail = V.scan_pickle(tmp_path / "two.pt")
    assert not ok and "thub_scan_probe.Thing" in detail


def test_a_zip_with_two_entries_of_one_name_is_refused(tmp_path):
    good = pickle.dumps(OrderedDict(a=1), protocol=2)
    write_zip(tmp_path / "dup.pt", [("a/data.pkl", good), ("a/data.pkl", good)])
    ok, detail = V.scan_pickle(tmp_path / "dup.pt")
    assert not ok and "same name" in detail


def test_a_zip_that_does_not_start_like_one_is_refused_as_ambiguous(tmp_path):
    good = pickle.dumps(OrderedDict(a=1), protocol=2)
    write_zip(tmp_path / "z.pt", [("a/data.pkl", good)])
    assert V.scan_pickle(tmp_path / "z.pt")[0]
    (tmp_path / "pre.pt").write_bytes(b"not a zip header " + (tmp_path / "z.pt").read_bytes())
    assert zipfile.is_zipfile(tmp_path / "pre.pt"), "zipfile itself accepts the prefix, which is the point"
    ok, detail = V.scan_pickle(tmp_path / "pre.pt")
    assert not ok and "ambiguous" in detail


def test_the_size_cap_is_enforced_and_counts_exactly(tmp_path, monkeypatch):
    data = pickle.dumps(OrderedDict(a="x" * 5000), protocol=2)
    p = tmp_path / "big.pkl"
    p.write_bytes(data)
    assert V.scan_pickle(p)[0]
    monkeypatch.setattr(V, "MAX_PICKLE_BYTES", len(data) - 1)
    # _Capped takes its default at definition time, so patch the reader's default the way scanning uses it
    monkeypatch.setattr(V._Capped, "__init__", lambda self, f, left=len(data) - 1: (setattr(self, "f", f), setattr(self, "left", left)) and None)
    ok, detail = V.scan_pickle(p)
    assert not ok and "not scanned" in detail
    monkeypatch.undo()
    z = tmp_path / "zbig.pt"
    write_zip(z, [("a/data.pkl", data)])
    monkeypatch.setattr(V, "MAX_PICKLE_BYTES", 100)
    ok, detail = V.scan_pickle(z)
    assert not ok and "scan limit" in detail


def test_capped_reader_semantics():
    import io

    r = V._Capped(io.BytesIO(b"abc\ndef\n"), left=8)
    assert r.read(3) == b"abc" and r.readline() == b"\n" and r.readline() == b"def\n" and r.left == 0
    with pytest.raises(V._TooBig):
        V._Capped(io.BytesIO(b"x" * 20), left=10).read(-1)
    with pytest.raises(V._TooBig):
        V._Capped(io.BytesIO(b"x" * 20), left=10).read(11)
    assert V._Capped(io.BytesIO(b"x" * 10), left=10).read(-1) == b"x" * 10, "exactly at the cap is fine"
    buf = bytearray(4)
    assert V._Capped(io.BytesIO(b"wxyz"), left=4).readinto(buf) == 4 and bytes(buf) == b"wxyz"


def test_the_tool_name_changed_with_the_method():
    assert V.TOOL_PICKLE.endswith("/2")
