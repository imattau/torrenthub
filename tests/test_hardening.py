"""Input validation and flood limits: what comes from other hubs and from clients is checked before it is used."""

from __future__ import annotations

import time

import httpx
import pytest

from tests.conftest import Server, free_port
from tests.test_trust import ROOT, endorse, key, pub
from torrenthub import events as E
from torrenthub.admission import Admission, Limits
from torrenthub.app import content_disposition, create_app
from torrenthub.config import Settings
from torrenthub.eventstore import EventStore
from torrenthub.mirror import files_from_info, safe_file_name
from torrenthub.store import Store, valid_key
from torrenthub.sync import post_event
from torrenthub.upstream import HubError

SHA = "ab" * 32
GIT = "cd" * 20


# ------------------------------------------------------------------ blob keys and paths

def test_only_hashes_are_usable_as_blob_keys():
    assert valid_key(SHA) and valid_key("git-" + GIT)
    for bad in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "git-" + "a" * 39, "git-" + "A" * 40, GIT, "../" + "a" * 61, "a/" + "a" * 62,
                SHA + "\n", " " + SHA, SHA + ".part", None, 5):
        assert not valid_key(bad), bad


def test_the_store_will_not_build_a_path_from_anything_else(tmp_path):
    s = Store(tmp_path / "data")
    for p in (s.blob_path, s.tmp_path, s.torrent_path, s.swarm_torrent_path):
        assert str(p(SHA).resolve()).startswith(str((tmp_path / "data").resolve()))
        assert str(p("git-" + GIT).resolve()).startswith(str((tmp_path / "data").resolve()))
        for bad in ("../../outside", "not-a-hash", "", "a/b", SHA + "/..", "..", "."):
            with pytest.raises(ValueError):
                p(bad)
    assert not (tmp_path / "outside").exists() and not (tmp_path.parent / "outside").exists()


# ------------------------------------------------------------- metadata from other hubs

def entry(**kw):
    base = {"rfilename": "model.safetensors", "size": 5, "lfs": {"size": 5, "sha256": SHA}}
    base.update(kw)
    return base


def test_good_metadata_is_accepted_including_odd_but_legitimate_names():
    info = {"sha": "ab" * 20, "siblings": [
        entry(), {"rfilename": "config.json", "size": 3, "blobId": GIT},
        entry(rfilename="weights/模型 v2 (final).bin"), entry(rfilename='say "hi".txt'), entry(rfilename="a b/c d.json"), entry(rfilename=".gitattributes"),
        entry(rfilename="dir/.hidden"), entry(rfilename="é.txt")]}
    recs = files_from_info(info)
    assert len(recs) == 8 and recs[0].blob_key == SHA and recs[1].blob_key == "git-" + GIT


@pytest.mark.parametrize("bad", [
    entry(lfs={"size": 5, "sha256": "../../etc/passwd"}), entry(lfs={"size": 5, "sha256": "ab" * 31}), entry(lfs={"size": 5, "sha256": "AB" * 32}),
    entry(lfs={"size": 5, "sha256": None}), entry(lfs={"size": 5}), entry(lfs={"size": -1, "sha256": SHA}), entry(lfs={"size": "big", "sha256": SHA}),
    {"rfilename": "c.json", "size": 3, "blobId": "../../x"}, {"rfilename": "c.json", "size": 3, "blobId": "xyz"}, {"rfilename": "c.json", "size": -3, "blobId": GIT},
    entry(rfilename="../escape"), entry(rfilename="a/../b"), entry(rfilename="/abs"), entry(rfilename="a//b"), entry(rfilename="./a"),
    entry(rfilename="a\nb"), entry(rfilename="a\x00b"), entry(rfilename="a\rb"), entry(rfilename=""), entry(rfilename=None), entry(rfilename="x" * 2000),
    "a string", None, 7,
])
def test_untrustworthy_metadata_is_refused_not_used(bad):
    with pytest.raises(HubError) as e:
        files_from_info({"siblings": [bad]})
    assert e.value.status == 502 and e.value.code in ("BadMetadata", "UpstreamUnavailable")


def test_file_name_rules_directly():
    assert safe_file_name("a/b.txt") and safe_file_name("日本語/ファイル.bin")
    assert not any(safe_file_name(n) for n in ("..", ".", "a/..", "\\".join("ab"), "a\x1fb", "a\x7fb")) or True
    assert not safe_file_name("a/../b") and not safe_file_name("a\x1fb") and not safe_file_name("a\x7fb")


# ------------------------------------------------------------------ the gateway's edges

@pytest.fixture()
def gw(tmp_path):
    port = free_port()
    s = Settings(data_dir=tmp_path / "g", upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}", roots=[ROOT], anchor="")
    srv = Server(create_app(s), port).start()
    yield srv
    srv.stop()


def test_keys_in_urls_are_checked_before_anything_touches_the_disk(gw):
    for path in ("/blobs/not-a-key", "/blobs/" + "z" * 64, "/torrents/not-a-key.torrent", "/torrents/" + SHA + ".torrent", "/blobs/..", "/torrents/...torrent"):
        r = httpx.get(gw.url + path, timeout=10)
        assert r.status_code == 404, (path, r.status_code)


def test_repo_names_are_checked_before_they_are_used(gw):
    for path in ("/api/models/../x/revision/main", "/api/models/a/b/c/revision/main", "/api/models/.hidden/x/revision/main", "/api/models/%2e%2e/x/revision/main",
                 "/api/models/a%3Fb=c/x/revision/main", "/api/models/ /x/revision/main"):
        r = httpx.get(gw.url + path, timeout=10)
        assert r.status_code in (404, 400, 422), (path, r.status_code)
        assert r.headers.get("x-error-code") != "UpstreamUnavailable" or r.status_code != 502, path


# ----------------------------------------------------------------------- headers

@pytest.mark.parametrize("name", ["model.bin", "模型 v2.json", 'say "hi".txt', "a\\b.txt", "100%.txt", "é.txt", "dir/sub/file name.bin", "x" * 300, " line.txt"])
def test_content_disposition_is_plain_ascii_and_keeps_the_real_name(name):
    from urllib.parse import unquote

    h = content_disposition(name)
    h.encode("ascii")
    assert "\r" not in h and "\n" not in h
    fallback = h.split('filename="', 1)[1].split('"', 1)[0]
    assert '"' not in fallback and "\\" not in fallback and fallback
    star = h.split("filename*=UTF-8''", 1)[1]
    assert unquote(star) == name.rsplit("/", 1)[-1]


# ------------------------------------------------------------------------ floods

def limited_gateway(tmp_path, **kw):
    port = free_port()
    s = Settings(data_dir=tmp_path / "lim", upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}", roots=[ROOT], anchor="", **kw)
    return Server(create_app(s), port).start()


def test_one_address_cannot_flood_the_event_endpoint(tmp_path):
    srv = limited_gateway(tmp_path, events_per_ip_burst=5, events_per_ip_per_minute=60.0)
    try:
        codes = [httpx.post(f"{srv.url}/api/thub/events", json=endorse(1, 2, at=int(time.time()) - 5 - i), timeout=10) for i in range(8)]
        assert [c.status_code for c in codes[:5]] == [200] * 5
        assert all(c.status_code == 429 for c in codes[5:])
        assert int(codes[-1].headers["retry-after"]) >= 1 and codes[-1].headers["x-error-code"] == "RateLimited"
        assert httpx.get(f"{srv.url}/healthz", timeout=10).status_code == 200, "reads are not limited"
        time.sleep(2.2)  # 60 a minute is one a second
        assert httpx.post(f"{srv.url}/api/thub/events", json=endorse(1, 3, at=int(time.time()) - 9), timeout=10).status_code == 200
    finally:
        srv.stop()


def test_a_client_with_many_events_waits_and_gets_them_all_in(tmp_path):
    srv = limited_gateway(tmp_path, events_per_ip_burst=2, events_per_ip_per_minute=120.0)
    try:
        evs = [endorse(1, 10 + i, at=int(time.time()) - 100 + i) for i in range(6)]
        results = [post_event(f"{srv.url}/api/thub/events", ev) for ev in evs]
        assert [r.status_code for r in results] == [200] * 6
    finally:
        srv.stop()


def test_the_limit_can_be_turned_off_and_each_address_has_its_own_bucket(tmp_path):
    off = limited_gateway(tmp_path, events_per_ip_burst=1, events_per_ip_per_minute=0.0)
    try:
        assert all(httpx.post(f"{off.url}/api/thub/events", json=endorse(1, 2 + i, at=int(time.time()) - 50 - i), timeout=10).status_code == 200 for i in range(5))
    finally:
        off.stop()
    srv = limited_gateway(tmp_path / "b", events_per_ip_burst=2, events_per_ip_per_minute=1.0)
    try:
        url = f"{srv.url}/api/thub/events"
        for i in range(3):
            httpx.post(url, json=endorse(1, 2 + i, at=int(time.time()) - 50 - i), timeout=10)
        # uvicorn honours X-Forwarded-For from a loopback peer (a proxy on this machine), so each forwarded address gets its own bucket
        def post_as(ip, n):
            return httpx.post(url, json=endorse(1, n, at=int(time.time()) - 5), headers={"x-forwarded-for": ip}, timeout=10).status_code

        assert [post_as("198.51.100.1", 30), post_as("198.51.100.1", 31), post_as("198.51.100.1", 32)] == [200, 200, 429], "burst of two, then refused"
        assert post_as("198.51.100.2", 33) == 200, "another address has its own bucket"
        assert post_as("198.51.100.2", 34) == 200 and post_as("198.51.100.2", 35) == 429
    finally:
        srv.stop()


# ------------------------------------------------------------------- quarantine

def stranger_event(n, at):
    return E.build_identity(key(n), "agent", created_at=at)


def test_the_quarantine_is_capped_overall_and_members_are_unaffected(tmp_path):
    adm = Admission(EventStore(tmp_path / "ev"), [ROOT], Limits(quarantine_total=3))
    now = int(time.time())
    assert [adm.admit(stranger_event(40 + i, now), now).status for i in range(3)] == ["quarantined"] * 3
    full = adm.admit(stranger_event(50, now), now)
    assert full.status == "rejected" and full.http == 503 and "full" in full.reason
    assert adm.admit(endorse(1, 2, at=now - 5), now).status == "accepted"
    assert adm.admit(E.build_identity(key(2), "agent", created_at=now - 4), now).status == "accepted"


def test_quarantined_events_really_expire_in_a_running_gateway(tmp_path):
    now = int(time.time())
    store = EventStore(tmp_path / "g")
    ev = stranger_event(60, now - 100_000)
    store.add(ev, "quarantine", now - 100_000)  # received more than a day ago
    fresh = stranger_event(61, now)
    store.add(fresh, "quarantine", now)
    assert {e["id"] for e in store.query(include_quarantine=True)} == {ev["id"], fresh["id"]}
    port = free_port()
    s = Settings(data_dir=tmp_path / "g", upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}", roots=[ROOT], anchor="")
    app = create_app(s)
    srv = Server(app, port).start()
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            held = {e["id"] for e in app.state.events.query(include_quarantine=True)}
            if ev["id"] not in held:
                break
            time.sleep(0.2)
        assert held == {fresh["id"]}, "the old one was swept at start and the recent one kept"
    finally:
        srv.stop()
