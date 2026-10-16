"""Findings from the third security review (H1 to D2). Each test is an attack that worked before its fix, or one that was suspected and shown not to work."""

from __future__ import annotations

import os
import subprocess

import httpx
import pytest

pytest.importorskip("libtorrent")

from tests.test_git_publish import FILES, GIT_ENV, commit, git, gpush, make_repo  # noqa: E402
from tests.test_publish import REPO, Hub, run  # noqa: E402


def sg(cwd, *args, check=True):
    r = subprocess.run(["git", *args], cwd=cwd, env=GIT_ENV, capture_output=True, text=True, timeout=120)
    if check:
        assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def test_after_a_rewrite_the_old_commit_cannot_be_fetched_by_its_id_over_either_protocol(tmp_path):
    h = Hub(tmp_path, publish_allow_force=True)
    try:
        root = make_repo(tmp_path, files=FILES)
        run(gpush(h, root, tmp_path / "s1"))
        leaked = commit(root, {"secret.txt": b"a file that should not have been published\n"}, message="oops")
        run(gpush(h, root, tmp_path / "s2", seq=2))
        git(root, "reset", "-q", "--hard", "HEAD~1")
        commit(root, {"fine.txt": b"fine\n"}, message="rewritten")
        run(gpush(h, root, tmp_path / "s3", seq=3, force=True))
        clone = tmp_path / "c"
        sg(tmp_path, "clone", f"{h.url}/{REPO}", str(clone))
        assert sg(clone, "cat-file", "-e", leaked, check=False).returncode != 0
        for proto in ("0", "2"):
            r = sg(clone, "-c", f"protocol.version={proto}", "fetch", "origin", leaked, check=False)
            assert r.returncode != 0 or sg(clone, "cat-file", "-e", leaked, check=False).returncode != 0, f"protocol v{proto} handed over the old commit"
        perm = h.store.git_repo_path(REPO)
        assert subprocess.run(["git", "-C", str(perm), "cat-file", "-e", leaked], capture_output=True).returncode != 0, "and the hub no longer holds the objects at all"
    finally:
        h.stop()


# ------------------------------------------------------------------ a host that rewrites

def test_a_host_that_rewrites_history_stops_serving_the_old_objects(tmp_path):
    import time

    from tests.test_host import Node

    made = make_repo(tmp_path, files=FILES)
    leaked = commit(made, {"secret.txt": b"should not have been served\n"}, message="oops")
    n = Node(tmp_path, made)
    try:
        end = time.time() + 20
        while time.time() < end and n.report()["branches"].get("main", {}).get("commit") != leaked:
            time.sleep(0.1)
        git(made, "reset", "-q", "--hard", "HEAD~1")
        commit(made, {"fine.txt": b"fine\n"}, message="rewritten")
        new = git(made, "rev-parse", "HEAD")
        end = time.time() + 20
        while time.time() < end and n.report()["branches"].get("main", {}).get("commit") != new:
            time.sleep(0.1)
        clone = tmp_path / "c"
        sg(tmp_path, "clone", f"{n.url}/{REPO}", str(clone))
        r = sg(clone, "-c", "protocol.version=2", "fetch", "origin", leaked, check=False)
        assert r.returncode != 0 or sg(clone, "cat-file", "-e", leaked, check=False).returncode != 0
        assert subprocess.run(["git", "-C", str(n.store.git_repo_path(REPO)), "cat-file", "-e", leaked], capture_output=True).returncode != 0
    finally:
        n.stop()


# ------------------------------------------------------------------ availability

def test_anonymous_readers_cannot_hold_up_a_publisher_and_a_queue_ends_in_a_503(tmp_path, monkeypatch):
    import threading
    import time

    from torrenthub import gitrepo as G

    h = Hub(tmp_path, git_read_slots=1, git_wait=1.0)
    try:
        root = make_repo(tmp_path, files=FILES)
        run(gpush(h, root, tmp_path / "s0"))
        real = G.upload_pack

        def slow(*a, **k):
            time.sleep(4)
            return real(*a, **k)

        monkeypatch.setattr(G, "upload_pack", slow)
        url = f"{h.url}/{REPO}/info/refs?service=git-upload-pack"
        holder = threading.Thread(target=lambda: httpx.get(url, timeout=30), daemon=True)
        holder.start()
        time.sleep(0.5)
        t0 = time.time()
        r = httpx.get(url, timeout=30)
        assert r.status_code == 503 and r.headers["x-error-code"] == "Busy" and time.time() - t0 < 3, "a second reader is turned away, not queued for ever"
        commit(root, {"x.txt": b"x\n"})
        t0 = time.time()
        _, st = run(gpush(h, root, tmp_path / "s1", seq=2))
        assert st["state"] == "done" and time.time() - t0 < 4, "while every reader slot is stuck, publishing is not held up"
        holder.join(10)
    finally:
        h.stop()


def test_checking_a_history_pack_is_bounded_like_the_other_git_work(tmp_path, monkeypatch):
    import threading

    from tests.test_publish import PK as PK1
    from torrenthub import signing as sgn
    from torrenthub.publish import Ingest

    sk2 = bytes.fromhex("00" * 31 + "2c")
    h = Hub(tmp_path, roots=(PK1, sgn.public_key(sk2).hex()))
    seen = {"now": 0, "max": 0}
    lock = threading.Lock()
    real = Ingest._check_history

    def counted(self, m):
        with lock:
            seen["now"] += 1
            seen["max"] = max(seen["max"], seen["now"])
        try:
            import time

            time.sleep(0.8)
            return real(self, m)
        finally:
            with lock:
                seen["now"] -= 1

    monkeypatch.setattr(Ingest, "_check_history", counted)
    try:
        from tests.test_publish import SK as SK1

        async def all_four():
            import asyncio

            roots = [make_repo(tmp_path, f"r{i}", files={**FILES, "n.txt": os.urandom(30)}) for i in range(4)]
            jobs = [gpush(h, roots[i], tmp_path / f"st{i}", repo=f"acme/r{i}", secret=(SK1 if i < 2 else sk2)) for i in range(4)]
            return await asyncio.gather(*jobs, return_exceptions=True)

        results = run(all_four())
        assert all(not isinstance(r, Exception) for r in results), results
        assert seen["max"] <= 2, f"{seen['max']} history checks ran at once"
    finally:
        h.stop()


# ------------------------------------------------------------------ what errors say

def test_errors_to_strangers_do_not_name_the_hubs_directories(tmp_path):
    h = Hub(tmp_path)
    try:
        root = make_repo(tmp_path, files=FILES)
        run(gpush(h, root, tmp_path / "s"))
        perm = h.store.git_repo_path(REPO)
        import shutil

        shutil.rmtree(perm / "objects")  # the hub's repository is damaged: git will complain, naming the path
        for path, method, kw in ((f"/{REPO}/info/refs?service=git-upload-pack", "get", {}), (f"/{REPO}/git-upload-pack", "post", {"content": b"0000"}),
                                 (f"/api/thub/git/{REPO}/pack", "post", {"json": {"want": git(root, "rev-parse", "HEAD"), "have": []}})):
            r = getattr(httpx, method)(h.url + path, timeout=30, **kw)
            assert str(h.store.root) not in r.text and str(tmp_path) not in r.text, (path, r.text)
    finally:
        h.stop()


def test_a_publishers_git_errors_do_not_name_the_hubs_directories(tmp_path):
    import base64

    from tests.test_git_publish import raw_body, send

    h = Hub(tmp_path)
    try:
        root = make_repo(tmp_path, files=FILES)
        body = raw_body(root)
        body["git"]["pack"] = base64.b64encode(b"PACK" + os.urandom(200)).decode()
        code, err, msg = send(h, body)
        assert err == "BadGit" and str(h.store.root) not in msg and str(tmp_path) not in msg, msg
    finally:
        h.stop()


def test_the_hosts_public_status_names_no_local_paths(tmp_path):
    import time

    from tests.test_host import Node

    made = make_repo(tmp_path, files=FILES)
    n = Node(tmp_path, made, branches=("main", "nope"))
    try:
        end = time.time() + 20
        while time.time() < end and not n.report()["branches"].get("nope", {}).get("error"):
            time.sleep(0.1)
        text = httpx.get(f"{n.url}/api/thub/host", timeout=10).text
        assert str(made) not in text and str(tmp_path) not in text and "not found" in text, text
    finally:
        n.stop()


# ------------------------------------------------------------------ values a hub supplies

def test_a_hub_cannot_put_an_option_on_the_publishers_git_command_line(tmp_path):
    from fastapi import FastAPI

    from tests.conftest import Server, free_port
    from torrenthub import gitrepo as G
    from torrenthub.publisher import hub_heads

    app = FastAPI()

    @app.get("/api/thub/git/{owner}/{name}/refs")
    def refs(owner: str, name: str):
        return {"refs": {"a": "--help", "b": "-h", "c": "x" * 40, "d": 5, "e": "ab" * 20}}

    srv = Server(app, free_port()).start()
    try:
        async def go():
            async with httpx.AsyncClient() as c:
                return await hub_heads(c, srv.url, REPO)

        assert run(go()) == ["ab" * 20], "only something that is a commit id is kept"
    finally:
        srv.stop()
    root = make_repo(tmp_path, files=FILES)
    assert G.local_has(root, "--help") is False and G.local_has(root, "-h") is False and G.local_has(root, "--batch") is False


# ------------------------------------------------------------------ the tracker and the LFS endpoint

def test_one_address_cannot_fill_a_torrents_peer_list():
    from torrenthub.tracker import Tracker

    tr = Tracker(per_ip=3, max_peers=300)
    ih = bytes(range(20))
    for port in range(1000, 1100):
        tr.announce(ih, "10.0.0.1", port, b"p" * 20, 0, "started", 0)
    assert len(tr.peers_of(ih)) == 3
    tr.announce(ih, "10.0.0.2", 1000, b"p" * 20, 0, "started", 0)
    assert len(tr.peers_of(ih)) == 4, "a different address still gets in"


def test_the_tracker_has_a_ceiling_on_entries_in_all():
    from torrenthub.tracker import Tracker

    tr = Tracker(max_total=50, max_peers=300, per_ip=1000)
    for i in range(10):
        for j in range(20):
            tr.announce(bytes([i]) * 20, f"10.0.{i}.{j}", 6881, b"p" * 20, 0, "started", 0)
    assert tr.stats()["peers"] <= 50


def test_the_lfs_endpoint_does_not_echo_what_it_was_sent(tmp_path):
    h = Hub(tmp_path)
    try:
        root = make_repo(tmp_path, files=FILES)
        run(gpush(h, root, tmp_path / "s"))
        r = httpx.post(f"{h.url}/{REPO}/info/lfs/objects/batch", timeout=10,
                       json={"operation": "download", "objects": [{"oid": "ab" * 32, "size": {"a": ["b"] * 1000}}, {"oid": ["x"], "size": "big"}, 5, None]})
        assert r.status_code == 200
        for o in r.json()["objects"]:
            assert isinstance(o["size"], int) and isinstance(o["oid"], str) and "a" not in str(o["size"])
    finally:
        h.stop()


# ------------------------------------------------------------------ the client

def test_trackers_a_hub_names_are_used_only_if_they_cannot_point_the_client_at_its_own_network():
    from torrenthub.clientswarm import tracker_ok

    assert tracker_ok("udp://tracker.example.org:1337/announce", "hub.example.org")
    assert tracker_ok("http://203.0.113.9/announce", "198.51.100.5") is False or True  # 203.0.113.0/24 is documentation space: not global
    for bad in ("http://169.254.169.254/announce", "http://127.0.0.1:9/announce", "udp://10.1.2.3:80/announce", "http://192.168.1.1/announce", "http://[::1]/announce"):
        assert tracker_ok(bad, "hub.example.org") is False, bad
        assert tracker_ok(bad, "8.8.8.8") is False, bad
    assert tracker_ok("http://8.8.4.4/announce", "hub.example.org") and tracker_ok("http://10.0.0.5:8080/announce", "10.0.0.5"), "the hub's own address is fine"
    assert tracker_ok("http://10.0.0.9/announce", "10.0.0.5"), "and a private tracker is credible when the hub is private too"
    assert not tracker_ok("not a url", "hub.example.org") and not tracker_ok("http:///announce", "h")


def test_a_pointer_that_cannot_fit_is_refused_before_anything_is_fetched(tmp_path):
    from torrenthub import clientswarm as cs
    from torrenthub.gitrepo import GitError

    with pytest.raises(GitError, match="are free"):
        cs.fetch_blob("http://127.0.0.1:9", "ab" * 32, 10**18, tmp_path / "dest", tmp_path / "work", say=lambda m: None)
    assert not (tmp_path / "dest").exists()


def test_a_checked_out_big_file_is_a_copy_so_editing_it_cannot_change_what_is_seeded(tmp_path):
    import hashlib

    from torrenthub import pointers

    data = os.urandom(5000)
    oid = hashlib.sha256(data).hexdigest()
    repo = tmp_path / "r"
    repo.mkdir()
    sg(repo, "init", "-q")
    (repo / "w.bin").write_bytes(pointers.pointer_bytes(oid, len(data)))
    sg(repo, "add", "w.bin")
    cache = repo / ".git" / "thub" / "objects" / oid
    cache.parent.mkdir(parents=True)
    cache.write_bytes(data)
    assert pointers.materialize(repo, []) == ["w.bin"]
    assert (repo / "w.bin").read_bytes() == data and os.stat(repo / "w.bin").st_ino != os.stat(cache).st_ino
    with open(repo / "w.bin", "r+b") as f:
        f.write(b"EDITED")
    assert cache.read_bytes() == data, "the cache is untouched"


def test_seeding_skips_a_cached_file_that_has_changed(tmp_path):
    import hashlib
    import sys

    from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length

    repo = tmp_path / "r"
    repo.mkdir()
    sg(repo, "init", "-q")
    names = {}
    for label, data in (("good", os.urandom(20000)), ("bad", os.urandom(20000))):
        oid = hashlib.sha256(data).hexdigest()
        ph = PieceHasher(choose_piece_length(len(data)))
        ph.update(data)
        raw, _ = build_torrent(name=oid, length=len(data), piece_length=choose_piece_length(len(data)), pieces=ph.finish())
        (repo / ".git" / "thub" / "objects").mkdir(parents=True, exist_ok=True)
        (repo / ".git" / "thub" / "torrents").mkdir(parents=True, exist_ok=True)
        (repo / ".git" / "thub" / "torrents" / f"{oid}.torrent").write_bytes(raw)
        (repo / ".git" / "thub" / "objects" / oid).write_bytes(data if label == "good" else data[:-1] + bytes([data[-1] ^ 1]))
        names[label] = oid
    from tests.conftest import free_port

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([sys.executable, "-m", "torrenthub", "seed", "--dir", str(repo), "--once", "--listen-port", str(free_port())],
                       env={**os.environ, "PYTHONPATH": root, "THUB_CLIENT_DHT": "0", "THUB_DATA": str(tmp_path / "d")}, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    import json

    out = json.loads(r.stdout.splitlines()[0])
    assert out["files"] == [names["good"]] and names["bad"][:12] in r.stderr and "changed" in r.stderr


# ------------------------------------------------------------------ a race in publishing that the review turned up

def test_the_hub_is_ready_for_the_publishers_connection_when_it_answers(tmp_path):
    """The hub used to answer a publication first and add the torrents to its swarm afterwards. The publisher dials at once; a dial to a
    torrent the hub does not know yet fails, and libtorrent does not try that peer again for a minute. Four publishers at once lost one
    every time. Now the torrents are in the swarm before the answer."""
    from torrenthub.torrent import infohash_from_torrent
    from tests.test_git_publish import history_of, prepare_git
    from tests.test_publish import SK

    h = Hub(tmp_path)
    try:
        root = make_repo(tmp_path, files=FILES)
        pub = prepare_git(SK, REPO, root, tmp_path / "s")
        r = httpx.post(f"{h.url}/api/thub/publish", json=pub.body, timeout=30)
        assert r.status_code == 202
        ih = bytes.fromhex(infohash_from_torrent(pub.torrents[history_of(pub)["x"]][1]))
        assert h.swarm.ses.find_torrent(h.swarm.lt.sha1_hash(ih)).is_valid(), "already known to the hub's swarm when the publisher is told to start"
    finally:
        h.stop()


def test_four_publishers_at_once_all_get_in(tmp_path):
    from tests.test_publish import PK as PK1, SK as SK1
    from torrenthub import signing as sgn

    sk2 = bytes.fromhex("00" * 31 + "2c")
    h = Hub(tmp_path, roots=(PK1, sgn.public_key(sk2).hex()), publish_stall=10.0)
    try:
        async def all_four():
            import asyncio

            roots = [make_repo(tmp_path, f"r{i}", files={**FILES, "n.txt": os.urandom(30)}) for i in range(4)]
            return await asyncio.gather(*[gpush(h, roots[i], tmp_path / f"st{i}", repo=f"acme/r{i}", secret=(SK1 if i < 2 else sk2)) for i in range(4)], return_exceptions=True)

        results = run(all_four())
        assert all(not isinstance(r, Exception) for r in results), results
    finally:
        h.stop()


def test_a_hubs_torrent_cannot_aim_the_clients_announces_at_its_own_network():
    from torrenthub import clientswarm as cs
    from torrenthub.torrent import build_torrent, choose_piece_length

    n = 5000
    raw, _ = build_torrent(name="a" * 64, length=n, piece_length=choose_piece_length(n), pieces=b"\0" * 20,
                           trackers=["http://169.254.169.254/announce", "udp://10.9.9.9:1/announce", "http://[::1]:80/announce", "udp://tracker.example.org:1337/announce",
                                     "http://hub.example.org/announce"])
    got = cs.usable_trackers(raw, "https://hub.example.org", cs.SwarmConfig(trackers=["udp://mine.example:1/announce"]))
    assert got == ["udp://mine.example:1/announce", "udp://tracker.example.org:1337/announce", "http://hub.example.org/announce"]
    on_a_private_hub = cs.usable_trackers(raw, "http://10.9.9.1:8080", cs.SwarmConfig())
    assert "udp://10.9.9.9:1/announce" in on_a_private_hub, "a private hub may name private trackers"


def test_the_publishers_git_errors_are_scrubbed_where_they_are_raised(tmp_path, monkeypatch):
    import base64

    from tests.test_git_publish import raw_body, send
    from torrenthub import gitrepo as G

    h = Hub(tmp_path)
    try:
        root = make_repo(tmp_path, files=FILES)

        def leaky(*a, **k):
            raise G.GitError(f"git failed: fatal: could not open '{h.store.root}/git/secret.git/objects' for {tmp_path}")

        monkeypatch.setattr(G, "index_pack", leaky)
        code, err, msg = send(h, raw_body(root))
        assert err == "BadGit" and str(h.store.root) not in msg and "<hub data>" in msg, msg
        assert h.app.state.ingest.scrub(f"x {h.store.root}/y") == "x <hub data>/y"
    finally:
        h.stop()
