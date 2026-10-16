"""Hosting a repo from a git repository on this machine (HOSTING.md, stage H2)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

import httpx
import pytest

pytest.importorskip("libtorrent")
if shutil.which("git") is None:
    pytest.skip("git is not installed", allow_module_level=True)

from huggingface_hub import snapshot_download  # noqa: E402

from tests.conftest import Server, free_port  # noqa: E402
from tests.test_git_publish import BIG, FILES, commit, git, make_repo, pointer  # noqa: E402
from tests.test_publish import PK, REPO, SK, agent_for, publisher_swarm, run  # noqa: E402
from torrenthub import gitrepo as G  # noqa: E402
from torrenthub.config import Settings  # noqa: E402
from torrenthub.host import Host, build_host_app  # noqa: E402
from torrenthub.manifest import build_manifest, verify_manifest  # noqa: E402
from torrenthub.swarm import LibtorrentSwarm  # noqa: E402
from torrenthub.torrent import sanitize_torrent  # noqa: E402

OID = hashlib.sha256(BIG).hexdigest()


class Node:
    """A host: the hub app with the watcher, on a loopback port."""

    def __init__(self, tmp_path, root, name="host", poll=0.2, branches=("main",), **kw):
        sp = free_port()
        self.swarm_port = sp
        self.swarm = LibtorrentSwarm(listen_port=sp, listen_host="127.0.0.1", dht=False)
        port = free_port()
        self.settings = Settings(data_dir=tmp_path / name, upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}", roots=[PK],
                                 anchor="", listen_port=sp, lazy_mirror=False, webseed_upstream=False)
        self.app, self.host = build_host_app(self.settings, swarm=self.swarm, repo=REPO, git_dir=root, secret=SK, branches=branches, poll=poll, **kw)
        self.srv = Server(self.app, port).start()
        self.url = self.srv.url
        self.store = self.app.state.store

    def stop(self):
        self.srv.stop()

    def report(self):
        return httpx.get(f"{self.url}/api/thub/host", timeout=10).json()


@pytest.fixture()
def made(tmp_path):
    return make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})


@pytest.fixture()
def node(tmp_path, made):
    n = Node(tmp_path, made)
    yield n
    n.stop()


def until(fn, timeout=20.0, what="the condition"):
    end = time.time() + timeout
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {what}")


def branch(n, name="main"):
    return n.report()["branches"].get(name, {})


def manifests(n):
    return httpx.get(f"{n.url}/api/thub/manifests/{REPO}", timeout=10).json()["events"]


# ------------------------------------------------------------------ serving a repo

def test_a_repo_in_a_git_directory_is_served_signed_and_verified(node, made, tmp_path):
    head = git(made, "rev-parse", "HEAD")
    assert branch(node)["commit"] == head, "the first pass ran before the first request"
    info = httpx.get(f"{node.url}/api/models/{REPO}/revision/main", timeout=10).json()
    assert info["sha"] == head
    local = snapshot_download(REPO, endpoint=node.url, cache_dir=str(tmp_path / "dl"), token=False)
    for name, data in {**FILES, "weights.bin": BIG}.items():
        assert open(f"{local}/{name}", "rb").read() == data, name
    m = verify_manifest(manifests(node)[0], {PK}, REPO)
    assert m.commit == head and m.git["tree"] == git(made, "rev-parse", "HEAD^{tree}") and m.git["force"] is False and m.seq == 1


def test_big_files_are_served_from_where_they_are_not_copied(node, made):
    blob = node.store.blob_path(OID)
    assert os.path.samefile(blob, made / "weights.bin"), "the store holds a link to the working tree's file"
    assert node.store.get_blob(OID).infohash and node.store.torrent_path(OID).exists()
    assert httpx.get(f"{node.url}/blobs/{OID}", timeout=30).content == BIG


def test_a_consumer_pinning_the_owner_fetches_from_the_host_with_nothing_else_involved(node, made, tmp_path):
    ag = agent_for(tmp_path, node)
    try:
        local = snapshot_download(REPO, endpoint=ag.url, cache_dir=str(tmp_path / "agent-dl"), token=False)
        for name, data in {**FILES, "weights.bin": BIG}.items():
            assert open(f"{local}/{name}", "rb").read() == data, name
    finally:
        ag.stop()


def test_the_host_seeds_the_file_in_place_to_a_peer(node, made, tmp_path):
    data = httpx.get(f"{node.url}/torrents/{OID}.torrent", timeout=30).content
    stripped = tmp_path / "t.torrent"
    stripped.write_bytes(sanitize_torrent(data, [], []))  # no web seed, no tracker: the host's swarm port is the only way
    sw = publisher_swarm()

    async def go():
        try:
            dl = await sw.start(stripped, tmp_path / "peer")
            await sw.connect(stripped, "127.0.0.1", node.swarm_port)
            end = time.time() + 30
            while time.time() < end and not dl.complete():
                await sw.connect(stripped, "127.0.0.1", node.swarm_port)
                import asyncio

                await asyncio.sleep(0.3)
            return dl.complete()
        finally:
            await sw.close()

    assert run(go())
    assert hashlib.sha256((tmp_path / "peer" / OID).read_bytes()).hexdigest() == OID


# ------------------------------------------------------------------ following the repository

def test_a_new_commit_is_signed_and_served_and_the_old_one_stays_pinnable(node, made):
    first = git(made, "rev-parse", "HEAD")
    second = commit(made, {"README.md": b"# version two\n"}, message="two")
    until(lambda: branch(node).get("commit") == second, what="the new commit")
    assert branch(node)["seq"] == 2
    assert httpx.get(f"{node.url}/{REPO}/resolve/main/README.md", timeout=10).content == b"# version two\n"
    assert httpx.get(f"{node.url}/{REPO}/resolve/{first}/README.md", timeout=10).content == FILES["README.md"]
    seqs = sorted(verify_manifest(e, {PK}, REPO).seq for e in manifests(node))
    assert seqs == [1, 2]


def test_a_new_big_file_in_a_later_commit_is_picked_up(node, made):
    other = os.urandom(1_300_000)
    head = commit(made, big={"extra.bin": other}, message="extra")
    until(lambda: branch(node).get("commit") == head, what="the commit with a new big file")
    assert httpx.get(f"{node.url}/{REPO}/resolve/main/extra.bin", timeout=30).content == other
    assert os.path.samefile(node.store.blob_path(hashlib.sha256(other).hexdigest()), made / "extra.bin")


def test_rewritten_history_is_signed_as_a_rewrite(node, made):
    commit(made, {"a.txt": b"a\n"}, message="two")
    until(lambda: branch(node).get("seq") == 2, what="the second commit")
    git(made, "reset", "-q", "--hard", "HEAD~1")
    git(made, "commit", "-q", "--allow-empty", "-m", "rewritten")
    new = git(made, "rev-parse", "HEAD")
    until(lambda: branch(node).get("commit") == new, what="the rewritten branch")
    latest = max((verify_manifest(e, {PK}, REPO) for e in manifests(node)), key=lambda m: m.seq)
    assert latest.git["force"] is True and latest.seq == 3
    older = [verify_manifest(e, {PK}, REPO) for e in manifests(node) if verify_manifest(e, {PK}, REPO).seq < 3]
    assert all(m.git["force"] is False for m in older)


def test_two_branches_at_one_commit_share_a_manifest_and_move_apart(tmp_path, made):
    git(made, "branch", "dev")
    n = Node(tmp_path, made, branches=("main", "dev"))
    try:
        base = git(made, "rev-parse", "HEAD")
        until(lambda: branch(n, "dev").get("commit") == base, what="both branches")
        ms = [verify_manifest(e, {PK}, REPO) for e in manifests(n)]
        assert len(ms) == 1 and set(ms[0].refs) == {"main", "dev"}
        moved = commit(made, {"x.txt": b"x\n"}, message="main moves")
        until(lambda: branch(n).get("commit") == moved, what="main to move")
        info = lambda r: httpx.get(f"{n.url}/api/models/{REPO}/revision/{r}", timeout=10).json()["sha"]
        assert info("main") == moved and info("dev") == base, "dev did not move"
    finally:
        n.stop()


def test_a_manifest_that_is_about_to_lapse_is_signed_again(tmp_path, made):
    n = Node(tmp_path, made, valid_for=4.0)
    try:
        until(lambda: branch(n).get("seq") == 1, what="the first manifest")
        until(lambda: branch(n).get("seq") == 2, timeout=10, what="the second signing at half the validity")
        latest = max((verify_manifest(e, {PK}, REPO) for e in manifests(n)), key=lambda m: m.seq)
        assert latest.commit == git(made, "rev-parse", "HEAD") and latest.valid_until > time.time()
    finally:
        n.stop()


# ------------------------------------------------------------------ the owner breaking things

def test_a_big_file_that_goes_missing_keeps_the_last_good_commit_and_says_why(node, made):
    good = git(made, "rev-parse", "HEAD")
    gone = os.urandom(1_200_000)
    head = commit(made, big={"later.bin": gone}, message="adds a file")
    (made / "later.bin").unlink()
    until(lambda: "later.bin" in branch(node).get("error", ""), what="the error")
    assert branch(node)["commit"] == good
    assert httpx.get(f"{node.url}/api/models/{REPO}/revision/main", timeout=10).json()["sha"] == good
    (made / "later.bin").write_bytes(gone)
    until(lambda: branch(node).get("commit") == head and not branch(node).get("error"), what="recovery once the file is back")


def test_a_file_edited_in_place_is_no_longer_served(node, made):
    assert httpx.get(f"{node.url}/blobs/{OID}", timeout=30).content == BIG
    with open(made / "weights.bin", "r+b") as f:  # an editor writing into the same file
        f.seek(100)
        f.write(b"CORRUPT")
    until(lambda: "does not hash" in branch(node).get("error", ""), what="the change to be noticed")
    assert httpx.get(f"{node.url}/blobs/{OID}", timeout=30).status_code >= 400
    (made / "weights.bin").write_bytes(BIG)  # put it back
    until(lambda: not branch(node).get("error"), what="recovery")
    assert httpx.get(f"{node.url}/blobs/{OID}", timeout=30).content == BIG


def test_a_file_replaced_by_a_checkout_does_not_disturb_serving_or_cause_rehashing(tmp_path, made, monkeypatch):
    calls = []
    real = Host._hash
    monkeypatch.setattr(Host, "_hash", staticmethod(lambda *a: calls.append(a) or real(*a)))
    n = Node(tmp_path, made)
    try:
        until(lambda: branch(n).get("seq") == 1, what="the first pass")
        assert len(calls) == 1
        tmp = made / "w.tmp"
        tmp.write_bytes(BIG)
        tmp.replace(made / "weights.bin")  # a new file with the same bytes, as a checkout does
        time.sleep(1.0)
        assert httpx.get(f"{n.url}/blobs/{OID}", timeout=30).content == BIG
        assert len(calls) == 1 and not branch(n).get("error"), "the link kept the old file; nothing was hashed again"
    finally:
        n.stop()


def test_a_restart_does_not_hash_the_big_files_again(tmp_path, made, monkeypatch):
    n = Node(tmp_path, made)
    until(lambda: branch(n).get("seq") == 1, what="the first pass")
    n.stop()
    calls = []
    monkeypatch.setattr(Host, "_hash", staticmethod(lambda *a: calls.append(a) or None))
    n2 = Node(tmp_path, made)
    try:
        until(lambda: branch(n2).get("seq") == 1, what="the same state after a restart")
        assert not calls and httpx.get(f"{n2.url}/blobs/{OID}", timeout=30).content == BIG
        assert len(manifests(n2)) == 1, "nothing was signed again"
    finally:
        n2.stop()


def test_a_missing_branch_serves_nothing_and_says_so(tmp_path, made):
    n = Node(tmp_path, made, branches=("nope",))
    try:
        until(lambda: "not found" in branch(n, "nope").get("error", ""), what="the error")
        assert httpx.get(f"{n.url}/api/models/{REPO}/revision/nope", timeout=10).status_code == 404
    finally:
        n.stop()


def test_a_tree_the_hub_would_refuse_is_not_served_either(tmp_path):
    root = make_repo(tmp_path, files=FILES)
    os.symlink("/etc/passwd", root / "link")
    git(root, "add", "link")
    git(root, "commit", "-q", "-m", "link")
    n = Node(tmp_path, root)
    try:
        until(lambda: "symbolic" in branch(n).get("error", ""), what="the refusal")
        assert not manifests(n) and httpx.get(f"{n.url}/api/models/{REPO}/revision/main", timeout=10).status_code == 404
    finally:
        n.stop()


def test_a_data_directory_that_holds_a_plain_repo_of_that_name_is_not_mixed(tmp_path, made):
    from torrenthub.store import Store

    st = Store(tmp_path / "host")
    info = {"sha": "ab" * 20, "siblings": [{"rfilename": "a", "size": 1, "lfs": {"size": 1, "sha256": "cd" * 32}}]}
    st.add_manifest(build_manifest(SK, REPO, info, ["main"], seq=1))
    del st
    n = Node(tmp_path, made)
    try:
        until(lambda: "not git backed" in branch(n).get("error", ""), what="the refusal")
    finally:
        n.stop()


def test_the_host_does_not_take_publications(node):
    r = httpx.post(f"{node.url}/api/thub/publish", json={}, timeout=10)
    assert r.status_code == 403 and r.headers["x-error-code"] == "PublishingDisabled"


# ------------------------------------------------------------------ the command

def test_the_host_command_serves_a_repo(tmp_path, made):
    keyfile = tmp_path / "k"
    keyfile.write_text(SK.hex())
    port, sp = free_port(), free_port()
    env = dict(os.environ, THUB_DATA=str(tmp_path / "cli-data"), THUB_TRACKERS="")
    proc = subprocess.Popen([sys.executable, "-m", "torrenthub", "host", "--git", str(made), "--repo", REPO, "--key-file", str(keyfile),
                             "--public-url", f"http://127.0.0.1:{port}", "--port", str(port), "--bind", "127.0.0.1", "--listen-port", str(sp),
                             "--poll", "0.3"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        until(lambda: _up(port), timeout=40, what="the host to start")
        head = git(made, "rev-parse", "HEAD")
        until(lambda: httpx.get(f"http://127.0.0.1:{port}/api/models/{REPO}/revision/main", timeout=5).status_code == 200, what="the repo")
        assert httpx.get(f"http://127.0.0.1:{port}/api/models/{REPO}/revision/main", timeout=5).json()["sha"] == head
        assert httpx.get(f"http://127.0.0.1:{port}/{REPO}/resolve/main/weights.bin", timeout=30).content == BIG
        ev = httpx.get(f"http://127.0.0.1:{port}/api/thub/manifests/{REPO}", timeout=10).json()["events"][0]
        assert verify_manifest(ev, {PK}, REPO).commit == head
    finally:
        proc.terminate()
        out, err = proc.communicate(timeout=20)
    first = json.loads(out.splitlines()[0])
    assert first["hosting"] == REPO and first["pubkey"] == PK
    assert f"signed:{PK}" in out


def _up(port):
    try:
        return httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2).status_code == 200
    except httpx.HTTPError:
        return False
