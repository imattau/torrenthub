"""Stock git against a hub (HOSTING.md, stage H4): `git clone https://hub/owner/name` with no helper,
the git-lfs batch API for big files, and a check that a plain clone can still be verified."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import time

import httpx
import pytest

pytest.importorskip("libtorrent")
if shutil.which("git") is None:
    pytest.skip("git is not installed", allow_module_level=True)

from tests.test_git_publish import BIG, FILES, GIT_ENV, commit, git, gpush, make_repo  # noqa: E402
from tests.test_host import Node  # noqa: E402
from tests.test_publish import PK, REPO, SK, Hub, run  # noqa: E402
from torrenthub import gitrepo as G  # noqa: E402
from torrenthub.gitremote import RemoteError, verify_clone  # noqa: E402

OID = hashlib.sha256(BIG).hexdigest()
PLAIN = {k: v for k, v in GIT_ENV.items()}  # no helper on PATH: this is stock git


def sg(cwd, *args, check=True, env=None):
    r = subprocess.run(["git", *args], cwd=cwd, env=env or PLAIN, capture_output=True, text=True, timeout=120)
    if check:
        assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0)
    yield h
    h.stop()


@pytest.fixture()
def published(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    run(gpush(hub, root, tmp_path / "stage1"))
    return root


def url(hub, suffix=""):
    return f"{hub.url}/{REPO}{suffix}"


# ------------------------------------------------------------------ smart HTTP

@pytest.mark.parametrize("version", ["0", "2"])
def test_stock_git_clones_a_hub_repo_over_http(hub, published, tmp_path, version):
    dst = tmp_path / f"c{version}"
    r = sg(tmp_path, "-c", f"protocol.version={version}", "clone", url(hub), str(dst))
    assert git(published, "rev-parse", "HEAD") == sg(dst, "rev-parse", "HEAD").stdout.strip()
    assert (dst / "config.json").read_bytes() == FILES["config.json"]
    assert (dst / "weights.bin").read_text().startswith("version https://git-lfs.github.com/spec/v1"), "big files are pointers in the tree"
    assert "warning" not in r.stderr.lower(), r.stderr


def test_a_url_ending_in_dot_git_is_the_same_repository(hub, published, tmp_path):
    sg(tmp_path, "clone", url(hub, ".git"), str(tmp_path / "c"))
    assert (tmp_path / "c" / "README.md").exists()


def test_fetch_brings_a_later_commit(hub, published, tmp_path):
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    commit(published, {"README.md": b"# later\n"}, message="later")
    run(gpush(hub, published, tmp_path / "stage2", seq=2))
    sg(dst, "fetch", "origin")
    assert sg(dst, "rev-parse", "origin/main").stdout.strip() == git(published, "rev-parse", "HEAD")
    assert sg(dst, "log", "--oneline", "origin/main").stdout.count("\n") == 2, "the history came along"


def test_a_branch_other_than_main_still_clones_and_checks_out(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    git(root, "branch", "-m", "dev")
    run(gpush(hub, root, tmp_path / "s", refs=("dev",)))
    r = sg(tmp_path, "clone", url(hub), str(tmp_path / "c"))
    assert (tmp_path / "c" / "config.json").exists() and sg(tmp_path / "c", "branch", "--show-current").stdout.strip() == "dev"
    assert "nonexistent" not in r.stderr


def test_the_hub_is_read_only_over_plain_git(hub, published, tmp_path):
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    (dst / "x.txt").write_text("x")
    sg(dst, "add", "x.txt")
    sg(dst, "commit", "-q", "-m", "x")
    r = sg(dst, "push", "origin", "main", check=False)
    assert r.returncode != 0 and "403" in r.stderr
    assert httpx.get(url(hub, "/info/refs?service=git-receive-pack"), timeout=10).status_code == 403
    assert httpx.get(url(hub, "/info/refs"), timeout=10).status_code == 403, "no dumb protocol"


def test_a_repo_the_hub_does_not_have_is_not_found(hub, tmp_path):
    r = sg(tmp_path, "clone", f"{hub.url}/nobody/none", str(tmp_path / "c"), check=False)
    assert r.returncode != 0 and "not found" in r.stderr


def test_a_hosted_repo_serves_its_served_branches_and_nothing_else(tmp_path):
    made = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    git(made, "checkout", "-q", "-b", "private")
    (made / "secret.txt").write_bytes(b"not for serving\n")
    git(made, "add", "secret.txt")
    git(made, "commit", "-q", "-m", "private work")
    secret = git(made, "rev-parse", "HEAD")
    git(made, "checkout", "-q", "main")
    n = Node(tmp_path, made)
    try:
        end = time.time() + 20
        while time.time() < end and not n.report()["branches"].get("main", {}).get("commit"):
            time.sleep(0.1)
        dst = tmp_path / "c"
        sg(tmp_path, "clone", f"{n.url}/{REPO}", str(dst))
        assert sg(dst, "rev-parse", "HEAD").stdout.strip() == git(made, "rev-parse", "main")
        assert [l.split()[1] for l in sg(dst, "ls-remote", "origin").stdout.splitlines()] == ["HEAD", "refs/heads/main"]
        assert sg(dst, "cat-file", "-e", secret, check=False).returncode != 0, "the private commit is not in the clone"
        assert sg(dst, "fetch", "origin", secret, check=False).returncode != 0, "and it cannot be asked for by id"
        perm = n.store.git_repo_path(REPO)
        assert G.object_type(perm, secret) is None, "the hub's own repository never held it"
    finally:
        n.stop()


def test_a_host_that_rewrites_history_updates_what_plain_git_sees(tmp_path):
    made = make_repo(tmp_path, files=FILES)
    commit(made, {"a.txt": b"a\n"}, message="two")
    n = Node(tmp_path, made)
    try:
        until_main = lambda sha: _wait(lambda: n.report()["branches"].get("main", {}).get("commit") == sha)
        until_main(git(made, "rev-parse", "HEAD"))
        git(made, "reset", "-q", "--hard", "HEAD~1")
        git(made, "commit", "-q", "--allow-empty", "-m", "rewritten")
        new = git(made, "rev-parse", "HEAD")
        until_main(new)
        out = sg(tmp_path, "ls-remote", f"{n.url}/{REPO}").stdout
        assert f"{new}\trefs/heads/main" in out
    finally:
        n.stop()


def _wait(fn, timeout=20.0):
    end = time.time() + timeout
    while time.time() < end:
        if fn():
            return True
        time.sleep(0.1)
    raise AssertionError("timed out")


# ------------------------------------------------------------------ limits on the git endpoints

def test_requests_that_inflate_are_refused(hub, published):
    u = url(hub, "/git-upload-pack")
    bomb = gzip.compress(b"0" * (hub.settings.git_http_max_body + 10))
    r = httpx.post(u, content=bomb, headers={"Content-Encoding": "gzip"}, timeout=30)
    assert r.status_code == 413, r.text
    assert httpx.post(u, content=b"not gzip", headers={"Content-Encoding": "gzip"}, timeout=30).status_code == 400
    assert httpx.post(u, content=b"x" * (hub.settings.git_http_max_body + 1), timeout=30).status_code == 413


def test_the_git_endpoints_are_rate_limited(tmp_path):
    h = Hub(tmp_path, git_http_per_ip_per_minute=1.0)
    try:
        codes = [httpx.get(f"{h.url}/{REPO}/info/refs?service=git-upload-pack", timeout=10).status_code for _ in range(40)]
        assert 429 in codes
    finally:
        h.stop()


def test_garbage_to_upload_pack_does_not_hurt_the_hub(hub, published):
    r = httpx.post(url(hub, "/git-upload-pack"), content=b"0032want " + b"zz" * 20 + b"\n0000", timeout=30)
    assert r.status_code in (200, 500)  # git answers with an error pkt-line, or the hub reports the failure
    assert httpx.get(f"{hub.url}/healthz", timeout=10).status_code == 200


# ------------------------------------------------------------------ git-lfs

def batch(hub, objects, op="download"):
    return httpx.post(url(hub, "/info/lfs/objects/batch"), json={"operation": op, "transfers": ["basic"], "objects": objects},
                      headers={"Accept": "application/vnd.git-lfs+json", "Content-Type": "application/vnd.git-lfs+json"}, timeout=30)


def test_the_lfs_batch_api_points_at_the_blob(hub, published):
    r = batch(hub, [{"oid": OID, "size": len(BIG)}])
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/vnd.git-lfs+json")
    o = r.json()["objects"][0]
    assert o["oid"] == OID and o["size"] == len(BIG) and r.json()["transfer"] == "basic"
    href = o["actions"]["download"]["href"]
    assert href == f"{hub.settings.public_url}/blobs/{OID}"
    assert hashlib.sha256(httpx.get(href, timeout=60).content).hexdigest() == OID
    assert httpx.get(f"{hub.url}/{REPO}.git/info/lfs/objects/batch").status_code in (404, 405), "the batch API is a POST"


def test_lfs_objects_this_repo_does_not_have_are_refused_one_by_one(hub, published):
    other = hashlib.sha256(b"other").hexdigest()
    r = batch(hub, [{"oid": OID, "size": len(BIG)}, {"oid": other, "size": 5}, {"oid": "nope", "size": 1}])
    objs = r.json()["objects"]
    assert "actions" in objs[0] and objs[1]["error"]["code"] == 404 and objs[2]["error"]["code"] == 422


def test_an_lfs_blob_of_another_repo_on_the_hub_is_not_given_out(hub, published, tmp_path):
    from tests.test_publish import FILES as PLAIN_FILES, push

    secret_big = os.urandom(1_300_000)
    run(push(hub, tmp_path, {**PLAIN_FILES, "other.bin": secret_big}, repo="acme/other", name="srcother", secret=SK))
    x = hashlib.sha256(secret_big).hexdigest()
    assert httpx.get(f"{hub.url}/blobs/{x}", timeout=30).status_code == 200, "blobs are public by hash, as they always were"
    assert "error" in batch(hub, [{"oid": x, "size": len(secret_big)}]).json()["objects"][0], "but this repo's LFS endpoint does not vouch for it"


def test_lfs_uploads_and_bad_requests_are_refused(hub, published):
    r = batch(hub, [{"oid": OID, "size": len(BIG)}], op="upload")
    assert r.status_code == 403 and "torrenthub publish" in r.json()["message"]
    assert httpx.post(url(hub, "/info/lfs/objects/batch"), content=b"not json", timeout=10).status_code == 422
    assert batch(hub, [{"oid": OID, "size": 1}] * 1001).status_code == 422


def test_lfs_does_not_serve_a_blocked_blob(hub, published):
    hub.store.add_block(OID, "takedown")
    assert batch(hub, [{"oid": OID, "size": len(BIG)}]).json()["objects"][0]["error"]["code"] == 404


# ------------------------------------------------------------------ verifying a plain clone

def test_a_plain_clone_verifies_against_the_owners_key(hub, published, tmp_path):
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    res = verify_clone(dst, [PK])
    assert res["ok"] and res["branches"]["main"]["state"] == "verified"


def test_verification_needs_a_pinned_key_and_a_wrong_one_verifies_nothing(hub, published, tmp_path):
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    with pytest.raises(RemoteError, match="no signer is pinned"):
        verify_clone(dst, [])
    from torrenthub import signing as sgn

    with pytest.raises(RemoteError, match="none is a valid"):
        verify_clone(dst, [sgn.public_key(bytes.fromhex("00" * 31 + "2b")).hex()])


def test_a_hub_that_moves_a_branch_to_an_unsigned_commit_is_noticed(hub, published, tmp_path):
    perm = hub.store.git_repo_path(REPO)
    signed = git(published, "rev-parse", "HEAD")
    commit(published, {"evil.txt": b"unsigned\n"}, message="unsigned work")
    evil = git(published, "rev-parse", "HEAD")
    G.run_git(["index-pack", "--stdin"], cwd=perm, stdin=G.make_pack(published, evil, [signed]), sandbox=True)
    G.update_ref(perm, "main", evil)  # the hub's repo now says something no manifest signed
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    assert sg(dst, "rev-parse", "HEAD").stdout.strip() == evil, "stock git believes the hub"
    res = verify_clone(dst, [PK])
    assert not res["ok"] and res["branches"]["main"]["state"] == "ahead"
    unrelated = make_repo(tmp_path, "unrelated", files={"u.txt": b"u\n"})
    u = git(unrelated, "rev-parse", "HEAD")
    G.run_git(["index-pack", "--stdin"], cwd=perm, stdin=G.make_pack(unrelated, u, []), sandbox=True)
    G.update_ref(perm, "main", u)
    dst2 = tmp_path / "c2"
    sg(tmp_path, "clone", url(hub), str(dst2))
    res2 = verify_clone(dst2, [PK])
    assert not res2["ok"] and res2["branches"]["main"]["state"] == "not_fetched" and "never arrives" in res2["branches"]["main"]["note"]
    sg(dst2, "fetch", "origin")  # fetching cannot help: the hub's repository no longer holds the signed history on that branch
    assert not verify_clone(dst2, [PK])["ok"]


def test_a_signed_table_the_commit_does_not_give_fails_verification(hub, published, tmp_path):
    from torrenthub.manifest import build_git_manifest

    base = git(published, "rev-parse", "HEAD")
    commit(published, message="forged table")
    forged = git(published, "rev-parse", "HEAD")
    tree, parents = G.commit_fields(published, forged)
    rows = tuple(sorted((p, s, ("ab" * 32 if p == "config.json" else x), b)
                        for p, s, x, b in G.derive(published, forged, blob_max=1 << 20, small_total=1 << 24, max_files=100, sandbox=False).rows))
    perm = hub.store.git_repo_path(REPO)
    G.run_git(["index-pack", "--stdin"], cwd=perm, stdin=G.make_pack(published, forged, [base]), sandbox=True)
    G.update_ref(perm, "main", forged)
    hub.store.add_manifest(build_git_manifest(SK, REPO, forged, tree, parents, rows, ["main"], seq=50))
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    res = verify_clone(dst, [PK])
    assert not res["ok"] and res["branches"]["main"]["state"] == "different"


def test_an_old_clone_is_not_wrong_just_not_up_to_date(hub, published, tmp_path):
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    commit(published, {"README.md": b"# later\n"}, message="later")
    run(gpush(hub, published, tmp_path / "stage2", seq=2))
    assert verify_clone(dst, [PK])["branches"]["main"]["state"] == "not_fetched"
    sg(dst, "pull", "-q", "--ff-only")
    assert verify_clone(dst, [PK])["ok"]


def test_the_verify_command_prints_and_sets_its_exit_status(hub, published, tmp_path):
    dst = tmp_path / "c"
    sg(tmp_path, "clone", url(hub), str(dst))
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    import sys

    cmd = [sys.executable, "-m", "torrenthub", "verify-git", "--dir", str(dst), "--signer", PK]
    env = {**os.environ, "PYTHONPATH": root, "THUB_DATA": str(tmp_path / "d")}
    ok = subprocess.run(cmd, env=env, capture_output=True, text=True)
    assert ok.returncode == 0 and json.loads(ok.stdout)["ok"] is True
    bad = subprocess.run(cmd[:-1] + ["00" * 31 + "2b"], env=env, capture_output=True, text=True)
    assert bad.returncode != 0


# ------------------------------------------------------------------ setting up for stock git-lfs

def test_git_init_with_lfs_writes_lfs_attributes_and_no_filter_config(tmp_path):
    from torrenthub import pointers

    root = tmp_path / "r"
    root.mkdir()
    sg(root, "init", "-q")
    out = pointers.install(root, ("*.bin",), lfs=True)
    assert out["added"] == ["*.bin"]
    assert (root / ".gitattributes").read_text() == "*.bin filter=lfs diff=lfs merge=lfs -text\n"
    assert sg(root, "config", "--get", "filter.thub.clean", check=False).returncode != 0
    assert sg(root, "config", "--get", "filter.lfs.clean").stdout.strip() == "git-lfs clean -- %f", "git-lfs's filters are set locally"
    hook = root / ".git" / "hooks" / "pre-push"
    assert "thub::*" in hook.read_text() and os.access(hook, os.X_OK), "a pre-push hook that leaves thub remotes alone"
    assert subprocess.run([str(hook), "origin", "thub::http://h/a/b"], input="", capture_output=True, text=True).returncode == 0
    assert pointers.install(root, ("*.bin",), lfs=True)["warnings"] == [], "running it again changes nothing"
    # git-lfs's own hook is replaced by ours, which still hands every other remote to git lfs
    hook.write_text("#!/bin/sh\ncommand -v git-lfs >/dev/null 2>&1 || { echo 'git-lfs missing'; exit 2; }\ngit lfs pre-push \"$@\"\n")
    assert pointers.install(root, ("*.bin",), lfs=True)["warnings"] == [] and "thub::*" in hook.read_text()
    assert (root / ".git" / "hooks" / "pre-push.thub-backup").exists()
    # a hook of the user's own is left alone, with a warning
    hook.write_text("#!/bin/sh\necho mine\n")
    w = pointers.install(root, ("*.bin",), lfs=True)["warnings"]
    assert w and "hook of your own" in w[0] and hook.read_text() == "#!/bin/sh\necho mine\n"
