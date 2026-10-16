"""Plain git against a torrenthub (HOSTING.md, stage H3): git push signs and publishes, git clone and
fetch take only what a valid signed manifest vouches for, and big files need no git-lfs."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("libtorrent")
if shutil.which("git") is None:
    pytest.skip("git is not installed", allow_module_level=True)

from tests.conftest import Server, free_port  # noqa: E402
from tests.test_git_publish import BIG, FILES, GIT_ENV  # noqa: E402
from tests.test_host import Node  # noqa: E402
from tests.test_publish import PK, REPO, SK, Hub  # noqa: E402
from torrenthub import gitrepo as G  # noqa: E402
from torrenthub import pointers  # noqa: E402
from torrenthub import signing as sg  # noqa: E402
from torrenthub.gitremote import Helper, parse_url  # noqa: E402
from torrenthub.manifest import build_git_manifest, verify_manifest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
OID = hashlib.sha256(BIG).hexdigest()
OTHER = bytes.fromhex("00" * 31 + "2b")


@pytest.fixture()
def env(tmp_path):
    shims = tmp_path / "shims"
    shims.mkdir()
    for name, module in (("git-remote-thub", "torrenthub.gitremote"), ("torrenthub", "torrenthub")):
        f = shims / name
        f.write_text(f'#!/bin/sh\nexport PYTHONPATH="{ROOT}"\nexec "{sys.executable}" -m {module} "$@"\n')
        f.chmod(f.stat().st_mode | stat.S_IEXEC)
    key = tmp_path / "key"
    key.write_text(SK.hex())
    return {**GIT_ENV, "PATH": f"{shims}:{os.environ['PATH']}", "THUB_KEY_FILE": str(key), "THUB_DATA": str(tmp_path / "thub-data"), "PYTHONPATH": str(ROOT)}


def g(env, cwd, *args, check=True, input=None):
    r = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, input=input, timeout=180)
    if check:
        assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def tool(env, cwd, *args, check=True):
    r = subprocess.run(["torrenthub", *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=180)
    if check:
        assert r.returncode == 0, (args, r.stdout, r.stderr)
    return r


def new_repo(env, tmp_path, name="work", big=True):
    root = tmp_path / name
    root.mkdir()
    g(env, root, "init", "-q", "-b", "main")
    tool(env, root, "git-init")
    for rel, data in FILES.items():
        (root / rel).write_bytes(data)
    if big:
        (root / "weights.bin").write_bytes(BIG)
    g(env, root, "add", "-A")
    g(env, root, "commit", "-q", "-m", "first")
    return root


def head(env, root, rev="HEAD"):
    return g(env, root, "rev-parse", rev).stdout.strip()


@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0)
    yield h
    h.stop()


def remote(hub, extra=""):
    return f"thub::{hub.url}/{REPO}{extra}"


# ------------------------------------------------------------------ the filter

def test_git_add_makes_a_pointer_and_keeps_the_bytes_without_git_lfs(env, tmp_path):
    root = new_repo(env, tmp_path)
    blob = g(env, root, "cat-file", "-p", "HEAD:weights.bin").stdout
    assert blob == f"version https://git-lfs.github.com/spec/v1\noid sha256:{OID}\nsize {len(BIG)}\n"
    assert (root / ".git" / "thub" / "objects" / OID).read_bytes() == BIG
    assert (root / "weights.bin").read_bytes() == BIG, "the working tree keeps the real file"
    assert g(env, root, "cat-file", "-p", "HEAD:config.json").stdout == FILES["config.json"].decode(), "other files are ordinary blobs"
    assert g(env, root, "status", "--short").stdout == "", "git sees the file as unchanged"


def test_a_pointer_is_not_wrapped_in_another_pointer(tmp_path):
    ptr = pointers.pointer_bytes("ab" * 32, 12)
    out = io.BytesIO()
    pointers.clean(io.BytesIO(ptr), out, tmp_path / ".git")
    assert out.getvalue() == ptr and not (tmp_path / ".git" / "thub" / "objects").exists()


def test_smudge_passes_ordinary_content_through_and_honours_skip(tmp_path, monkeypatch):
    out = io.BytesIO()
    pointers.smudge(io.BytesIO(b"hello"), out, tmp_path, [])
    assert out.getvalue() == b"hello"
    ptr = pointers.pointer_bytes("ab" * 32, 12)
    monkeypatch.setenv("THUB_SKIP_SMUDGE", "1")
    out = io.BytesIO()
    pointers.smudge(io.BytesIO(ptr), out, tmp_path, [])
    assert out.getvalue() == ptr


def test_smudge_refuses_bytes_that_are_not_the_file_the_pointer_names(tmp_path):
    from fastapi import FastAPI, Response

    app = FastAPI()

    @app.get("/blobs/{key}")
    def blob(key: str):
        return Response(b"x" * len(BIG))  # right size, wrong bytes

    srv = Server(app, free_port()).start()
    try:
        with pytest.raises(G.GitError, match="not the file the pointer names"):
            pointers.ensure_cached(tmp_path, OID, len(BIG), [srv.url])
        assert not pointers.cache_path(tmp_path, OID).exists(), "nothing wrong was kept"
        assert not list((tmp_path / "thub" / "tmp").glob("*")), "no half file is left"
    finally:
        srv.stop()


# ------------------------------------------------------------------ push

def test_git_push_signs_and_publishes_and_the_hub_serves_it_verified(hub, env, tmp_path):
    root = new_repo(env, tmp_path)
    g(env, root, "remote", "add", "hub", remote(hub))
    r = g(env, root, "push", "hub", "main")
    assert "publishing" in r.stderr
    tip = head(env, root)
    assert httpx.get(f"{hub.url}/api/thub/git/{REPO}/refs", timeout=10).json()["refs"] == {"main": tip}
    ev = httpx.get(f"{hub.url}/api/thub/manifests/{REPO}", timeout=10).json()["events"][0]
    m = verify_manifest(ev, {PK}, REPO)
    assert m.commit == tip and m.git["force"] is False
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/weights.bin", timeout=60).content == BIG
    assert g(env, root, "rev-parse", "hub/main").stdout.strip() == tip, "git records where the remote branch is"


def test_a_second_push_sends_only_new_objects_and_a_fast_forward_is_accepted(hub, env, tmp_path):
    root = new_repo(env, tmp_path)
    g(env, root, "remote", "add", "hub", remote(hub))
    g(env, root, "push", "hub", "main")
    (root / "README.md").write_bytes(b"# two\n")
    g(env, root, "commit", "-q", "-am", "two")
    r = g(env, root, "push", "hub", "main")
    assert "0 big file(s)" in r.stderr
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/README.md", timeout=10).content == b"# two\n"
    assert httpx.get(f"{hub.url}/api/thub/git/{REPO}/refs", timeout=10).json()["refs"]["main"] == head(env, root)


def test_a_push_that_is_not_a_fast_forward_is_rejected_by_git_and_a_forced_one_by_the_hub(hub, env, tmp_path):
    root = new_repo(env, tmp_path)
    g(env, root, "remote", "add", "hub", remote(hub))
    g(env, root, "push", "hub", "main")
    g(env, root, "commit", "-q", "--allow-empty", "-m", "two")
    g(env, root, "push", "hub", "main")
    g(env, root, "reset", "-q", "--hard", "HEAD~1")
    g(env, root, "commit", "-q", "--allow-empty", "-m", "rewritten")
    plain = g(env, root, "push", "hub", "main", check=False)
    assert plain.returncode != 0 and "non-fast-forward" in plain.stderr
    forced = g(env, root, "push", "--force", "hub", "main", check=False)
    assert forced.returncode != 0 and "NotFastForward" not in forced.stdout and "does not allow" in forced.stderr + forced.stdout


def test_a_forced_push_goes_through_when_the_hub_allows_rewrites(tmp_path, env):
    h = Hub(tmp_path, publish_allow_force=True)
    try:
        root = new_repo(env, tmp_path)
        g(env, root, "remote", "add", "hub", remote(h))
        g(env, root, "push", "hub", "main")
        g(env, root, "commit", "-q", "--allow-empty", "-m", "two")
        g(env, root, "push", "hub", "main")
        g(env, root, "reset", "-q", "--hard", "HEAD~1")
        g(env, root, "commit", "-q", "--allow-empty", "-m", "rewritten")
        g(env, root, "push", "--force", "hub", "main")
        assert httpx.get(f"{h.url}/api/thub/git/{REPO}/refs", timeout=10).json()["refs"]["main"] == head(env, root)
        evs = httpx.get(f"{h.url}/api/thub/manifests/{REPO}", timeout=10).json()["events"]
        assert max((verify_manifest(e, {PK}, REPO) for e in evs), key=lambda m: m.seq).git["force"] is True
    finally:
        h.stop()


def test_a_push_without_a_key_or_with_the_wrong_one_fails_clearly(hub, env, tmp_path):
    root = new_repo(env, tmp_path)
    g(env, root, "remote", "add", "hub", remote(hub))
    nokey = {k: v for k, v in env.items() if k != "THUB_KEY_FILE"}
    r = g(nokey, root, "push", "hub", "main", check=False)
    assert r.returncode != 0 and "no signing key" in r.stderr + r.stdout
    other = tmp_path / "other"
    other.write_text(OTHER.hex())
    r = g({**env, "THUB_KEY_FILE": str(other)}, root, "push", "hub", "main", check=False)
    assert r.returncode != 0 and "NotAuthorised" in r.stderr + r.stdout
    assert httpx.get(f"{hub.url}/api/thub/git/{REPO}/refs", timeout=10).json()["refs"] == {}


def test_tags_and_deletions_cannot_be_pushed(hub, env, tmp_path):
    root = new_repo(env, tmp_path)
    g(env, root, "remote", "add", "hub", remote(hub))
    g(env, root, "push", "hub", "main")
    g(env, root, "tag", "v1")
    r = g(env, root, "push", "hub", "v1", check=False)
    assert r.returncode != 0 and "only branches" in r.stderr + r.stdout
    r = g(env, root, "push", "hub", ":main", check=False)
    assert r.returncode != 0 and "only branches" in r.stderr + r.stdout


# ------------------------------------------------------------------ clone and fetch

def pushed(hub, env, tmp_path):
    root = new_repo(env, tmp_path)
    g(env, root, "remote", "add", "hub", remote(hub))
    g(env, root, "push", "hub", "main")
    return root


def test_git_clone_gets_the_signed_history_and_pointers_and_pull_files_fills_them_in(hub, env, tmp_path):
    src = pushed(hub, env, tmp_path)
    dst = tmp_path / "clone"
    g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", remote(hub), str(dst))
    assert head(env, dst) == head(env, src)
    assert (dst / "config.json").read_bytes() == FILES["config.json"]
    assert (dst / "weights.bin").read_text().startswith("version https://git-lfs.github.com/spec/v1"), "big files arrive as pointers"
    tool(env, dst, "git-init")
    r = tool(env, dst, "pull-files")
    assert '"weights.bin"' in r.stdout
    assert (dst / "weights.bin").read_bytes() == BIG
    assert g(env, dst, "status", "--short").stdout == "", "the filled-in file is what git expects"


def test_a_clone_with_the_filter_set_up_gets_the_big_file_during_checkout(hub, env, tmp_path):
    pushed(hub, env, tmp_path)
    dst = tmp_path / "clone"
    g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", "-c", "filter.thub.clean=torrenthub filter clean", "-c", "filter.thub.smudge=torrenthub filter smudge",
      "-c", "filter.thub.required=true", remote(hub), str(dst))
    assert (dst / "weights.bin").read_bytes() == BIG
    assert (dst / ".git" / "thub" / "objects" / OID).read_bytes() == BIG
    assert g(env, dst, "status", "--short").stdout == ""


def test_a_clone_with_no_signer_pinned_is_refused(hub, env, tmp_path):
    pushed(hub, env, tmp_path)
    r = g(env, tmp_path, "clone", remote(hub), str(tmp_path / "c"), check=False)
    assert r.returncode != 0 and "no signer is pinned" in r.stderr


def test_a_clone_pinning_someone_else_gets_nothing(hub, env, tmp_path):
    pushed(hub, env, tmp_path)
    other = sg.public_key(OTHER).hex()
    r = g(env, tmp_path, "clone", "-c", f"thub.signer={other}", remote(hub), str(tmp_path / "c"), check=False)
    assert r.returncode != 0 and "none is a valid git backed one signed by a pinned key" in r.stderr
    assert not (tmp_path / "c" / "config.json").exists()


def test_the_signer_can_be_named_in_the_url_or_the_environment(hub, env, tmp_path):
    pushed(hub, env, tmp_path)
    g(env, tmp_path, "clone", remote(hub, f"?signer={PK}"), str(tmp_path / "c1"))
    g({**env, "THUB_SIGNERS": PK}, tmp_path, "clone", remote(hub), str(tmp_path / "c2"))
    assert (tmp_path / "c1" / "config.json").exists() and (tmp_path / "c2" / "config.json").exists()


def test_fetch_brings_in_a_new_signed_commit_and_only_what_is_new(hub, env, tmp_path):
    src = pushed(hub, env, tmp_path)
    dst = tmp_path / "clone"
    g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", remote(hub), str(dst))
    (src / "README.md").write_bytes(b"# later\n")
    g(env, src, "commit", "-q", "-am", "later")
    g(env, src, "push", "hub", "main")
    g(env, dst, "fetch", "origin")
    assert head(env, dst, "origin/main") == head(env, src)
    g(env, dst, "merge", "-q", "--ff-only", "origin/main")
    assert (dst / "README.md").read_bytes() == b"# later\n"


def test_a_manifest_by_another_key_cannot_move_a_branch_for_a_pinned_client(hub, env, tmp_path):
    src = pushed(hub, env, tmp_path)
    dst = tmp_path / "clone"
    g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", remote(hub), str(dst))
    g(env, src, "commit", "-q", "--allow-empty", "-m", "evil")
    evil = head(env, src)
    tree, parents = G.commit_fields(src, evil)
    rows = G.derive(src, evil, blob_max=1 << 20, small_total=1 << 24, max_files=100, sandbox=False).rows
    hub.store.add_manifest(build_git_manifest(OTHER, REPO, evil, tree, parents, rows, ["main"], seq=99))
    g(env, dst, "fetch", "origin")
    assert head(env, dst, "origin/main") == head(env, src, "HEAD~1"), "the branch did not move"


def test_a_hub_that_sends_the_wrong_objects_is_caught(hub, env, tmp_path, monkeypatch):
    src = pushed(hub, env, tmp_path)
    (src / "README.md").write_bytes(b"# later\n")
    g(env, src, "commit", "-q", "-am", "later")
    g(env, src, "push", "hub", "main")
    ing = hub.app.state.ingest
    older = head(env, src, "HEAD~1")
    real = ing.serve_pack

    async def liar(repo, want, have, host_dir=None):
        return await real(repo, older, [])  # always the first commit, whatever was asked for

    monkeypatch.setattr(ing, "serve_pack", liar)
    dst = tmp_path / "clone"
    r = g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", remote(hub), str(dst), check=False)
    assert r.returncode != 0
    refs = subprocess.run(["git", "-C", str(dst), "for-each-ref"], capture_output=True, text=True, env=env).stdout if dst.exists() else ""
    assert refs.strip() == "", "no branch was created from objects that were not the signed commit"


def test_a_signed_table_that_the_commit_does_not_give_is_refused_by_the_client(hub, env, tmp_path):
    src = pushed(hub, env, tmp_path)
    g(env, src, "commit", "-q", "--allow-empty", "-m", "forged table")
    forged = head(env, src)
    tree, parents = G.commit_fields(src, forged)
    rows = tuple(sorted((p, s, ("ab" * 32 if p == "config.json" else x), b) for p, s, x, b in G.derive(src, forged, blob_max=1 << 20, small_total=1 << 24, max_files=100, sandbox=False).rows))
    # the owner's own key signs a table that is not the commit's; the hub would refuse it at publish, so put it in the store directly
    ing = hub.app.state.ingest
    pack = G.make_pack(src, forged, [head(env, src, "HEAD~1")])
    perm = ing._perm_repo(REPO)
    G.run_git(["index-pack", "--stdin"], cwd=perm, stdin=pack, sandbox=True)
    G.update_ref(perm, "main", forged)
    hub.store.add_manifest(build_git_manifest(SK, REPO, forged, tree, parents, rows, ["main"], seq=50))
    dst = tmp_path / "clone"
    r = g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", remote(hub), str(dst), check=False)
    assert r.returncode != 0 and "does not give the file table" in r.stderr


def test_a_git_clone_from_a_machine_that_hosts_its_own_repo(tmp_path, env):
    from tests.test_git_publish import make_repo

    made = make_repo(tmp_path, files={**FILES, ".gitattributes": b"*.bin filter=thub -text\n"}, big={"weights.bin": BIG})
    n = Node(tmp_path, made)
    try:
        import time

        end = time.time() + 20
        while time.time() < end and not n.report()["branches"].get("main", {}).get("commit"):
            time.sleep(0.1)
        dst = tmp_path / "clone"
        g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", "-c", "filter.thub.clean=torrenthub filter clean", "-c", "filter.thub.smudge=torrenthub filter smudge",
          "-c", "filter.thub.required=true", f"thub::{n.url}/{REPO}", str(dst))
        assert head(env, dst) == head(env, made)
        assert (dst / "weights.bin").read_bytes() == BIG and (dst / "README.md").read_bytes() == FILES["README.md"]
    finally:
        n.stop()


# ------------------------------------------------------------------ the pack endpoint on the hub

def test_the_hub_gives_packs_only_for_commits_it_serves(hub, env, tmp_path):
    src = pushed(hub, env, tmp_path)
    tip = head(env, src)
    url = f"{hub.url}/api/thub/git/{REPO}/pack"
    ok = httpx.post(url, json={"want": tip, "have": []}, timeout=30)
    assert ok.status_code == 200 and ok.content[:4] == b"PACK"
    for bad, code in (({"want": "ab" * 20, "have": []}, 404), ({"want": "zz", "have": []}, 400), ({"want": tip, "have": ["1"]}, 400),
                      ({"want": tip, "have": ["ab" * 20] * 65}, 400), ({"have": []}, 400)):
        r = httpx.post(url, json=bad, timeout=30)
        assert r.status_code == code, (bad, r.status_code, r.text)
    assert httpx.post(f"{hub.url}/api/thub/git/nobody/none/pack", json={"want": tip, "have": []}, timeout=30).status_code == 404


def test_a_have_the_hub_does_not_know_is_ignored(hub, env, tmp_path):
    src = pushed(hub, env, tmp_path)
    r = httpx.post(f"{hub.url}/api/thub/git/{REPO}/pack", json={"want": head(env, src), "have": ["cd" * 20]}, timeout=30)
    assert r.status_code == 200 and r.content[:4] == b"PACK"


def test_a_host_hands_out_only_what_it_serves_not_everything_in_the_repository(tmp_path, env):
    from tests.test_git_publish import make_repo

    made = make_repo(tmp_path, files=FILES)
    g(env, made, "checkout", "-q", "-b", "private")
    (made / "secret.txt").write_bytes(b"not for serving\n")
    g(env, made, "add", "secret.txt")
    g(env, made, "commit", "-q", "-m", "private work")
    secret = head(env, made)
    g(env, made, "checkout", "-q", "main")
    n = Node(tmp_path, made)  # serves main only
    try:
        import time

        end = time.time() + 20
        while time.time() < end and not n.report()["branches"].get("main", {}).get("commit"):
            time.sleep(0.1)
        url = f"{n.url}/api/thub/git/{REPO}/pack"
        assert httpx.post(url, json={"want": head(env, made), "have": []}, timeout=30).status_code == 200
        r = httpx.post(url, json={"want": secret, "have": []}, timeout=30)
        assert r.status_code == 404 and r.headers["x-error-code"] == "NotServed"
    finally:
        n.stop()


def test_an_expired_manifest_is_ignored_by_a_client(hub, env, tmp_path):
    import time

    src = pushed(hub, env, tmp_path)
    good = head(env, src)
    g(env, src, "commit", "-q", "--allow-empty", "-m", "later")
    later = head(env, src)
    tree, parents = G.commit_fields(src, later)
    rows = G.derive(src, later, blob_max=1 << 20, small_total=1 << 24, max_files=100, sandbox=False).rows
    now = int(time.time())
    perm = hub.app.state.ingest._perm_repo(REPO)  # the hub holds the commit's objects too, as if it had once been published
    G.run_git(["index-pack", "--stdin"], cwd=perm, stdin=G.make_pack(src, later, [good]), sandbox=True)
    hub.store.add_manifest(build_git_manifest(SK, REPO, later, tree, parents, rows, ["main"], created_at=now - 1000, seq=77, valid_until=now - 500))
    dst = tmp_path / "clone"
    g(env, tmp_path, "clone", "-c", f"thub.signer={PK}", remote(hub), str(dst))
    assert head(env, dst) == good, "the newest manifest had lapsed, so the clone follows the one before it"


def test_the_pack_endpoint_is_rate_limited(tmp_path, env):
    h = Hub(tmp_path, git_pack_per_ip_per_minute=1.0)
    try:
        codes = [httpx.post(f"{h.url}/api/thub/git/{REPO}/pack", json={"want": "ab" * 20, "have": []}, timeout=10).status_code for _ in range(25)]
        assert 429 in codes
    finally:
        h.stop()


# ------------------------------------------------------------------ the helper itself

def test_urls():
    assert parse_url("thub://hub.example/acme/pub") == ("https://hub.example", "acme/pub", [])
    assert parse_url("http://127.0.0.1:8080/acme/pub.git")[:2] == ("http://127.0.0.1:8080", "acme/pub")
    assert parse_url(f"https://h/acme/pub?signer={PK}&signer={PK}")[2] == [PK, PK]
    for bad in ("ftp://h/acme/pub", "https://h/just-one", "https://h/a/b/c", "thub://", "https://h/../x"):
        with pytest.raises(ValueError):
            parse_url(bad)


def test_the_protocol_basics():
    out = io.StringIO()
    h = Helper("origin", "http://127.0.0.1:9/acme/pub", out=out, err=io.StringIO())
    assert h.serve(io.StringIO("capabilities\n\n")) == 0
    assert out.getvalue() == "fetch\npush\noption\n\n"
    out.truncate(0), out.seek(0)
    h.serve(io.StringIO("option verbosity 2\noption followtags true\nwhat\n\n"))
    assert out.getvalue() == "ok\nunsupported\nunsupported\n"
    assert h.verbosity == 2


def test_the_helper_refuses_to_fetch_a_commit_no_valid_manifest_signs(tmp_path, env):
    root = new_repo(env, tmp_path)
    h = Helper("origin", f"http://127.0.0.1:9/{REPO}?signer={PK}", out=io.StringIO(), err=io.StringIO())
    h.git_dir = root / ".git"
    h._signed = {"main": ("ab" * 20, None)}  # what the signed manifests say the branch holds
    with pytest.raises(Exception, match="not what a valid manifest signs"):
        h.do_fetch([f"fetch {'cd' * 20} refs/heads/main"])
    with pytest.raises(Exception, match="not what a valid manifest signs"):
        h.do_fetch([f"fetch {'ab' * 20} refs/heads/other"])
