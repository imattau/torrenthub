"""Git backed publishing (HOSTING.md, stage H1): a real git repository goes to a hub, and every
rule the hub applies to a publisher's objects is shown to refuse what it should."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess

import httpx
import pytest

pytest.importorskip("libtorrent")
if shutil.which("git") is None:
    pytest.skip("git is not installed", allow_module_level=True)

from huggingface_hub import snapshot_download  # noqa: E402

from tests.test_publish import PK, REPO, SK, Hub, publisher_swarm, run  # noqa: E402
from torrenthub import gitrepo as G  # noqa: E402
from torrenthub.manifest import ManifestInvalid, build_git_manifest, verify_manifest  # noqa: E402
from torrenthub.publisher import hub_heads, prepare_git, publish  # noqa: E402

BIG = os.urandom(2 * 1024 * 1024 + 77)
GIT_ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}


def git(repo, *args, input=None):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=GIT_ENV, input=input)
    assert r.returncode == 0, (args, r.stderr.decode())
    return r.stdout.decode().strip()


def pointer(data: bytes) -> bytes:
    return f"version https://git-lfs.github.com/spec/v1\noid sha256:{hashlib.sha256(data).hexdigest()}\nsize {len(data)}\n".encode()


def make_repo(tmp_path, name="work", files=None, big=None, message="first"):
    """A git repo whose tree holds `files` as plain blobs and `big` as LFS pointers, while the
    working tree keeps the real bytes of the big files, as it does after a git-lfs checkout."""
    root = tmp_path / name
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    commit(root, files, big, message)
    return root


def commit(root, files=None, big=None, message="next"):
    for rel, data in (files or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(data)
    for rel, data in (big or {}).items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(pointer(data))
    paths = [*(files or {}), *(big or {})]
    if paths:  # only these: a big file's real bytes stay in the working tree and out of git
        git(root, "add", "-f", "--", *paths)
    git(root, "commit", "-q", "--allow-empty", "-m", message)
    for rel, data in (big or {}).items():
        (root / rel).write_bytes(data)
    return git(root, "rev-parse", "HEAD")


FILES = {"config.json": b'{"hidden": 8}\n', "README.md": b"# a git backed model\n"}


@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0)
    yield h
    h.stop()


async def gpush(hub, root, stage, *, seq=1, secret=SK, repo=REPO, **kw):
    async with httpx.AsyncClient(timeout=30) as c:
        have = await hub_heads(c, hub.url, repo)
    pub = prepare_git(secret, repo, root, stage, seq=seq, have=have, **kw)
    sw = publisher_swarm()
    try:
        return pub, await publish(hub.url, pub, sw, timeout=60, poll=0.3)
    finally:
        await sw.close()


def raw_body(root, rows=None, *, seq=1, refs=("main",), rev="HEAD", have=(), force=False):
    """A publication built by hand, without the publisher's own checks, so the hub's can be tried."""
    head = G.local_commit(root, rev)
    tree, parents = G.commit_fields(root, head)
    rows = rows or (("x.txt", 1, "00" * 32, None),)
    ev = build_git_manifest(SK, REPO, head, tree, parents, rows, list(refs), seq=seq, force=force)
    pack = G.make_pack(root, head, [h for h in have if G.local_has(root, h)])
    return {"manifest": ev, "inline": {}, "torrents": {}, "git": {"head": head, "pack": base64.b64encode(pack).decode()}}


def send(hub, body):
    r = httpx.post(f"{hub.url}/api/thub/publish", json=body, timeout=60)
    return r.status_code, r.headers.get("x-error-code"), (r.json().get("error", "") if r.status_code >= 400 else r.json())


# ------------------------------------------------------------------ the happy path

def test_a_git_repo_reaches_the_hub_with_its_real_commit_id_and_downloads_verified(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    head = git(root, "rev-parse", "HEAD")
    pub, st = run(gpush(hub, root, tmp_path / "stage1"))
    assert st["state"] == "done" and st["commit"] == head, "the commit is git's own id, not a hash of the table"
    info = httpx.get(f"{hub.url}/api/models/{REPO}/revision/main", timeout=30).json()
    assert info["sha"] == head and sorted(s["rfilename"] for s in info["siblings"]) == sorted([*FILES, "weights.bin"])
    local = snapshot_download(REPO, endpoint=hub.url, cache_dir=str(tmp_path / "dl"), token=False)
    for name, data in {**FILES, "weights.bin": BIG}.items():
        assert open(f"{local}/{name}", "rb").read() == data, name
    # the hub keeps the history as git, and says where each branch is
    perm = hub.app.state.ingest._perm_repo(REPO)
    assert git(perm, "cat-file", "-t", head) == "commit" and git(perm, "rev-parse", "refs/heads/main") == head
    assert httpx.get(f"{hub.url}/api/thub/git/{REPO}/refs", timeout=30).json()["refs"] == {"main": head}
    # the stored manifest verifies as version 3 and names the same tree
    ev = httpx.get(f"{hub.url}/api/thub/manifests/{REPO}", timeout=30).json()["events"][0]
    m = verify_manifest(ev, {PK}, REPO)
    assert m.git["tree"] == git(root, "rev-parse", "HEAD^{tree}") and m.commit == head


def test_a_second_commit_sends_only_what_the_hub_lacks_and_moves_the_branch(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    first, _ = run(gpush(hub, root, tmp_path / "s1"))
    head2 = commit(root, {"README.md": b"# version two\n", "notes/new.txt": b"hello\n"}, message="second")
    pub2, st = run(gpush(hub, root, tmp_path / "s2", seq=2))
    assert st["state"] == "done" and pub2.commit == head2 and not pub2.torrents, "the big file is already on the hub"
    full = G.make_pack(root, head2, [])
    assert len(base64.b64decode(pub2.body["git"]["pack"])) < len(full), "only the new objects were sent"
    perm = hub.app.state.ingest._perm_repo(REPO)
    assert git(perm, "rev-list", "--count", "refs/heads/main") == "2"
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/README.md", timeout=30).content == b"# version two\n"
    assert httpx.get(f"{hub.url}/{REPO}/resolve/{first.commit}/README.md", timeout=30).content == FILES["README.md"], "the old commit is still there"
    import time

    for _ in range(50):
        if not list((hub.store.root / "tmp").glob("git-*")):
            break
        time.sleep(0.1)
    assert not list((hub.store.root / "tmp").glob("git-*")), "the throwaway repositories are removed once a publication is done"


def test_a_new_big_file_in_a_later_commit_goes_by_torrent(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    run(gpush(hub, root, tmp_path / "s1"))
    other = os.urandom(1_500_000)
    commit(root, big={"extra.bin": other})
    pub, st = run(gpush(hub, root, tmp_path / "s2", seq=2))
    assert st["state"] == "done" and list(pub.torrents) == [hashlib.sha256(other).hexdigest()]
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/extra.bin", timeout=60).content == other


def test_the_pack_counts_against_the_quota(tmp_path):
    data = os.urandom(100)
    root = make_repo(tmp_path, files={"a.txt": data})
    pub = prepare_git(SK, REPO, root, tmp_path / "s")
    pack = len(base64.b64decode(pub.body["git"]["pack"]))
    assert pack > 150, "the pack is bigger than the file it carries"
    h = Hub(tmp_path, quota=len(data) + 50)  # room for the file, not for the file and the pack
    try:
        code = send(h, pub.body)
        assert code[0] == 413 and code[1] == "QuotaExceeded"
    finally:
        h.stop()
    h2 = Hub(tmp_path, "hub2", quota=len(data) + pack)
    try:
        assert send(h2, pub.body)[0] == 202
        import time

        for _ in range(50):
            if h2.store.charged_bytes(PK):
                break
            time.sleep(0.1)
        assert h2.store.charged_bytes(PK) == len(data) + pack, "the file and the pack are both charged"
    finally:
        h2.stop()


# ------------------------------------------------------------------ history rules

def test_a_commit_that_does_not_descend_from_the_branch_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    run(gpush(hub, root, tmp_path / "s1"))
    other = make_repo(tmp_path, "other", files={"unrelated.txt": b"x\n"})
    code, err, msg = send(hub, raw_body(other, rows=(("unrelated.txt", 2, hashlib.sha256(b"x\n").hexdigest(), None),), seq=2))
    assert (code, err) == (409, "NotFastForward"), msg
    assert httpx.get(f"{hub.url}/api/models/{REPO}/revision/main", timeout=30).json()["sha"] == git(root, "rev-parse", "HEAD")


def test_a_rewrite_needs_both_the_publisher_and_the_hub_to_ask_for_it(tmp_path):
    for allow in (False, True):
        root = make_repo(tmp_path, f"work{allow}", files=FILES)
        commit(root, {"more.txt": b"m\n"}, message="two")
        older = git(root, "rev-parse", "HEAD~1")
        h = Hub(tmp_path, f"hub{allow}", publish_allow_force=allow)
        try:
            run(gpush(h, root, tmp_path / f"a{allow}"))
            git(root, "reset", "-q", "--hard", older)
            git(root, "commit", "-q", "--allow-empty", "-m", "rewritten history")
            plain = send(h, prepare_git(SK, REPO, root, tmp_path / f"b{allow}", seq=2, have=[]).body)
            assert (plain[0], plain[1]) == (409, "NotFastForward"), "without force it is refused whatever the hub allows"
            forced = send(h, prepare_git(SK, REPO, root, tmp_path / f"c{allow}", seq=3, have=[], force=True).body)
            assert (forced[0] == 202) is allow, forced
            if not allow:
                assert forced[1] == "NotFastForward" and "does not allow" in forced[2]
        finally:
            h.stop()


def test_two_publications_racing_on_one_branch_cannot_both_win(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    run(gpush(hub, root, tmp_path / "s1"))
    base = git(root, "rev-parse", "HEAD")
    a = commit(root, {"a.txt": b"a\n"}, message="a")
    git(root, "checkout", "-q", "-b", "side", base)
    b = commit(root, {"b.txt": b"b\n"}, message="b")
    pa = prepare_git(SK, REPO, root, tmp_path / "sa", rev=a, seq=2, have=[base])
    pb = prepare_git(SK, REPO, root, tmp_path / "sb", rev=b, seq=3, have=[base])
    ra, rb = send(hub, pa.body), send(hub, pb.body)
    assert ra[0] == 202 and rb[0] in (202, 409)
    import time

    time.sleep(2)  # let any job still running finish
    top = httpx.get(f"{hub.url}/api/thub/git/{REPO}/refs", timeout=30).json()["refs"]["main"]
    perm = hub.app.state.ingest._perm_repo(REPO)
    assert git(perm, "rev-parse", "refs/heads/main") == top and top in (a, b)
    loser = b if top == a else a
    assert subprocess.run(["git", "-C", str(perm), "merge-base", "--is-ancestor", loser, top]).returncode != 0, "one history won; the other did not merge in"
    assert httpx.get(f"{hub.url}/api/models/{REPO}/revision/main", timeout=30).json()["sha"] == top


def test_the_branch_is_checked_again_just_before_it_moves(hub, tmp_path):
    from torrenthub.manifest import verify_manifest as vm
    from torrenthub.publish import PublishError

    root = make_repo(tmp_path, files=FILES)
    run(gpush(hub, root, tmp_path / "s1"))
    base = git(root, "rev-parse", "HEAD")
    a = commit(root, {"a.txt": b"a\n"}, message="a")
    git(root, "checkout", "-q", "-b", "side", base)
    b = commit(root, {"b.txt": b"b\n"}, message="b")
    ing = hub.app.state.ingest
    pub_b = prepare_git(SK, REPO, root, tmp_path / "sb", rev=b, seq=3, have=[base])
    mb = vm(pub_b.manifest, {PK}, REPO, table=None)
    work = ing._git_check(mb, base64.b64decode(pub_b.body["git"]["pack"]))  # passes: the branch is still at `base`
    try:
        hub.store.put_commit(REPO, "main", a, hub.store.get_commit_info(REPO, base), hub.store.list_files(REPO, base))  # another publication lands first
        with pytest.raises(PublishError) as e:
            ing._git_finish(mb, work)
        assert e.value.code == "NotFastForward"
        assert not ing._perm_repo(REPO).joinpath("refs/heads/main").exists() or git(ing._perm_repo(REPO), "rev-parse", "refs/heads/main") != b
    finally:
        shutil.rmtree(work.tmp, ignore_errors=True)


def test_the_hub_checks_the_history_is_complete_even_if_indexing_did_not(hub, tmp_path, monkeypatch):
    def lenient(repo, pack, *, max_pack, timeout=60.0):  # as if git's own strict check had let it through
        G.run_git(["index-pack", "--stdin", "--fix-thin"], cwd=repo, stdin=pack, sandbox=True)
        return next(p.stem[5:] for p in (repo / "objects" / "pack").glob("pack-*.pack"))

    monkeypatch.setattr(G, "index_pack", lenient)
    root = make_repo(tmp_path, files=FILES)
    parent = git(root, "rev-parse", "HEAD")
    commit(root, {"more.txt": b"m\n"}, message="child")
    rows = tuple(sorted((p, len(d), hashlib.sha256(d).hexdigest(), None) for p, d in {**FILES, "more.txt": b"m\n"}.items()))
    code, err, msg = send(hub, raw_body(root, rows=rows, have=[parent]))
    assert (code, err) == (400, "BadGit") and "not complete" in msg, msg


# ------------------------------------------------------------------ hostile objects

def test_a_symlink_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    os.symlink("/etc/passwd", root / "link")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "link")
    code, err, msg = send(hub, raw_body(root))
    assert (code, err) == (400, "BadGit") and "symbolic" in msg
    with pytest.raises(ValueError, match="symbolic"):
        prepare_git(SK, REPO, root, tmp_path / "s")


def test_a_submodule_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    git(root, "update-index", "--add", "--cacheinfo", f"160000,{'ab' * 20},sub")
    git(root, "commit", "-q", "-m", "submodule")
    code, err, msg = send(hub, raw_body(root))
    assert (code, err) == (400, "BadGit") and "submodule" in msg


def test_paths_that_collide_on_a_case_insensitive_disk_are_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    blob = git(root, "hash-object", "-w", "--stdin", input=b"x\n")
    for p in ("Model.txt", "model.txt"):
        git(root, "update-index", "--add", "--cacheinfo", f"100644,{blob},{p}")
    git(root, "commit", "-q", "-m", "case")
    code, err, msg = send(hub, raw_body(root))
    assert (code, err) == (400, "BadGit") and "case" in msg


def test_a_big_file_committed_straight_into_git_is_refused(tmp_path):
    h = Hub(tmp_path, publish_git_blob_max=1024 * 1024)
    try:
        root = make_repo(tmp_path, files={"big.bin": os.urandom(1_500_000)})
        code, err, msg = send(h, raw_body(root))
        assert (code, err) == (400, "BadGit") and "LFS pointer" in msg
    finally:
        h.stop()


def test_a_pointer_that_is_nearly_right_is_refused_not_guessed_at(hub, tmp_path):
    root = make_repo(tmp_path, files={"w.bin": b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"A" * 64 + b"\nsize 10\n"})
    code, err, msg = send(hub, raw_body(root))
    assert (code, err) == (400, "BadGit") and "LFS pointer" in msg


def test_a_manifest_whose_table_is_not_the_commits_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    rows = G.derive(root, G.local_commit(root, "HEAD"), blob_max=1 << 20, small_total=1 << 20, max_files=100, sandbox=False).rows
    lie = tuple(sorted((p, s, ("ab" * 32 if p == "config.json" else x), b) for p, s, x, b in rows))
    code, err, msg = send(hub, raw_body(root, rows=lie))
    assert (code, err) == (400, "BadGit") and "file table" in msg


def test_a_pack_missing_the_history_it_needs_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    parent = git(root, "rev-parse", "HEAD")
    commit(root, {"more.txt": b"m\n"}, message="child")
    rows = tuple(sorted((p, len(d), hashlib.sha256(d).hexdigest(), None) for p, d in {**FILES, "more.txt": b"m\n"}.items()))
    code, err, msg = send(hub, raw_body(root, rows=rows, have=[parent]))
    assert (code, err) == (400, "BadGit") and ("expected object" in msg or "not complete" in msg or "not in the pack" in msg), msg


def test_something_that_is_not_a_pack_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    body = raw_body(root)
    body["git"]["pack"] = base64.b64encode(b"this is not a pack").decode()
    assert send(hub, body)[:2] == (400, "BadGit")
    body["git"]["pack"] = base64.b64encode(b"PACK" + os.urandom(200)).decode()
    assert send(hub, body)[:2] == (400, "BadGit")


def test_a_pack_over_the_limit_is_refused(tmp_path):
    h = Hub(tmp_path, publish_git_max_pack=2000)
    try:
        root = make_repo(tmp_path, files={"big.txt": os.urandom(5000)})
        code, err, msg = send(h, raw_body(root))
        assert (code, err) == (400, "BadGit") and "at most" in msg
    finally:
        h.stop()


def test_a_pack_that_inflates_is_stopped_by_the_time_limit(tmp_path):
    h = Hub(tmp_path, publish_git_timeout=0.05, publish_git_blob_max=1 << 30)
    try:
        root = make_repo(tmp_path, files={"a.txt": b"a\n"})
        (root / "zeros.bin").write_bytes(bytes(256 * 1024 * 1024))
        git(root, "add", "zeros.bin")
        git(root, "commit", "-q", "-m", "zeros")
        body = raw_body(root)
        assert len(base64.b64decode(body["git"]["pack"])) < 1024 * 1024, "a quarter of a gigabyte of zeros packs to under a megabyte"
        code, err, msg = send(h, body)
        assert (code, err) == (400, "BadGit") and "took longer" in msg, msg
        assert not list((h.store.root / "tmp").glob("git-*")) and not h.app.state.ingest._perm_repo(REPO).exists()
    finally:
        h.stop()


def test_the_head_must_be_the_manifests_commit(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    body = raw_body(root)
    body["git"]["head"] = "ab" * 20
    assert send(hub, body)[:2] == (400, "BadRequest")


def test_a_manifest_that_misstates_the_tree_or_parents_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    head = G.local_commit(root, "HEAD")
    rows = tuple(sorted((p, len(d), hashlib.sha256(d).hexdigest(), None) for p, d in FILES.items()))
    ev = build_git_manifest(SK, REPO, head, "cd" * 20, [], rows, ["main"], seq=1)
    body = {"manifest": ev, "inline": {}, "torrents": {}, "git": {"head": head, "pack": base64.b64encode(G.make_pack(root, head, [])).decode()}}
    code, err, msg = send(hub, body)
    assert (code, err) == (400, "BadGit") and "tree and parents" in msg


def test_a_bad_branch_name_is_refused(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    code, err, msg = send(hub, raw_body(root, refs=("../../escape",)))
    assert (code, err) == (400, "BadManifest")


def test_a_repo_cannot_switch_between_git_and_plain(hub, tmp_path):
    from tests.test_publish import FILES as PLAIN, push

    run(push(hub, tmp_path, PLAIN))
    root = make_repo(tmp_path, files=FILES)
    code, err, msg = send(hub, prepare_git(SK, REPO, root, tmp_path / "s", seq=2).body)
    assert (code, err) == (409, "WrongKind")


def test_a_hub_without_git_publishing_says_so(tmp_path):
    h = Hub(tmp_path, publish_git=False)
    try:
        root = make_repo(tmp_path, files=FILES)
        assert send(h, prepare_git(SK, REPO, root, tmp_path / "s").body)[:2] == (501, "NoGit")
    finally:
        h.stop()


def test_an_unauthorised_key_cannot_publish_git_either(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    other = bytes.fromhex("00" * 31 + "2b")
    assert send(hub, prepare_git(other, REPO, root, tmp_path / "s").body)[:2] == (403, "NotAuthorised")


def test_a_failed_publication_leaves_no_git_state(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    send(hub, {**raw_body(root), "git": {"head": "x", "pack": ""}})
    ing = hub.app.state.ingest
    assert not ing._perm_repo(REPO).exists()
    assert not [p for p in (hub.store.root / "tmp").glob("git-*")], "the throwaway repository is removed"


def test_a_stale_seq_is_refused_before_any_git_runs(hub, tmp_path, monkeypatch):
    root = make_repo(tmp_path, files=FILES)
    run(gpush(hub, root, tmp_path / "s1"))
    commit(root, {"x.txt": b"x\n"})
    called = []
    monkeypatch.setattr(G, "index_pack", lambda *a, **k: called.append(1))
    code, err, _ = send(hub, prepare_git(SK, REPO, root, tmp_path / "s2", seq=1).body)
    assert (code, err) == (409, "StaleSeq") and not called


# ------------------------------------------------------------------ the publisher's side

def test_the_publisher_refuses_a_big_file_that_is_not_what_the_pointer_names(tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    (root / "weights.bin").write_bytes(BIG[:-1] + b"X")
    with pytest.raises(ValueError, match="does not hash"):
        prepare_git(SK, REPO, root, tmp_path / "s")


def test_the_publisher_says_where_it_looked_when_a_big_file_is_missing(tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    (root / "weights.bin").unlink()
    with pytest.raises(ValueError, match="working tree"):
        prepare_git(SK, REPO, root, tmp_path / "s")
    folder = tmp_path / "elsewhere"
    folder.mkdir()
    (folder / "weights.bin").write_bytes(BIG)
    assert prepare_git(SK, REPO, root, tmp_path / "s2", extra_dirs=[folder]).torrents


def test_the_publisher_finds_a_big_file_in_the_git_lfs_cache(tmp_path):
    root = make_repo(tmp_path, files=FILES, big={"weights.bin": BIG})
    (root / "weights.bin").unlink()
    oid = hashlib.sha256(BIG).hexdigest()
    cache = root / ".git" / "lfs" / "objects" / oid[:2] / oid[2:4]
    cache.mkdir(parents=True)
    (cache / oid).write_bytes(BIG)
    assert list(prepare_git(SK, REPO, root, tmp_path / "s").torrents) == [oid]


def test_the_working_tree_is_not_published_only_the_commit(hub, tmp_path):
    root = make_repo(tmp_path, files=FILES)
    (root / "README.md").write_bytes(b"uncommitted edit\n")
    (root / "untracked.txt").write_bytes(b"not in git\n")
    run(gpush(hub, root, tmp_path / "s"))
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/README.md", timeout=30).content == FILES["README.md"]
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/untracked.txt", timeout=30).status_code == 404


# ------------------------------------------------------------------ the git layer on its own

def test_pointer_parsing_is_strict():
    oid = "ab" * 32
    good = f"version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 12\n".encode()
    assert G.parse_pointer(good) == (oid, 12)
    assert G.parse_pointer(b"just a file\n") is None
    for bad in (good + b"ext-0-x sha256:1\n", good.replace(b"size 12", b"size 012"), good.replace(oid.encode(), oid.upper().encode()),
                good.rstrip(b"\n"), good.replace(b"\n", b"\r\n"), good.replace(b"size 12", b"size -1")):
        with pytest.raises(G.GitError):
            G.parse_pointer(bad)


def test_ref_names():
    assert all(G.valid_ref(r) for r in ("main", "v1.0", "release/2024", "a_b-c"))
    assert not any(G.valid_ref(r) for r in ("", "..", "a/../b", "/x", "x/", "-x", "a.lock", "a b", "x" * 80, "a\n", "refs/../x", None))


def test_manifest_v3_round_trips_and_notices_tampering():
    rows = (("a", 1, "11" * 32, None), ("b", 2, "22" * 32, None))
    ev = build_git_manifest(SK, REPO, "aa" * 20, "bb" * 20, ["cc" * 20], rows, ["main"], seq=3)
    m = verify_manifest(ev, {PK}, REPO)
    assert m.git == {"tree": "bb" * 20, "parents": ["cc" * 20], "force": False} and m.rows == rows and m.seq == 3
    big = tuple((f"f{i:04d}", i, f"{i:064x}", None) for i in range(300))
    ev2 = build_git_manifest(SK, REPO, "aa" * 20, "bb" * 20, [], big, ["main"], seq=1)
    m2 = verify_manifest(ev2, {PK}, REPO)
    assert m2.needs_table and m2.files_x
    from torrenthub.manifest import table_bytes, with_table

    assert with_table(m2, table_bytes(big)).rows == big
    body = json.loads(ev["content"])
    body["table_sha256"] = "00" * 32
    from torrenthub import signing as sg

    forged = sg.sign_event(SK, ev["kind"], ev["tags"], json.dumps(body, separators=(",", ":"), sort_keys=True), ev["created_at"])
    with pytest.raises(ManifestInvalid, match="table_sha256"):
        verify_manifest(forged, {PK}, REPO)
    body = json.loads(ev["content"])
    del body["git"]
    with pytest.raises(ManifestInvalid, match="git field"):
        verify_manifest(sg.sign_event(SK, ev["kind"], ev["tags"], json.dumps(body, separators=(",", ":"), sort_keys=True), ev["created_at"]), {PK}, REPO)
