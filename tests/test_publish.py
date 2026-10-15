"""Publishing: a signed repo that exists nowhere else gets onto a hub and out to an agent, verified."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time

import httpx
import pytest

pytest.importorskip("libtorrent")

from huggingface_hub import snapshot_download  # noqa: E402

from tests.conftest import Server, free_port  # noqa: E402
from torrenthub import signing as sg  # noqa: E402
from torrenthub.app import create_app  # noqa: E402
from torrenthub.config import Settings  # noqa: E402
from torrenthub.federation import fingerprint  # noqa: E402
from torrenthub.manifest import build_manifest, content_commit  # noqa: E402
from torrenthub.publisher import prepare, publish  # noqa: E402
from torrenthub.swarm import LibtorrentSwarm  # noqa: E402
from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length  # noqa: E402

SK = bytes.fromhex("00" * 31 + "2a")
PK = sg.public_key(SK).hex()
OTHER = bytes.fromhex("00" * 31 + "2b")
REPO = "acme/pub"

BIG = os.urandom(3 * 1024 * 1024 + 123)
FILES = {"config.json": b'{"hidden": 8}\n', "README.md": b"# a published model\n", "weights.bin": BIG}


def write_tree(root, files):
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


class Hub:
    def __init__(self, tmp_path, name="hub", roots=(PK,), quota=100 * 1024 * 1024, **kw):
        sp = free_port()
        self.swarm = LibtorrentSwarm(listen_port=sp, listen_host="127.0.0.1", dht=False)
        port = free_port()
        self.settings = Settings(data_dir=tmp_path / name, upstream="http://127.0.0.1:9", public_url=f"http://127.0.0.1:{port}",
                                 roots=list(roots), anchor="", listen_port=sp, publish_quota=quota, **kw)
        self.app = create_app(self.settings, swarm=self.swarm)
        self.srv = Server(self.app, port).start()
        self.url = self.srv.url
        self.store = self.app.state.store

    def stop(self):
        self.srv.stop()


@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0)
    yield h
    h.stop()


def publisher_swarm():
    return LibtorrentSwarm(listen_port=free_port(), listen_host="127.0.0.1", dht=False)


async def push(hub, tmp_path, files, *, secret=SK, repo=REPO, seq=1, name="src", **kw):
    root = write_tree(tmp_path / name, files)
    pub = prepare(secret, repo, root, tmp_path / f"stage-{name}-{seq}", seq=seq, **kw)
    sw = publisher_swarm()
    try:
        return pub, await publish(hub.url, pub, sw, timeout=60, poll=0.3)
    finally:
        await sw.close()


def run(coro):
    import asyncio

    return asyncio.run(coro)


def post(hub, body):
    return httpx.post(f"{hub.url}/api/thub/publish", json=body, timeout=30)


# ------------------------------------------------------------------ the happy path

def test_a_publication_reaches_the_hub_and_downloads_verified(hub, tmp_path):
    pub, st = run(push(hub, tmp_path, FILES))
    assert st["state"] == "done" and st["commit"] == pub.commit
    info = httpx.get(f"{hub.url}/api/models/{REPO}/revision/main", timeout=30).json()
    assert info["sha"] == pub.commit and sorted(s["rfilename"] for s in info["siblings"]) == sorted(FILES)
    assert all(s["lfs"]["sha256"] == hashlib.sha256(FILES[s["rfilename"]]).hexdigest() for s in info["siblings"])
    local = snapshot_download(REPO, endpoint=hub.url, cache_dir=str(tmp_path / "dl"), token=False)
    for name, data in FILES.items():
        assert (open(f"{local}/{name}", "rb").read()) == data, name
    mans = httpx.get(f"{hub.url}/api/thub/manifests/{REPO}", timeout=30).json()["events"]
    assert [m["id"] for m in mans] == [pub.manifest["id"]]
    big = hashlib.sha256(BIG).hexdigest()
    assert hub.store.get_blob(big).infohash and hub.store.torrent_path(big).exists(), "the hub can now seed it too"


def test_publishing_the_same_manifest_again_is_a_no_op_and_a_stale_seq_is_refused(hub, tmp_path):
    pub, _ = run(push(hub, tmp_path, FILES))
    again = post(hub, pub.body)
    assert again.status_code == 200 and again.json()["already"] is True
    r = run(_expect_refusal(hub, tmp_path, {**FILES, "README.md": b"changed\n"}, seq=1, name="src2"))
    assert r["status"] == 409 and r["code"] == "StaleSeq"


async def _expect_refusal(hub, tmp_path, files, *, secret=SK, seq=1, name="x", **kw):
    root = write_tree(tmp_path / name, files)
    pub = prepare(secret, REPO, root, tmp_path / f"stage-{name}", seq=seq, **kw)
    r = post(hub, pub.body)
    assert r.status_code >= 400, r.text
    return {"status": r.status_code, "code": r.headers.get("x-error-code"), "message": r.json().get("error", "")}


def test_a_higher_seq_moves_the_branch_and_old_commits_stay_pinnable(hub, tmp_path):
    pub1, _ = run(push(hub, tmp_path, FILES, seq=1))
    v2 = {**FILES, "README.md": b"# version two\n"}
    pub2, _ = run(push(hub, tmp_path, v2, seq=2, name="src2"))
    assert pub1.commit != pub2.commit
    assert httpx.get(f"{hub.url}/api/models/{REPO}/revision/main", timeout=30).json()["sha"] == pub2.commit
    assert httpx.get(f"{hub.url}/api/models/{REPO}/revision/{pub1.commit}", timeout=30).json()["sha"] == pub1.commit
    assert httpx.get(f"{hub.url}/{REPO}/resolve/{pub1.commit}/README.md", timeout=30).content == FILES["README.md"]
    assert httpx.get(f"{hub.url}/{REPO}/resolve/main/README.md", timeout=30).content == b"# version two\n"


def test_a_large_file_table_goes_in_a_blob_and_still_works(hub, tmp_path):
    files = {f"shards/part-{i:04d}.json": b'{"i": %d}\n' % i for i in range(260)}
    pub, st = run(push(hub, tmp_path, files))
    assert "table" in pub.body and st["state"] == "done"
    x = next(t[1] for t in pub.manifest["tags"] if t[0] == "files_x")
    assert httpx.get(f"{hub.url}/blobs/{x}", timeout=30).status_code == 200
    assert len(json.loads(pub.manifest["content"])) < 12, "the event holds the hash, not 260 rows"


# --------------------------------------------------------------------- refusals

def test_publishing_is_off_unless_the_hub_has_a_quota(tmp_path):
    h = Hub(tmp_path, quota=0)
    try:
        r = run(_expect_refusal(h, tmp_path, FILES))
        assert r["status"] == 403 and r["code"] == "PublishingDisabled"
    finally:
        h.stop()


def test_only_authorised_keys_may_publish(hub, tmp_path):
    r = run(_expect_refusal(hub, tmp_path, FILES, secret=OTHER))
    assert r["status"] == 403 and r["code"] == "NotAuthorised"
    assert not hub.store.is_published(REPO)


def test_a_delegate_of_a_root_may_publish_its_scope_only(tmp_path):
    from torrenthub import events as E

    h = Hub(tmp_path, publish_stall=15.0)
    try:
        d = E.build_delegation(SK, sg.public_key(OTHER).hex(), [f"publish:{REPO}"], created_at=int(time.time()) - 10)
        assert httpx.post(f"{h.url}/api/thub/events", json=d, timeout=30).status_code == 200
        pub, st = run(push(h, tmp_path, FILES, secret=OTHER))
        assert st["state"] == "done"
        root = write_tree(tmp_path / "other", FILES)
        other_repo = prepare(OTHER, "acme/else", root, tmp_path / "st-else", seq=1)
        rr = post(h, other_repo.body)
        assert rr.status_code == 403 and rr.headers["x-error-code"] == "NotAuthorised"
    finally:
        h.stop()


def test_a_revoked_publisher_is_refused(tmp_path):
    from torrenthub import events as E

    h = Hub(tmp_path)
    try:
        rev = E.build_revocation(SK, "key", PK, created_at=int(time.time()) - 5)
        # a root revoking itself: its own events stop counting, and so does its right to publish
        httpx.post(f"{h.url}/api/thub/events", json=rev, timeout=30)
        r = run(_expect_refusal(h, tmp_path, FILES))
        assert r["status"] == 403
    finally:
        h.stop()


def test_the_quota_is_enforced_per_key_and_counts_only_new_bytes(tmp_path):
    h = Hub(tmp_path, quota=len(BIG) + 100_000, publish_stall=15.0)
    try:
        pub, st = run(push(h, tmp_path, FILES))
        assert st["state"] == "done" and 0 < h.store.charged_bytes(PK) <= len(BIG) + 100_000
        # the same big file again in a new version costs nothing extra; a second big file does
        run(push(h, tmp_path, {**FILES, "README.md": b"v2\n"}, seq=2, name="s2"))
        r = run(_expect_refusal(h, tmp_path, {**FILES, "other.bin": os.urandom(2_000_000)}, seq=3, name="s3"))
        assert r["status"] == 413 and r["code"] == "QuotaExceeded"
    finally:
        h.stop()


def test_published_blobs_are_never_chosen_for_eviction(hub, tmp_path):
    run(push(hub, tmp_path, FILES))
    big = hashlib.sha256(BIG).hexdigest()
    assert hub.store.get_blob(big).infohash is not None
    assert big not in {b.key for b in hub.store.lru_candidates()}


@pytest.mark.parametrize("what", ["expired", "bad_table", "no_content", "bad_torrent", "wrong_inline", "bad_path", "future", "v1"])
def test_bad_publications_are_refused_before_anything_is_taken(hub, tmp_path, what):
    root = write_tree(tmp_path / "s", FILES)
    pub = prepare(SK, REPO, root, tmp_path / "st", seq=1)
    body = json.loads(json.dumps(pub.body))
    big = hashlib.sha256(BIG).hexdigest()
    small = hashlib.sha256(FILES["README.md"]).hexdigest()
    if what == "expired":
        old = int(time.time()) - 1000
        body = prepare(SK, REPO, root, tmp_path / "st2", seq=1, valid_for=100, created_at=old).body
    elif what == "no_content":
        body["torrents"].pop(big)
    elif what == "wrong_inline":
        body["inline"][small] = base64.b64encode(b"not the signed bytes").decode()
    elif what == "bad_torrent":
        t = base64.b64decode(body["torrents"][big])
        body["torrents"][big] = base64.b64encode(t.replace(b"piece length", b"piece lengtx")).decode()
    elif what == "future":
        body = prepare(SK, REPO, root, tmp_path / "st2", seq=1, created_at=int(time.time()) + 5000).body
    elif what == "v1":
        info = {"sha": "ab" * 20, "siblings": [{"rfilename": "a", "size": 1, "lfs": {"size": 1, "sha256": "cd" * 32}}]}
        body = {"manifest": build_manifest(SK, REPO, info, ["main"]), "inline": {}, "torrents": {}}
    elif what == "bad_path":
        (tmp_path / "t").mkdir()
        (tmp_path / "t" / "ok.txt").write_text("x")
        p2 = prepare(SK, REPO, tmp_path / "t", tmp_path / "st3", seq=1)
        ev = json.loads(p2.manifest["content"])
        ev["files"][0][0] = "../escape.txt"
        # re-sign over the bad path so only the path check can stop it
        info = {"sha": "0" * 40, "siblings": [{"rfilename": "../escape.txt", "size": 1, "lfs": {"size": 1, "sha256": ev["files"][0][2]}}]}
        rows = fingerprint(info)
        info["sha"] = content_commit(rows)
        body = {"manifest": build_manifest(SK, REPO, info, ["main"], seq=1), "inline": {ev["files"][0][2]: base64.b64encode(b"x").decode()}, "torrents": {}}
    elif what == "bad_table":
        files = {f"p{i:04d}": b"%d" % i for i in range(250)}
        p2 = prepare(SK, REPO, write_tree(tmp_path / "many", files), tmp_path / "st4", seq=1)
        body = json.loads(json.dumps(p2.body))
        body["table"] = base64.b64encode(base64.b64decode(body["table"]).replace(b"p0001", b"p0002")).decode()
    r = post(hub, body)
    assert r.status_code in (400, 413), (what, r.status_code, r.text)
    assert not hub.store.is_published(REPO), "nothing becomes visible"
    assert hub.store.count_blobs() == 0, "and no bytes were kept"


def test_what_arrives_must_be_what_was_signed(tmp_path):
    """A publisher signs one file but its torrent describes other bytes: the transfer completes
    (the pieces are consistent with the torrent), the whole file hash does not match, nothing appears."""
    h = Hub(tmp_path, publish_stall=15.0)
    try:
        root = write_tree(tmp_path / "s", FILES)
        pub = prepare(SK, REPO, root, tmp_path / "st", seq=1)
        big = hashlib.sha256(BIG).hexdigest()
        evil = os.urandom(len(BIG))
        ph = PieceHasher(choose_piece_length(len(evil)))
        ph.update(evil)
        data, _ = build_torrent(name=big, length=len(evil), piece_length=choose_piece_length(len(evil)), pieces=ph.finish())
        pub.body["torrents"][big] = base64.b64encode(data).decode()
        (pub.stage / f"{big}.torrent").write_bytes(data)
        (pub.stage / big).unlink()
        (pub.stage / big).write_bytes(evil)
        pub.torrents[big] = (pub.stage / f"{big}.torrent", data)
        with pytest.raises(RuntimeError, match="not the signed sha256"):
            run(_publish_only(h, pub))
        assert not h.store.is_published(REPO) and not h.store.blob_complete(big)
        assert httpx.get(f"{h.url}/api/models/{REPO}/revision/main", timeout=30).status_code >= 400, "nothing is served"
    finally:
        h.stop()


async def _publish_only(hub, pub):
    sw = publisher_swarm()
    try:
        return await publish(hub.url, pub, sw, timeout=60, poll=0.3)
    finally:
        await sw.close()


def test_a_publisher_that_never_connects_is_given_up_on(tmp_path):
    h = Hub(tmp_path, publish_stall=3.0)
    try:
        root = write_tree(tmp_path / "s", FILES)
        pub = prepare(SK, REPO, root, tmp_path / "st", seq=1)
        r = post(h, pub.body)
        assert r.status_code == 202
        job = r.json()["job"]
        deadline = time.time() + 30
        while time.time() < deadline:
            st = httpx.get(f"{h.url}/api/thub/publish/{job}", timeout=30).json()
            if st["state"] != "pulling":
                break
            time.sleep(0.5)
        assert st["state"] == "failed" and "nothing arrived" in st["error"]
        assert not h.store.is_published(REPO)
        assert httpx.get(f"{h.url}/api/thub/publish/nope", timeout=30).status_code == 404
    finally:
        h.stop()


# ------------------------------------------------------------- an agent fetching it

def agent_for(tmp_path, hub, trust=None, **kw):
    port = free_port()
    s = Settings(data_dir=tmp_path / "agent", upstream=hub.url, public_url=f"http://127.0.0.1:{port}", anchor="",
                 trust=trust if trust is not None else [("acme/*", "signed:" + PK)], **kw)
    return Server(create_app(s), port).start()


def test_an_agent_that_pins_the_publisher_fetches_it_fully_verified(hub, tmp_path):
    run(push(hub, tmp_path, FILES))
    ag = agent_for(tmp_path, hub)
    try:
        local = snapshot_download(REPO, endpoint=ag.url, cache_dir=str(tmp_path / "agent-dl"), token=False)
        for name, data in FILES.items():
            assert open(f"{local}/{name}", "rb").read() == data, name
        assert httpx.get(f"{ag.url}/metrics", timeout=30).text.count('thub_manifest_total{result="valid"}') == 1
    finally:
        ag.stop()


def test_an_agent_that_pins_someone_else_refuses_it(hub, tmp_path):
    run(push(hub, tmp_path, FILES))
    ag = agent_for(tmp_path, hub, trust=[("acme/*", "signed:" + sg.public_key(OTHER).hex())])
    try:
        r = httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=30)
        assert r.status_code == 502 and r.headers["x-error-code"] == "NoValidManifest"
    finally:
        ag.stop()


def test_an_agent_resolves_a_table_blob_manifest(hub, tmp_path):
    files = {f"shards/part-{i:04d}.json": b'{"i": %d}\n' % i for i in range(230)}
    pub, _ = run(push(hub, tmp_path, files))
    ag = agent_for(tmp_path, hub)
    try:
        info = httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=60).json()
        assert info["sha"] == pub.commit and len(info["siblings"]) == 230
        assert httpx.get(f"{ag.url}/{REPO}/resolve/main/shards/part-0007.json", timeout=30).content == b'{"i": 7}\n'
    finally:
        ag.stop()


def _inject(hub, secret, files_info, refs, *, seq, created_at, valid_until=None):
    """Put a commit and its manifest straight into a hub's store, as if published."""
    from torrenthub.mirror import files_from_info

    rows = fingerprint(files_info)
    files_info["sha"] = content_commit(rows)
    hub.store.put_commit(REPO, refs[0], files_info["sha"], files_info, files_from_info(files_info))
    ev = build_manifest(secret, REPO, files_info, list(refs), created_at=created_at, seq=seq, valid_until=valid_until)
    hub.store.add_manifest(ev)
    return files_info["sha"]


def _info(name):
    x = hashlib.sha256(name.encode()).hexdigest()
    return {"sha": "0" * 40, "siblings": [{"rfilename": name, "size": 4, "lfs": {"size": 4, "sha256": x}}]}


def test_the_agent_follows_seq_not_the_timestamp_so_a_replayed_old_manifest_loses(hub, tmp_path):
    now = int(time.time())
    new = _inject(hub, SK, _info("new.bin"), ["main"], seq=5, created_at=now - 5000)   # newest by seq, oldest by clock
    old = _inject(hub, SK, _info("old.bin"), ["main"], seq=2, created_at=now - 10)     # a replay with a fresher clock
    assert new != old
    ag = agent_for(tmp_path, hub)
    try:
        assert httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=30).json()["sha"] == new
    finally:
        ag.stop()


def test_an_expired_manifest_is_not_believed_for_a_branch_but_still_for_a_pinned_commit(hub, tmp_path):
    now = int(time.time())
    c = _inject(hub, SK, _info("a.bin"), ["main"], seq=1, created_at=now - 1000, valid_until=now - 10)
    ag = agent_for(tmp_path, hub)
    try:
        r = httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=30)
        assert r.status_code == 502 and r.headers["x-error-code"] == "ManifestExpired"
        assert httpx.get(f"{ag.url}/api/models/{REPO}/revision/{c}", timeout=30).json()["sha"] == c
    finally:
        ag.stop()


def test_a_newer_unexpired_manifest_beats_an_expired_one(hub, tmp_path):
    now = int(time.time())
    _inject(hub, SK, _info("a.bin"), ["main"], seq=1, created_at=now - 1000, valid_until=now - 10)
    good = _inject(hub, SK, _info("b.bin"), ["main"], seq=2, created_at=now - 5, valid_until=now + 1000)
    ag = agent_for(tmp_path, hub)
    try:
        assert httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=30).json()["sha"] == good
    finally:
        ag.stop()


def test_a_maximum_manifest_age_can_be_required(hub, tmp_path):
    now = int(time.time())
    c = _inject(hub, SK, _info("a.bin"), ["main"], seq=1, created_at=now - 5000)
    ag = agent_for(tmp_path, hub, manifest_max_age=600.0)
    try:
        r = httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=30)
        assert r.status_code == 502 and r.headers["x-error-code"] == "ManifestStale"
        assert httpx.get(f"{ag.url}/api/models/{REPO}/revision/{c}", timeout=30).status_code == 200
    finally:
        ag.stop()


def test_the_manifest_age_limit_can_come_from_the_policy_file(hub, tmp_path):
    now = int(time.time())
    c = _inject(hub, SK, _info("a.bin"), ["main"], seq=1, created_at=now - 5000)
    pol = tmp_path / "policy.toml"
    pol.write_text("[freshness]\nmanifest_max_age = '10m'\n")
    ag = agent_for(tmp_path, hub, policy=str(pol))
    try:
        r = httpx.get(f"{ag.url}/api/models/{REPO}/revision/main", timeout=30)
        assert r.status_code == 502 and r.headers["x-error-code"] == "ManifestStale"
        assert httpx.get(f"{ag.url}/api/models/{REPO}/revision/{c}", timeout=30).status_code == 200
    finally:
        ag.stop()
    # the environment setting wins when both are given
    ag2 = agent_for(tmp_path / "second", hub, policy=str(pol), manifest_max_age=100_000.0)
    try:
        assert httpx.get(f"{ag2.url}/api/models/{REPO}/revision/main", timeout=30).json()["sha"] == c
    finally:
        ag2.stop()


def test_a_publishers_torrent_cannot_make_the_hub_contact_anyone_and_the_stored_copy_is_clean(tmp_path):
    import socket
    import threading

    from torrenthub.torrent import bdecode, bencode

    hits = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = time.time() + 40

    def serve():
        srv.settimeout(0.5)
        while time.time() < stop:
            try:
                c, _ = srv.accept()
                hits.append(c.recv(2048).split(b"\r\n")[0])
                c.close()
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()
    h = Hub(tmp_path, publish_stall=15.0, trackers=["udp://tracker.operator.example:1337/announce"])
    try:
        root = write_tree(tmp_path / "s", FILES)
        pub = prepare(SK, REPO, root, tmp_path / "st", seq=1)
        big = hashlib.sha256(BIG).hexdigest()
        meta = bdecode(base64.b64decode(pub.body["torrents"][big]))
        meta.update({b"announce": f"http://127.0.0.1:{port}/announce".encode(), b"url-list": [f"http://127.0.0.1:{port}/web".encode()],
                     b"nodes": [[b"127.0.0.1", port]]})
        evil = bencode(meta)
        pub.body["torrents"][big] = base64.b64encode(evil).decode()  # only what is sent to the hub is hostile; the publisher seeds the clean copy
        assert run(_publish_only(h, pub))["state"] == "done"
        stored = bdecode(h.store.torrent_path(big).read_bytes())
        assert set(stored) == {b"info", b"announce", b"announce-list", b"url-list"}
        assert stored[b"announce"] == b"udp://tracker.operator.example:1337/announce", "only the operator's tracker"
        assert stored[b"url-list"] == [f"{h.settings.public_url}/blobs/{big}".encode()], "only the hub's own web seed"
        assert hits == [], hits
    finally:
        h.stop()
        srv.close()


def test_awkward_file_names_publish_and_download_without_breaking_the_headers(hub, tmp_path):
    from urllib.parse import quote, unquote

    names = {"模型 v2.json": b"{}\n", 'say "hi".txt': b"hi\n", "100% done.txt": b"d\n", "dir/é à.md": b"# e\n"}
    pub, st = run(push(hub, tmp_path, {**names, "config.json": b"{}\n"}))
    assert st["state"] == "done"
    for name, data in names.items():
        r = httpx.get(f"{hub.url}/{REPO}/resolve/main/{quote(name)}", timeout=30)
        assert r.status_code == 200 and r.content == data, name
        cd = r.headers["content-disposition"]
        cd.encode("ascii")
        assert unquote(cd.split("filename*=UTF-8''")[1]) == name.rsplit("/", 1)[-1]
    local = snapshot_download(REPO, endpoint=hub.url, cache_dir=str(tmp_path / "dl"), token=False)
    for name, data in names.items():
        assert open(f"{local}/{name}", "rb").read() == data


def test_a_file_name_with_a_control_character_cannot_be_published(hub, tmp_path):
    import base64
    from torrenthub.federation import fingerprint

    x = hashlib.sha256(b"x").hexdigest()
    for bad in ("a\nb.txt", "a\x00b", "tab\there"):
        info = {"sha": "0" * 40, "siblings": [{"rfilename": bad, "size": 1, "lfs": {"size": 1, "sha256": x}}]}
        info["sha"] = content_commit(fingerprint(info))
        body = {"manifest": build_manifest(SK, REPO, info, ["main"], seq=1), "inline": {x: base64.b64encode(b"x").decode()}, "torrents": {}}
        r = post(hub, body)
        assert r.status_code == 400 and "unsafe path" in r.json()["error"], (bad, r.text)
