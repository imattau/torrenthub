"""Phase 4: a source of truth that does not depend on any hub.

The anchor is the origin. Repo metadata (the expected hashes) comes only from it, and hubs
supply torrents and bytes that are checked against what the anchor said. The lockfile pins
commits you have already seen, so a later change of mind by any upstream is refused.
"""

from __future__ import annotations

import json

import httpx
import pytest
from huggingface_hub import snapshot_download

from tests.conftest import free_port
from tests.fake_upstream import REPO
from tests.helpers import SMALL_FILES_BUDGET, assert_repo_equals, warm_hub
from tests.test_federation import LIE, lie_about_big_file, netloc
from torrenthub.config import Settings, effective_anchor
from torrenthub.lock import Lockfile
from torrenthub.upstream import HubError, Upstream, UpstreamSet, make_upstream

pytest.importorskip("libtorrent")


# ------------------------------------------------------------------ anchor

def test_a_hub_that_lies_about_hashes_is_ignored_when_there_is_an_anchor(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url, ref_ttl=3600)
    data, sha = warm_hub(hub, upstream)
    lie_about_big_file(hub, upstream)
    hits_after_warm = dict(upstream.app.state.file_hits)

    agent = nodes(
        "agent", hub.url, anchor=upstream.url,
        peers=[hub.endpoint], swarm_first=True, swarm_stall=10,
    )
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    m = agent.metrics
    assert m.get("thub_upstream_requests_total", upstream=netloc(upstream.url), kind="anchor", result="ok") >= 1
    assert m.get("thub_upstream_requests_total", upstream=netloc(hub), kind="meta", result="ok") == 0, \
        "the hub was asked for metadata"
    assert upstream.app.state.file_hits == hits_after_warm, "the origin served file bytes"
    assert m.get("thub_bytes_fetched_total", source="swarm") == len(data)
    assert not agent.store.blob_complete(LIE)


def test_without_an_anchor_the_same_lying_hub_is_believed(nodes, upstream):
    """The control for the test above."""
    hub = nodes("hub", upstream.url, ref_ttl=3600)
    warm_hub(hub, upstream)
    lie_about_big_file(hub, upstream)
    agent = nodes("agent", hub.url)
    doc = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30).json()
    big = next(s for s in doc["siblings"] if s["rfilename"] == "model.safetensors")
    assert big["lfs"]["sha256"] == LIE


def test_a_hub_serving_bad_bytes_under_honest_metadata_is_still_caught(nodes, upstream):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    bad = bytearray(data)
    bad[len(bad) // 2] ^= 0xFF
    hub.store.blob_path(sha).write_bytes(bytes(bad))  # the hub's copy is corrupted

    agent = nodes("agent", hub.url, anchor=upstream.url)
    try:
        got = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60).content
    except httpx.HTTPError:
        got = None
    assert got is None or len(got) < len(bad), "a complete corrupt file reached the client"
    assert agent.metrics.get("thub_integrity_failures_total", source="upstream") == 1
    assert not agent.store.blob_complete(sha)


def test_anchor_down_refuses_new_metadata_by_default(nodes, upstream):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    dead = f"http://127.0.0.1:{free_port()}"
    agent = nodes("agent", hub.url, anchor=dead)
    r = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)
    assert r.status_code == 502 and r.headers["x-error-code"] == "UpstreamUnavailable"
    assert "anchor" in r.headers["x-error-message"]
    assert agent.metrics.get("thub_anchor_unavailable_total") == 1


def test_anchor_down_can_fall_back_to_the_hub_when_allowed(nodes, upstream):
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    dead = f"http://127.0.0.1:{free_port()}"
    agent = nodes("agent", hub.url, anchor=dead, anchor_required=False)
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)
    assert r.status_code == 200 and r.content == data
    assert agent.metrics.get("thub_anchor_skipped_total") >= 1


def test_metadata_already_stored_survives_the_anchor_going_away(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    agent = nodes("agent", hub.url, anchor=upstream.url)
    snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c1"), token=False)
    upstream.stop()
    hub.stop()
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c2"), token=False)
    assert_repo_equals(local, upstream.app.state.files)


def test_anchor_404_is_a_404_even_if_a_hub_has_the_repo(nodes, upstream):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    agent = nodes("agent", hub.url, anchor=upstream.url)
    r = httpx.get(f"{agent.url}/api/models/acme/other/revision/main", timeout=30)
    assert r.status_code == 404


# ------------------------------------------------------------------ anchor setup

def test_agent_mode_defaults_to_huggingface_as_the_anchor():
    s = Settings(data_dir="x", swarm_first=True)
    assert effective_anchor(s) == "https://huggingface.co"
    assert effective_anchor(Settings(data_dir="x")) == ""
    assert effective_anchor(Settings(data_dir="x", swarm_first=True, anchor="")) == ""
    assert effective_anchor(Settings(data_dir="x", anchor="https://o.example")) == "https://o.example"


def test_make_upstream_with_an_anchor():
    s = Settings(data_dir="x", upstreams=["http://hub:1"], anchor="http://origin:2")
    u = make_upstream(s)
    assert isinstance(u, UpstreamSet) and u.anchor.base_url == "http://origin:2"
    assert [x.base_url for x in u.sources] == ["http://hub:1"]
    # The anchor listed among the upstreams is not asked twice, and alone it is just an Upstream.
    only = make_upstream(Settings(data_dir="x", upstreams=["http://origin:2"], anchor="http://origin:2"))
    assert isinstance(only, Upstream)
    both = make_upstream(Settings(data_dir="x", upstreams=["http://hub:1", "http://origin:2"], anchor="http://origin:2"))
    assert [x.base_url for x in both.sources] == ["http://hub:1"]


def test_anchor_environment(monkeypatch):
    monkeypatch.setenv("THUB_ANCHOR", "https://o.example/")
    monkeypatch.setenv("THUB_ANCHOR_REQUIRED", "false")
    monkeypatch.setenv("THUB_LOCKFILE", "/tmp/x.lock")
    monkeypatch.setenv("THUB_LOCK_MODE", "strict")
    s = Settings.from_env()
    assert (s.anchor, s.anchor_required, str(s.lockfile), s.lock_mode) == ("https://o.example", False, "/tmp/x.lock", "strict")
    monkeypatch.setenv("THUB_ANCHOR", "none")
    assert Settings.from_env().anchor == ""
    monkeypatch.delenv("THUB_ANCHOR")
    assert Settings.from_env().anchor is None


# ------------------------------------------------------------------ lockfile

def honest_info(upstream):
    r = httpx.get(f"{upstream.url}/api/models/{REPO}/revision/main", params={"blobs": "true"}, timeout=30)
    return r.json()


def test_lockfile_catches_a_hub_that_changes_its_answer_later(nodes, upstream, tmp_path):
    lock = tmp_path / "thub.lock"
    Lockfile(lock).add(REPO, honest_info(upstream))  # recorded from the origin while it was honest

    hub = nodes("hub", upstream.url, ref_ttl=3600)
    warm_hub(hub, upstream)
    lie_about_big_file(hub, upstream)
    agent = nodes("agent", hub.url, lockfile=lock)

    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=30)
    assert r.status_code == 502 and r.headers["x-error-code"] == "LockMismatch"
    assert agent.metrics.get("thub_lock_refused_total") == 1
    assert not agent.store.blob_complete(LIE)


def test_lockfile_passes_matching_metadata(nodes, upstream, tmp_path):
    lock = tmp_path / "thub.lock"
    Lockfile(lock).add(REPO, honest_info(upstream))
    agent = nodes("agent", upstream.url, lockfile=lock)
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)
    assert_repo_equals(local, upstream.app.state.files)
    assert agent.metrics.get("thub_lock_refused_total") == 0


def test_strict_mode_refuses_unknown_commits(nodes, upstream, tmp_path):
    agent = nodes("agent", upstream.url, lockfile=tmp_path / "thub.lock", lock_mode="strict")
    r = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)
    assert r.status_code == 403 and r.headers["x-error-code"] == "NotLocked"


def test_record_mode_adds_new_commits_and_then_enforces_them(tmp_path):
    info = {"sha": "a" * 40, "siblings": [{"rfilename": "w.bin", "size": 5, "blobId": "b" * 40}]}
    path = tmp_path / "x.lock"
    lf = Lockfile(path, "record")
    assert lf.check("o/r", info) is True  # recorded
    assert lf.check("o/r", info) is False  # already known, matches
    changed = json.loads(json.dumps(info))
    changed["siblings"][0]["blobId"] = "c" * 40
    with pytest.raises(HubError) as e:
        lf.check("o/r", changed)
    assert e.value.code == "LockMismatch"
    again = Lockfile(path, "verify")  # persisted, and a fresh reader enforces it
    assert "o/r@" + "a" * 40 in again.entries
    with pytest.raises(HubError):
        again.check("o/r", changed)


def test_verify_mode_lets_unknown_commits_through_without_recording(tmp_path):
    info = {"sha": "d" * 40, "siblings": []}
    lf = Lockfile(tmp_path / "x.lock", "verify")
    assert lf.check("o/r", info) is False
    assert not (tmp_path / "x.lock").exists()


def test_lockfile_add_refuses_to_overwrite_and_rejects_bad_files(tmp_path):
    info = {"sha": "e" * 40, "siblings": [{"rfilename": "a", "size": 1, "blobId": "f" * 40}]}
    lf = Lockfile(tmp_path / "x.lock")
    assert lf.add("o/r", info) is True and lf.add("o/r", info) is False
    other = {"sha": "e" * 40, "siblings": []}
    with pytest.raises(HubError):
        lf.add("o/r", other)
    bad = tmp_path / "bad.lock"
    bad.write_text('{"version": 9, "commits": {}}')
    with pytest.raises(ValueError):
        Lockfile(bad)
    with pytest.raises(ValueError):
        Lockfile(tmp_path / "y.lock", "nonsense")


# ------------------------------------------------------------------ per repo trust

from torrenthub.config import parse_trust  # noqa: E402

OWN = "acme/mine"


def test_parse_trust():
    assert parse_trust("acme/*=hub, *=anchor-or-hub") == [("acme/*", "hub"), ("*", "anchor-or-hub")]
    assert parse_trust(None) == []
    for bad in ("acme/*", "acme/*=nonsense", "=hub"):
        with pytest.raises(ValueError):
            parse_trust(bad)


def test_a_rule_needing_an_anchor_without_one_is_a_startup_error():
    with pytest.raises(ValueError):
        UpstreamSet([Upstream("http://h:1")], trust=[("*", "anchor")])


def test_rule_order_and_default():
    u = UpstreamSet([Upstream("http://h:1")], anchor=Upstream("http://o:2"),
                    trust=[("acme/*", "hub"), ("acme/x", "anchor")])
    assert u.mode_for("acme/x") == "hub"  # first match wins
    assert u.mode_for("other/y") == "anchor"  # default with an anchor
    assert UpstreamSet([Upstream("http://h:1")]).mode_for("any/thing") == "hub"


def test_a_repo_the_anchor_lacks_is_a_404_by_default_but_served_when_the_rule_allows(nodes, upstream, tmp_path):
    """The hub holds a repo that the origin has never heard of (a user's own repo)."""
    mine = nodes("mine", upstream.url, ref_ttl=3600)
    warm_hub(mine, upstream)
    commit = upstream.app.state.commit
    info = mine.store.get_commit_info(REPO, commit)
    from torrenthub.mirror import files_from_info
    mine.store.put_commit(OWN, "main", commit, info, files_from_info(info))
    # (the blobs are shared by key, so the hub can serve OWN's files)

    closed = nodes("closed", mine.url, anchor=upstream.url)
    assert httpx.get(f"{closed.url}/api/models/{OWN}/revision/main", timeout=30).status_code == 404

    lock = tmp_path / "t.lock"
    open_ = nodes("open", mine.url, anchor=upstream.url, trust=[("acme/mine", "anchor-or-hub")], lockfile=lock)
    r = httpx.get(f"{open_.url}/api/models/{OWN}/revision/main", timeout=30)
    assert r.status_code == 200
    assert r.headers["x-thub-source"] == "hub"
    assert open_.metrics.get("thub_metadata_source_total", source="hub") == 1
    # Unvouched tables are pinned on first sight, even in the default verify mode.
    assert f"{OWN}@{commit}" in Lockfile(lock).entries

    # A real repo still goes through the anchor, and says so.
    r2 = httpx.get(f"{open_.url}/api/models/{REPO}/revision/main", timeout=30)
    assert r2.status_code == 200 and r2.headers["x-thub-source"] == "anchor"
    assert open_.store.get_source(REPO, upstream.app.state.commit) == "anchor"


def test_unvouched_repo_that_later_appears_on_the_anchor_with_other_contents_is_refused(tmp_path):
    """Name squatting: the hub's first answer was pinned, so a different table later is refused."""
    lf = Lockfile(tmp_path / "t.lock", "verify")
    first = {"sha": "1" * 40, "siblings": [{"rfilename": "w", "size": 1, "blobId": "a" * 40}]}
    assert lf.check("o/r", first, record_unknown=True) is True
    squat = {"sha": "1" * 40, "siblings": [{"rfilename": "w", "size": 1, "blobId": "b" * 40}]}
    with pytest.raises(HubError):
        lf.check("o/r", squat)


def test_hub_rule_never_asks_the_anchor(nodes, upstream):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    agent = nodes("agent", hub.url, anchor=upstream.url, trust=[("*", "hub")])
    r = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)
    assert r.status_code == 200 and r.headers["x-thub-source"] == "hub"
    assert agent.metrics.get("thub_upstream_requests_total", upstream=netloc(upstream.url), kind="anchor", result="ok") == 0


def test_anchor_down_with_anchor_or_hub_is_still_refused_not_treated_as_missing(nodes, upstream):
    """Unreachable is not the same as absent. Falling through here would let an outage
    switch the protection off."""
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    dead = f"http://127.0.0.1:{free_port()}"
    agent = nodes("agent", hub.url, anchor=dead, trust=[("*", "anchor-or-hub")])
    r = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)
    assert r.status_code == 502


def test_a_stronger_source_is_not_overwritten_by_a_weaker_one(nodes, upstream):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    agent = nodes("agent", hub.url, anchor=upstream.url)
    httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)
    c = upstream.app.state.commit
    agent.store.set_source(REPO, c, "hub")
    assert agent.store.get_source(REPO, c) == "anchor"
