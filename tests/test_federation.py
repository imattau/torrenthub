"""Several upstream hubs: failover, agreement between them, and checking a hub against the origin.

Topology: one fake origin ("Hugging Face"), two hubs that each mirror it, and agents whose
upstream list is made of those. Real libtorrent and the real HF client, all on loopback.
"""

from __future__ import annotations

import hashlib
from urllib.parse import urlparse

import httpx
import pytest
from huggingface_hub import snapshot_download

from tests.conftest import free_port
from tests.fake_upstream import REPO
from tests.helpers import SMALL_FILES_BUDGET, assert_repo_equals, warm_hub
from torrenthub.config import Settings
from torrenthub.mirror import files_from_info
from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length
from torrenthub.upstream import Upstream, UpstreamSet, make_upstream

pytest.importorskip("libtorrent")

LIE = "f" * 64


def netloc(node_or_url):
    url = node_or_url if isinstance(node_or_url, str) else node_or_url.url
    return urlparse(url).netloc


def lie_about_big_file(node, upstream):
    """Make a hub tell agents a different sha256 for the big file, as a compromised hub would."""
    commit = upstream.app.state.commit
    info = node.store.get_commit_info(REPO, commit)
    for s in info["siblings"]:
        if s["rfilename"] == "model.safetensors":
            s["lfs"]["sha256"] = LIE
    node.store.put_commit(REPO, "main", commit, info, files_from_info(info))


def two_hubs(nodes, upstream, **kw):
    a = nodes("hubA", upstream.url, **kw)
    b = nodes("hubB", upstream.url, **kw)
    data, sha = warm_hub(a, upstream)
    warm_hub(b, upstream)
    return a, b, data, sha


# ------------------------------------------------------------------ failover

def test_agent_skips_a_dead_first_upstream(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    dead = f"http://127.0.0.1:{free_port()}"

    agent = nodes("agent", dead, upstreams=[dead, hub.url])
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    m = agent.metrics
    assert m.get("thub_upstream_requests_total", upstream=netloc(dead), kind="meta", result="error") >= 1
    assert m.get("thub_upstream_requests_total", upstream=netloc(hub), kind="meta", result="ok") >= 1


def test_file_bytes_fail_over_when_the_first_hub_cannot_supply_them(nodes, upstream):
    """Hub A answers metadata but has taken the file down (451). Hub B has it.

    Failover only happens on a status before any bytes flow. A hub that answers 200 and then
    breaks is not retried on another hub, so this test uses a real refusal."""
    a = nodes("hubA", upstream.url)
    b = nodes("hubB", upstream.url)
    data, sha = warm_hub(b, upstream)
    assert httpx.get(f"{a.url}/api/models/{REPO}/revision/main").status_code == 200  # metadata only
    a.store.add_block(sha, "test takedown")
    upstream.stop()

    agent = nodes("agent", a.url, upstreams=[a.url, b.url])
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)

    assert r.status_code == 200 and r.content == data
    m = agent.metrics
    assert m.get("thub_upstream_requests_total", upstream=netloc(a), kind="file", result="error") == 1
    assert m.get("thub_upstream_requests_total", upstream=netloc(b), kind="file", result="ok") == 1


def test_missing_everywhere_is_a_404_not_a_502(nodes, upstream):
    a, b, *_ = two_hubs(nodes, upstream)
    agent = nodes("agent", a.url, upstreams=[a.url, b.url])
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/no-such-file.bin", timeout=30)
    assert r.status_code == 404 and r.headers["x-error-code"] == "EntryNotFound"


# ------------------------------------------------------------------ agreement

def test_quorum_two_passes_when_both_hubs_agree(nodes, upstream, tmp_path):
    a, b, data, sha = two_hubs(nodes, upstream)
    agent = nodes("agent", a.url, upstreams=[a.url, b.url], quorum=2)
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)
    assert_repo_equals(local, upstream.app.state.files)
    assert agent.metrics.get("thub_metadata_disagreements_total") == 0


def test_quorum_two_refuses_when_one_hub_lies(nodes, upstream):
    a, b, data, sha = two_hubs(nodes, upstream, ref_ttl=3600)
    lie_about_big_file(b, upstream)

    agent = nodes("agent", a.url, upstreams=[a.url, b.url], quorum=2)
    r = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)

    assert r.status_code == 502 and r.headers["x-error-code"] == "UpstreamDisagreement"
    assert agent.metrics.get("thub_metadata_disagreements_total") == 1
    assert not agent.store.blob_complete(sha)


def test_quorum_one_trusts_whichever_hub_answers_first(nodes, upstream):
    """What the quorum is for: with quorum 1 and the liar first, its table is accepted."""
    a, b, data, sha = two_hubs(nodes, upstream, ref_ttl=3600)
    lie_about_big_file(b, upstream)

    agent = nodes("agent", b.url, upstreams=[b.url, a.url], quorum=1)
    doc = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30).json()
    big = next(s for s in doc["siblings"] if s["rfilename"] == "model.safetensors")
    assert big["lfs"]["sha256"] == LIE


def test_a_hub_is_checked_against_the_origin_while_bytes_come_from_peers(nodes, upstream, tmp_path):
    """Upstreams [hub, origin] with quorum 2: the hub cannot lie about hashes, and the origin
    still serves no file bytes. The big file arrives from the hub's swarm."""
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    hits_after_warm = dict(upstream.app.state.file_hits)

    agent = nodes(
        "agent", hub.url, upstreams=[hub.url, upstream.url], quorum=2,
        peers=[hub.endpoint], swarm_first=True, swarm_stall=10,
    )
    before = hub.served()
    local = snapshot_download(REPO, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    assert upstream.app.state.file_hits == hits_after_warm, "the origin served file bytes to the agent"
    assert hub.served() - before < SMALL_FILES_BUDGET
    assert agent.metrics.get("thub_bytes_fetched_total", source="swarm") == len(data)
    assert agent.metrics.get("thub_metadata_disagreements_total") == 0


def test_a_lying_hub_is_caught_by_the_origin(nodes, upstream):
    hub = nodes("hub", upstream.url, ref_ttl=3600)
    data, sha = warm_hub(hub, upstream)
    lie_about_big_file(hub, upstream)

    agent = nodes("agent", hub.url, upstreams=[hub.url, upstream.url], quorum=2)
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=30)

    assert r.status_code == 502 and r.headers["x-error-code"] == "UpstreamDisagreement"
    assert not agent.store.blob_complete(sha) and not agent.store.blob_complete(LIE)


def test_quorum_not_met_because_too_few_upstreams_answer(nodes, upstream):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    dead = f"http://127.0.0.1:{free_port()}"
    agent = nodes("agent", hub.url, upstreams=[hub.url, dead], quorum=2)

    r = httpx.get(f"{agent.url}/api/models/{REPO}/revision/main", timeout=30)
    assert r.status_code == 502 and r.headers["x-error-code"] == "UpstreamUnavailable"
    assert "1 of the 2" in r.headers["x-error-message"]
    assert agent.metrics.get("thub_metadata_disagreements_total") == 0  # unavailable, not contradicted


# ------------------------------------------------------------------ torrents from several hubs

def test_a_bad_torrent_from_the_first_hub_does_not_block_the_second(nodes, upstream):
    a, b, data, sha = two_hubs(nodes, upstream)
    pl = choose_piece_length(len(data))
    h = PieceHasher(pl)
    h.update(data)
    wrong, _ = build_torrent(name="not-the-blob", length=len(data), piece_length=pl, pieces=h.finish())
    a.store.torrent_path(sha).write_bytes(wrong)

    agent = nodes(
        "agent", a.url, upstreams=[a.url, b.url],
        peers=[b.endpoint], swarm_first=True, swarm_stall=10,
    )
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)

    assert r.status_code == 200 and r.content == data
    m = agent.metrics
    assert m.get("thub_torrent_fetch_total", result="rejected") == 1
    assert m.get("thub_torrent_fetch_total", result="ok") == 1
    assert m.get("thub_bytes_fetched_total", source="swarm") == len(data)


def test_independent_hubs_produce_the_same_infohash_so_they_share_one_swarm(nodes, upstream):
    a, b, data, sha = two_hubs(nodes, upstream)
    assert a.store.get_blob(sha).infohash == b.store.get_blob(sha).infohash

    agent = nodes(
        "agent", a.url, upstreams=[a.url, b.url],
        peers=[a.endpoint, b.endpoint], swarm_first=True, swarm_stall=10,
    )
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)
    assert r.status_code == 200 and r.content == data
    assert agent.store.get_blob(sha).infohash == a.store.get_blob(sha).infohash


# ------------------------------------------------------------------ configuration

def test_make_upstream_chooses_the_simple_client_for_one_url():
    s = Settings(data_dir="x", upstream="http://one.example")
    assert isinstance(make_upstream(s), Upstream)
    s = Settings(data_dir="x", upstreams=["http://a.example", "http://b.example"])
    assert isinstance(make_upstream(s), UpstreamSet)


def test_quorum_larger_than_the_upstream_list_is_a_startup_error():
    with pytest.raises(ValueError):
        make_upstream(Settings(data_dir="x", upstreams=["http://a.example", "http://b.example"], quorum=3))
    with pytest.raises(ValueError):
        make_upstream(Settings(data_dir="x", upstream="http://one.example", quorum=2))


def test_environment_settings(monkeypatch):
    monkeypatch.setenv("THUB_UPSTREAMS", "https://a.example/, https://b.example")
    monkeypatch.setenv("THUB_QUORUM", "2")
    monkeypatch.setenv("THUB_META_TIMEOUT", "7")
    s = Settings.from_env()
    assert s.upstreams == ["https://a.example", "https://b.example"]
    assert s.upstream == "https://a.example"
    assert s.quorum == 2 and s.meta_timeout == 7.0


def test_a_hub_that_answers_200_and_then_breaks_before_any_byte_is_skipped(nodes, upstream):
    """Hub A has the metadata, no file, and its origin is gone, so it sends 200 headers and then
    drops the connection. Reading the first chunk before committing lets the agent move on."""
    a = nodes("hubA", upstream.url)
    b = nodes("hubB", upstream.url)
    data, sha = warm_hub(b, upstream)
    assert httpx.get(f"{a.url}/api/models/{REPO}/revision/main").status_code == 200  # metadata only
    upstream.stop()

    agent = nodes("agent", a.url, upstreams=[a.url, b.url])
    r = httpx.get(f"{agent.url}/{REPO}/resolve/main/model.safetensors", timeout=60)

    assert r.status_code == 200 and r.content == data
    m = agent.metrics
    assert m.get("thub_upstream_requests_total", upstream=netloc(a), kind="file", result="error") == 1
    assert m.get("thub_upstream_requests_total", upstream=netloc(b), kind="file", result="ok") == 1
