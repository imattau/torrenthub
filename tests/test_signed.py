"""Creator signatures: a repo only a creator vouches for, hosted on hubs nobody has to trust."""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys

import httpx
import pytest
from huggingface_hub import snapshot_download

from tests.fake_upstream import REPO
from tests.helpers import assert_repo_equals, warm_hub
from tests.test_federation import LIE, lie_about_big_file
from torrenthub import signing as sg
from torrenthub.config import parse_trust
from torrenthub.manifest import MANIFEST_KIND, ManifestInvalid, build_manifest, verify_manifest
from torrenthub.mirror import files_from_info
from torrenthub.upstream import Upstream, UpstreamSet

pytest.importorskip("libtorrent")

OWN = "acme/mine"
SK = bytes.fromhex("00" * 31 + "2a")
PK = sg.public_key(SK).hex()
OTHER_SK = bytes.fromhex("00" * 31 + "2b")


def rule(*keys):
    return [("acme/*", "signed:" + "+".join(keys))]


def host_as_own(hub, upstream, sk=SK, refs=("main",), created_at=1000):
    """Make `hub` hold the fake origin's files as repo acme/mine, with a manifest signed by sk."""
    commit = upstream.app.state.commit
    info = hub.store.get_commit_info(REPO, commit)
    hub.store.put_commit(OWN, "main", commit, info, files_from_info(info))
    ev = build_manifest(sk, OWN, info, list(refs), created_at=created_at)
    hub.store.add_manifest(ev)
    return info, ev


def hub_with_repo(nodes, upstream, name="hub", with_manifest=True, **kw):
    hub = nodes(name, upstream.url, ref_ttl=3600, **kw)
    data, sha = warm_hub(hub, upstream)
    commit = upstream.app.state.commit
    info = hub.store.get_commit_info(REPO, commit)
    hub.store.put_commit(OWN, "main", commit, info, files_from_info(info))
    ev = build_manifest(SK, OWN, info, ["main"], created_at=1000)
    if with_manifest:
        hub.store.add_manifest(ev)
    return hub, info, ev, data, sha


# ------------------------------------------------------------------ the happy path

def test_a_signed_repo_is_fetched_from_a_hub_nobody_trusts(nodes, upstream, tmp_path):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream)
    agent = nodes("agent", hub.url, trust=rule(PK))

    local = snapshot_download(OWN, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    r = httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30)
    assert r.headers["x-thub-source"] == "signed"
    assert agent.metrics.get("thub_manifest_total", result="valid") >= 1
    assert [e["id"] for e in agent.store.list_manifests(OWN)] == [ev["id"]]  # kept, so it can serve on


def test_an_agent_can_pass_the_manifest_on_to_the_next_agent(nodes, upstream, tmp_path):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream)
    first = nodes("first", hub.url, trust=rule(PK))
    snapshot_download(OWN, endpoint=first.url, cache_dir=str(tmp_path / "c1"), token=False)
    hub.stop()
    second = nodes("second", first.url, trust=rule(PK))
    local = snapshot_download(OWN, endpoint=second.url, cache_dir=str(tmp_path / "c2"), token=False)
    assert_repo_equals(local, upstream.app.state.files)


def test_pinned_commit_and_unknown_revision(nodes, upstream):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream)
    agent = nodes("agent", hub.url, trust=rule(PK))
    commit = info["sha"]
    assert httpx.get(f"{agent.url}/api/models/{OWN}/revision/{commit}", timeout=30).status_code == 200
    r = httpx.get(f"{agent.url}/api/models/{OWN}/revision/dev", timeout=30)
    assert r.status_code == 404 and r.headers["x-error-code"] == "RevisionNotFound"


# ------------------------------------------------------------------ hubs that lie

def test_a_hub_that_lies_about_hashes_is_skipped(nodes, upstream, tmp_path):
    liar, *_ = hub_with_repo(nodes, upstream, "liar")
    honest, info, ev, data, sha = hub_with_repo(nodes, upstream, "honest")
    # the liar changes the stored table for acme/mine
    bad = copy.deepcopy(info)
    for s in bad["siblings"]:
        if s["rfilename"] == "model.safetensors":
            s["lfs"]["sha256"] = LIE
    liar.store.put_commit(OWN, "main", info["sha"], bad, files_from_info(bad))

    agent = nodes("agent", liar.url, upstreams=[liar.url, honest.url], trust=rule(PK))
    local = snapshot_download(OWN, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)

    assert_repo_equals(local, upstream.app.state.files)
    assert agent.metrics.get("thub_manifest_hub_mismatch_total") == 1
    assert not agent.store.blob_complete(LIE)


def test_only_a_lying_hub_means_a_refusal_not_the_lie(nodes, upstream):
    liar, info, ev, data, sha = hub_with_repo(nodes, upstream, "liar")  # holds the real manifest
    bad = copy.deepcopy(info)
    for s in bad["siblings"]:
        if s["rfilename"] == "model.safetensors":
            s["lfs"]["sha256"] = LIE
    liar.store.put_commit(OWN, "main", info["sha"], bad, files_from_info(bad))
    agent = nodes("agent", liar.url, trust=rule(PK))
    r = httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30)
    assert r.status_code == 502 and r.headers["x-error-code"] == "ManifestMismatch"


# ------------------------------------------------------------------ manifests that are not good enough

def test_a_manifest_from_the_wrong_key_is_not_used(nodes, upstream):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream, with_manifest=False)
    hub.store.add_manifest(build_manifest(OTHER_SK, OWN, info, ["main"]))
    agent = nodes("agent", hub.url, trust=rule(PK))
    r = httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30)
    assert r.status_code == 502 and r.headers["x-error-code"] == "NoValidManifest"
    assert agent.metrics.get("thub_manifest_total", result="invalid") == 1


def test_no_manifest_at_all_is_a_refusal(nodes, upstream):
    hub, *_ = hub_with_repo(nodes, upstream, with_manifest=False)
    agent = nodes("agent", hub.url, trust=rule(PK))
    r = httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30)
    assert r.status_code == 502 and r.headers["x-error-code"] == "NoValidManifest"


def test_either_of_several_trusted_keys_will_do(nodes, upstream):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream, with_manifest=False)
    hub.store.add_manifest(build_manifest(OTHER_SK, OWN, info, ["main"]))
    agent = nodes("agent", hub.url, trust=rule(PK, sg.public_key(OTHER_SK).hex()))
    assert httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30).status_code == 200


def test_manifest_verification_rules():
    info = {"sha": "a" * 40, "siblings": [{"rfilename": "w", "size": 3, "blobId": "b" * 40}]}
    ev = build_manifest(SK, OWN, info, ["main"], created_at=5)
    ok = verify_manifest(ev, {PK}, OWN)
    assert ok.commit == "a" * 40 and ok.refs == ("main",) and ok.created_at == 5

    def bad(e, allowed={PK}, repo=OWN):
        with pytest.raises(ManifestInvalid):
            verify_manifest(e, allowed, repo)

    bad(ev, allowed={sg.public_key(OTHER_SK).hex()})  # signer not trusted
    bad(ev, repo="acme/other")  # signed for another repo
    bad({**ev, "content": ev["content"].replace("main", "dev")})  # content changed after signing
    bad({**ev, "sig": "00" * 64})
    bad({**ev, "kind": MANIFEST_KIND + 1})
    # Correctly signed, but the tags say something else than the content does.
    forged = sg.sign_event(SK, MANIFEST_KIND, [["d", "x"], ["repo", OWN], ["commit", "c" * 40]], ev["content"], 5)
    bad(forged)
    bad({"junk": 1})
    bad({**ev, "content": "not json"})


# ------------------------------------------------------------------ branch names

def two_commits(hub, info, created=(100, 200)):
    first = copy.deepcopy(info)
    first["sha"] = "1" * 40
    second = copy.deepcopy(info)
    second["sha"] = "2" * 40
    second["siblings"] = [s for s in second["siblings"] if s["rfilename"] != "README.md"]
    for i in (first, second):
        hub.store.put_commit(OWN, "x", i["sha"], i, files_from_info(i))
    m1 = build_manifest(SK, OWN, first, ["main"], created_at=created[0])
    m2 = build_manifest(SK, OWN, second, ["main"], created_at=created[1])
    return first, second, m1, m2


def test_newest_signed_claim_on_a_branch_wins(nodes, upstream):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream, with_manifest=False)
    first, second, m1, m2 = two_commits(hub, info)
    hub.store.add_manifest(m1)
    hub.store.add_manifest(m2)
    agent = nodes("agent", hub.url, trust=rule(PK))
    assert httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30).json()["sha"] == "2" * 40
    assert httpx.get(f"{agent.url}/api/models/{OWN}/revision/{'1' * 40}", timeout=30).json()["sha"] == "1" * 40


def test_a_hub_that_withholds_the_newest_manifest_can_roll_a_branch_back(nodes, upstream):
    """Known limit: signatures prove authenticity, not freshness. Another hub that has the
    newer manifest fixes it, because the agent takes manifests from all of them."""
    stale, info, ev, data, sha = hub_with_repo(nodes, upstream, "stale", with_manifest=False)
    fresh, *_ = hub_with_repo(nodes, upstream, "fresh", with_manifest=False)
    first, second, m1, m2 = two_commits(stale, info)
    two_commits(fresh, info)
    stale.store.add_manifest(m1)
    fresh.store.add_manifest(m1)
    fresh.store.add_manifest(m2)

    only_stale = nodes("a1", stale.url, trust=rule(PK))
    assert httpx.get(f"{only_stale.url}/api/models/{OWN}/revision/main", timeout=30).json()["sha"] == "1" * 40

    both = nodes("a2", stale.url, upstreams=[stale.url, fresh.url], trust=rule(PK))
    assert httpx.get(f"{both.url}/api/models/{OWN}/revision/main", timeout=30).json()["sha"] == "2" * 40


# ------------------------------------------------------------------ configuration and the hub endpoint

def test_parse_trust_signed():
    npub = sg.bech32_encode("npub", bytes.fromhex(PK))
    assert parse_trust(f"acme/*=signed:{npub}+{PK}") == [("acme/*", f"signed:{PK}+{PK}")]
    for bad in ("acme/*=signed", "acme/*=signed:nope", "acme/*=signed:", f"acme/*=signed:{'0' * 64}"):
        with pytest.raises(ValueError):
            parse_trust(bad)


def test_set_mode_and_default_for_signed_rules():
    u = UpstreamSet([Upstream("http://h:1")], trust=rule(PK))
    assert u.mode_for("acme/x").startswith("signed:") and u.mode_for("other/y") == "hub"


def test_hub_manifest_endpoint_is_safe(nodes, upstream):
    hub, info, ev, data, sha = hub_with_repo(nodes, upstream)
    got = httpx.get(f"{hub.url}/api/thub/manifests/{OWN}", timeout=30).json()["events"]
    assert [e["id"] for e in got] == [ev["id"]]
    for odd in ("..", "a/../../b", "x/y/z", ".hidden/x"):
        r = httpx.get(f"{hub.url}/api/thub/manifests/{odd}", timeout=30)
        assert r.status_code in (200, 404) and (r.status_code == 404 or r.json()["events"] == [])


# ------------------------------------------------------------------ command line

def cli(args, env):
    return subprocess.run([sys.executable, "-m", "torrenthub.cli", *args], env=env, capture_output=True, text=True, timeout=60)


def test_sign_list_and_import_from_the_command_line(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url, ref_ttl=3600)
    warm_hub(hub, upstream)
    env = {**os.environ, "THUB_UPSTREAM": hub.url, "THUB_ANCHOR": "none", "THUB_DATA": str(tmp_path / "creator")}

    k = json.loads(cli(["keygen"], env).stdout)
    assert k["nsec"].startswith("nsec1") and k["npub"].startswith("npub1")
    keyfile = tmp_path / "k"
    keyfile.write_text(k["nsec"])

    # the repo id the creator signs for is the one their hub knows it by
    out = cli(["sign", REPO, "--key-file", str(keyfile)], env)
    assert out.returncode == 0, out.stderr
    assert k["nsec"] not in out.stdout + out.stderr
    signed = json.loads(out.stdout)
    assert signed["pubkey"] == k["pubkey_hex"] and signed["refs"] == ["main"]
    listing = cli(["manifests", REPO], env).stdout
    assert signed["event_id"][:16] in listing and "main" in listing

    ev_path = next((tmp_path / "creator" / "manifests").rglob("*.json"))
    other = {**env, "THUB_DATA": str(tmp_path / "hub2")}
    wrong = cli(["manifest-add", str(ev_path), "--key", sg.public_key(OTHER_SK).hex()], other)
    assert wrong.returncode != 0 and "rejected" in wrong.stderr
    right = cli(["manifest-add", str(ev_path), "--key", k["npub"]], other)
    assert right.returncode == 0 and json.loads(right.stdout)["added"] is True
    assert json.loads(cli(["manifest-add", str(ev_path), "--key", k["npub"]], other).stdout)["added"] is False

    nokey = cli(["sign", REPO], {**env, "THUB_SIGNING_KEY": ""})
    assert nokey.returncode != 0
