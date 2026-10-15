"""A `signed:ROOT` rule accepts manifests from keys ROOT has delegated to, and only while that holds."""

from __future__ import annotations

import time

import httpx
import pytest
from huggingface_hub import snapshot_download

from tests.fake_upstream import REPO
from tests.helpers import assert_repo_equals
from tests.test_signed import OWN, host_as_own, hub_with_repo
from tests.test_trust import ROOT, key, pub
from torrenthub import events as E

pytest.importorskip("libtorrent")

DEL = key(30)
DEL_PK = pub(30)
RULE = [("acme/*", "signed:" + ROOT)]


def setup(nodes, upstream):
    hub, *_ = hub_with_repo(nodes, upstream, with_manifest=False)
    host_as_own(hub, upstream, sk=DEL)  # the manifest is signed by the delegate, not the root
    agent = nodes("agent", hub.url, trust=RULE)
    return hub, agent


def info(agent):
    return httpx.get(f"{agent.url}/api/models/{OWN}/revision/main", timeout=30)


def post(agent, ev):
    r = httpx.post(f"{agent.url}/api/thub/events", json=ev, timeout=30)
    assert r.status_code == 200, r.text
    return r


def delegation(scope="publish:acme/*", **kw):
    return E.build_delegation(key(1), DEL_PK, [scope], **kw)


def test_a_delegate_of_the_root_can_sign_and_the_agent_accepts_it(nodes, upstream, tmp_path):
    hub, agent = setup(nodes, upstream)
    r = info(agent)
    assert r.status_code == 502 and r.headers["x-error-code"] == "NoValidManifest"

    post(agent, delegation())
    r = info(agent)
    assert r.status_code == 200 and r.headers["x-thub-source"] == "signed"
    local = snapshot_download(OWN, endpoint=agent.url, cache_dir=str(tmp_path / "c"), token=False)
    assert_repo_equals(local, upstream.app.state.files)


def test_a_delegation_for_another_namespace_does_not_help(nodes, upstream):
    hub, agent = setup(nodes, upstream)
    post(agent, delegation("publish:other/*"))
    assert info(agent).status_code == 502


def test_an_expired_delegation_does_not_help(nodes, upstream):
    hub, agent = setup(nodes, upstream)
    post(agent, delegation(expires=int(time.time()) - 10))
    assert info(agent).status_code == 502


def test_revoking_the_delegation_stops_it_at_once(nodes, upstream):
    hub, agent = setup(nodes, upstream)
    d = delegation()
    post(agent, d)
    assert info(agent).status_code == 200
    post(agent, E.build_revocation(key(1), "event", d["id"]))
    assert info(agent).status_code == 502


def test_a_delegation_from_someone_who_is_not_the_root_is_ignored(nodes, upstream):
    hub, agent = setup(nodes, upstream)
    fake = E.build_delegation(key(2), DEL_PK, ["publish:acme/*"])
    r = httpx.post(f"{agent.url}/api/thub/events", json=fake, timeout=30)
    assert r.json()["status"] == "quarantined"
    assert info(agent).status_code == 502


def test_a_redelegated_chain_works_only_if_every_link_allows_it(nodes, upstream):
    hub, agent = setup(nodes, upstream)
    mid = key(31)
    post(agent, E.build_delegation(key(1), pub(31), ["publish:acme/*"], redelegable=False))
    post(agent, E.build_delegation(mid, DEL_PK, ["publish:acme/*"]))
    assert info(agent).status_code == 502
    post(agent, E.build_delegation(key(1), pub(31), ["publish:acme/*"], redelegable=True))
    assert info(agent).status_code == 200


def test_a_signed_key_in_a_rule_is_a_root_without_being_listed_twice(nodes, upstream):
    hub, agent = setup(nodes, upstream)
    g = agent.app.state.admission.graph()
    assert ROOT in g.roots
