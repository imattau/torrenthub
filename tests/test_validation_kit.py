"""The scripts in validation/ are run by hand against the real internet. These tests check that
they do what they say against the fake origin and real gateways, so a surprise on the real run
is about the real world and not about the scripts."""

import json
import subprocess
import sys

import pytest

from tests.fake_upstream import REPO
from tests.helpers import warm_hub


def run(*args):
    return subprocess.run([sys.executable, *args], capture_output=True, text=True, timeout=120)


def test_probe_passes_a_consistent_origin(upstream, tmp_path):
    out = tmp_path / "r.json"
    r = run("validation/probe_hf.py", "--endpoint", upstream.url, "--repo", REPO, "--json", str(out), "--max-mb", "10")
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.loads(out.read_text())[0]
    assert all(c["ok"] for c in rep["checks"].values())
    assert rep["info"]["tested_file"]["path"] == "model.safetensors"


def test_probe_fails_when_the_bytes_do_not_match_the_advertised_hash(upstream):
    data = bytearray(upstream.app.state.files["model.safetensors"])
    data[100] ^= 1
    upstream.app.state.files["model.safetensors"] = bytes(data)
    r = run("validation/probe_hf.py", "--endpoint", upstream.url, "--repo", REPO, "--max-mb", "10")
    assert r.returncode == 1 and "FAIL  R5" in r.stdout


def test_probe_reports_a_missing_repo_and_skips_when_nothing_fits(upstream):
    r = run("validation/probe_hf.py", "--endpoint", upstream.url, "--repo", "acme/nope")
    assert r.returncode == 1 and "FAIL  R1" in r.stdout
    r = run("validation/probe_hf.py", "--endpoint", upstream.url, "--repo", REPO, "--max-mb", "0.00001")
    assert "SKIP  R4" in r.stdout and r.returncode == 0


def test_measure_reports_peer_share_for_an_agent(nodes, upstream, tmp_path):
    pytest.importorskip("libtorrent")
    hub = nodes("hub", upstream.url)
    data, sha = warm_hub(hub, upstream)
    upstream.stop()
    agent = nodes("agent", hub.url, peers=[hub.endpoint], swarm_first=True, swarm_stall=10)
    out = tmp_path / "m.json"
    r = run("validation/measure.py", "--gateway", agent.url, "--hub", hub.url, "--repo", REPO, "--json", str(out))
    assert r.returncode == 0, r.stdout + r.stderr
    rep = json.loads(out.read_text())
    assert rep["gateway_fetched_from_swarm"] == len(data)
    assert rep["peer_share"] > 0.95  # only the small files came over HTTP
    assert rep["swarm_fallbacks"] == 0 and rep["integrity_failures"] == 0
    assert rep["hub_http_served_bytes"] < 200_000
    assert "peer share" in r.stdout


def test_measure_says_so_when_the_gateway_already_had_the_repo(nodes, upstream, tmp_path):
    hub = nodes("hub", upstream.url)
    warm_hub(hub, upstream)
    r = run("validation/measure.py", "--gateway", hub.url, "--repo", REPO)
    assert r.returncode == 0 and "n/a" in r.stdout


def test_static_peer_hints_parse_and_reject_junk(monkeypatch):
    from torrenthub.config import Settings
    from torrenthub.swarm import parse_peers

    assert parse_peers(["10.0.0.5:6881", "[::1]:7000"]) == [("10.0.0.5", 6881), ("::1", 7000)]
    for bad in ("nohost", "host:", "host:0", "host:99999", ":6881", "host:abc"):
        with pytest.raises(ValueError):
            parse_peers([bad])
    monkeypatch.setenv("THUB_PEERS", "10.0.0.5:6881, 10.0.0.6:6881")
    assert Settings.from_env().peers == ["10.0.0.5:6881", "10.0.0.6:6881"]
