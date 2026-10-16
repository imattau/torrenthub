"""Running it for real: the doctor, the advertised port, key files, and the package itself."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

pytest.importorskip("libtorrent")

from tests.conftest import free_port  # noqa: E402
from tests.test_publish import FILES, Hub, push, run  # noqa: E402
from torrenthub import doctor as D  # noqa: E402
from torrenthub.config import Settings  # noqa: E402
from torrenthub.signing import key_file_warning  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def settings(tmp_path, **kw):
    base = dict(data_dir=tmp_path / "d", public_url="https://hub.example.org", swarm="libtorrent", listen_port=free_port(), max_disk_bytes=10 * 2**30)
    base.update(kw)
    return Settings(**base)


def by_name(checks):
    out = {}
    for c in checks:
        out.setdefault(c.name, []).append(c)
    return out


# ------------------------------------------------------------------ the doctor

def test_a_sensible_setup_has_nothing_to_fix(tmp_path):
    checks = by_name(D.run(settings(tmp_path, tracker=True)))
    assert not [c for cs in checks.values() for c in cs if c.level == "fail"]
    assert checks["public url"][0].level == "ok" and checks["swarm port"][0].level == "ok" and checks["git"][0].level == "ok"


def test_a_public_url_that_says_localhost_is_flagged_when_there_is_a_swarm(tmp_path):
    c = by_name(D.run(settings(tmp_path, public_url="http://localhost:8080")))["public url"][0]
    assert c.level == "warn" and "THUB_PUBLIC_URL" in c.detail
    assert by_name(D.run(settings(tmp_path, public_url="http://10.0.0.5:8080")))["public url"][0].level == "warn"
    assert by_name(D.run(settings(tmp_path, public_url="not a url")))["public url"][0].level == "fail"


def test_plain_http_on_a_public_name_asks_for_tls(tmp_path):
    assert "tls" in by_name(D.run(settings(tmp_path, public_url="http://hub.example.org")))
    assert "tls" not in by_name(D.run(settings(tmp_path, public_url="https://hub.example.org")))


def test_publishing_on_with_nobody_allowed_to_publish_fails(tmp_path):
    c = by_name(D.run(settings(tmp_path, publish_quota=10**9, roots=[])))["publishing"][0]
    assert c.level == "fail" and "THUB_ROOTS" in c.detail
    assert by_name(D.run(settings(tmp_path, publish_quota=10**9, roots=["ab" * 32])))["publishing"][0].level == "ok"
    forced = by_name(D.run(settings(tmp_path, publish_quota=10**9, roots=["ab" * 32], publish_allow_force=True)))["publishing"]
    assert any(c.level == "warn" and "rewrite" in c.detail for c in forced)


def test_no_swarm_no_libtorrent_and_no_disk_budget_are_said(tmp_path):
    checks = by_name(D.run(settings(tmp_path, swarm="none")))
    assert checks["swarm"][0].level == "warn"
    assert by_name(D.run(settings(tmp_path, max_disk_bytes=0)))["disk budget"][0].level == "warn"


def test_a_data_directory_that_cannot_be_written_fails(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    c = by_name(D.run(settings(tmp_path, data_dir=blocker / "inside")))["data dir"][0]
    assert c.level == "fail"


def test_a_busy_swarm_port_is_a_warning_not_a_failure(tmp_path):
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("0.0.0.0", 0))
        s.listen()
        c = by_name(D.run(settings(tmp_path, listen_port=s.getsockname()[1])))["swarm port"][0]
    assert c.level == "warn" and "TCP" in c.detail


def test_both_discovery_methods_off_is_said(tmp_path):
    assert by_name(D.run(settings(tmp_path, tracker=False, dht=False)))["discovery"][0].level == "warn"


def test_an_old_git_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(D, "_git_version", lambda: (2, 20, 1))
    assert by_name(D.run(settings(tmp_path)))["git"][0].level == "fail"
    monkeypatch.setattr(D, "_git_version", lambda: None)
    assert by_name(D.run(settings(tmp_path)))["git"][0].level == "warn"
    assert by_name(D.run(settings(tmp_path, publish_quota=1, roots=["ab" * 32])))["git"][0].level == "fail", "publishing needs git"


def test_https_without_forwarded_allow_ips_mentions_the_proxy(tmp_path, monkeypatch):
    monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)
    assert "proxy" in by_name(D.run(settings(tmp_path)))
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "127.0.0.1")
    assert "proxy" not in by_name(D.run(settings(tmp_path)))


def test_probe_finds_the_running_hub_and_its_swarm_port(tmp_path):
    h = Hub(tmp_path)
    try:
        s = Settings(data_dir=tmp_path / "x", public_url=h.url, swarm="libtorrent", listen_port=h.settings.listen_port)
        probes = [c for c in D.probe_running(s)]
        assert [c.level for c in probes] == ["ok", "ok"], [c.line() for c in probes]
    finally:
        h.stop()


def test_probe_catches_a_public_url_that_is_not_where_the_hub_thinks_it_is(tmp_path):
    h = Hub(tmp_path)
    try:
        wrong = Settings(data_dir=tmp_path / "x", public_url=h.url.replace("127.0.0.1", "localhost"), swarm="libtorrent")
        c = D.probe_running(wrong)[0]
        assert c.level == "fail" and "THUB_PUBLIC_URL" in c.detail
    finally:
        h.stop()


def test_probe_catches_a_swarm_port_nobody_listens_on(tmp_path):
    h = Hub(tmp_path, swarm_public_port=free_port())  # advertised, but the hub listens elsewhere
    try:
        s = Settings(data_dir=tmp_path / "x", public_url=h.url, swarm="libtorrent")
        assert any(c.level == "fail" and "swarm port" in c.detail for c in D.probe_running(s))
    finally:
        h.stop()


def test_probe_reports_a_hub_that_is_not_there(tmp_path):
    c = D.probe_running(Settings(data_dir=tmp_path, public_url="http://127.0.0.1:9"))[0]
    assert c.level == "fail" and "did not answer" in c.detail


def test_the_doctor_command_exits_nonzero_on_a_failure(tmp_path):
    env = {**os.environ, "PYTHONPATH": str(ROOT), "THUB_DATA": str(tmp_path / "d"), "THUB_PUBLISH_QUOTA": "1G", "THUB_ROOTS": ""}
    r = subprocess.run([sys.executable, "-m", "torrenthub", "doctor"], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 1 and "fail  publishing" in r.stdout and "1 failed" in r.stdout
    r = subprocess.run([sys.executable, "-m", "torrenthub", "doctor"], env={**env, "THUB_PUBLISH_QUOTA": "0"}, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "0 failed" in r.stdout


# ------------------------------------------------------------------ a port that is not the one the hub listens on

def test_clients_are_told_the_port_outsiders_reach_not_the_one_the_hub_listens_on(tmp_path):
    outside = free_port()
    h = Hub(tmp_path, swarm_public_port=outside)
    try:
        info = httpx.get(f"{h.url}/api/thub/info", timeout=10).json()
        assert info["swarm"]["port"] == outside and info["dht"]["port"] == outside and outside != h.settings.listen_port
        assert h.app.state.tracker.self_peer == ("127.0.0.1", outside)
        assert h.settings.advertised_swarm_port == outside
        assert Settings(data_dir=tmp_path, listen_port=6881).advertised_swarm_port == 6881, "unset means the listen port"
    finally:
        h.stop()


def test_a_publisher_dials_the_advertised_port(tmp_path):
    """The publisher gets the swarm port from the hub's answer. With a mapped port, the listen port would be a dead end."""
    h = Hub(tmp_path, swarm_public_port=free_port())
    try:
        from tests.test_publish import SK, prepare, write_tree
        from tests.test_publish import REPO

        pub = prepare(SK, REPO, write_tree(tmp_path / "src", FILES), tmp_path / "stage", seq=1)
        r = httpx.post(f"{h.url}/api/thub/publish", json=pub.body, timeout=30)
        assert r.json()["swarm"]["port"] == h.settings.advertised_swarm_port
    finally:
        h.stop()


# ------------------------------------------------------------------ key files

def test_a_key_file_other_users_can_read_is_warned_about(tmp_path):
    key = tmp_path / "k"
    key.write_text("00" * 32)
    key.chmod(0o644)
    w = key_file_warning(key)
    assert w and "chmod 600" in w and "644" in w
    key.chmod(0o600)
    assert key_file_warning(key) is None
    key.chmod(0o640)
    assert key_file_warning(key) is not None
    assert key_file_warning(tmp_path / "missing") is None


def test_the_commands_that_read_a_key_say_so(tmp_path):
    key = tmp_path / "k"
    key.write_text("00" * 31 + "2a")
    key.chmod(0o644)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "THUB_DATA": str(tmp_path / "d")}
    r = subprocess.run([sys.executable, "-m", "torrenthub", "endorse", "--key-file", str(key), "--subject", "ab" * 32, "--scope", "x", "--weight", "0.5"],
                       env=env, capture_output=True, text=True, timeout=60)
    assert "readable by other users" in r.stderr and r.returncode == 0
    key.chmod(0o600)
    r = subprocess.run([sys.executable, "-m", "torrenthub", "endorse", "--key-file", str(key), "--subject", "ab" * 32, "--scope", "x", "--weight", "0.5"],
                       env=env, capture_output=True, text=True, timeout=60)
    assert "readable by other users" not in r.stderr


# ------------------------------------------------------------------ things only a different machine finds

def test_every_git_command_that_needs_a_repository_is_run_inside_one(tmp_path, monkeypatch):
    """`git show-index` run outside a repository segfaults on git 2.47.3 (the container's), and works on 2.43. Found by running the image."""
    from torrenthub import gitrepo as G

    repo = tmp_path / "r"
    G.init_bare(repo)
    data = os.urandom(300)
    pack = subprocess.run(["git", "-C", str(repo), "hash-object", "-w", "--stdin"], input=data, capture_output=True).stdout
    out = subprocess.run(["git", "-C", str(repo), "pack-objects", "-q", str(repo / "objects" / "pack" / "pack")], input=pack, capture_output=True).stdout.decode().strip()
    seen = []
    real = G.run_git
    monkeypatch.setattr(G, "run_git", lambda args, **kw: (seen.append((list(args), kw.get("cwd"))), real(args, **kw))[1])
    assert G.pack_object_count(repo, out) == 1
    assert [cwd for args, cwd in seen if args[0] == "show-index"] == [repo]


# ------------------------------------------------------------------ a hub with a name

def test_libtorrent_is_never_handed_a_hostname_where_it_wants_an_address(tmp_path):
    """connect_peer takes only IP addresses. Every test and VM run named the hub by its IP, so publishing to or cloning from a hub by its DNS
    name crashed, found only by putting a real name (localhost, through a TLS proxy) in front. The swarm resolves names itself now."""
    import hashlib

    from torrenthub.swarm import LibtorrentSwarm, resolve_peer
    from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length

    assert resolve_peer("127.0.0.1", 6881) == ("127.0.0.1", 6881)
    assert resolve_peer("localhost", 6881) == ("127.0.0.1", 6881), "an IPv4 address is preferred"
    assert resolve_peer("no-such-host.invalid", 6881) is None
    data = os.urandom(3000)
    key = hashlib.sha256(data).hexdigest()
    ph = PieceHasher(choose_piece_length(len(data)))
    ph.update(data)
    raw, _ = build_torrent(name=key, length=len(data), piece_length=choose_piece_length(len(data)), pieces=ph.finish())
    (tmp_path / "t.torrent").write_bytes(raw)
    (tmp_path / key).write_bytes(data)
    sw = LibtorrentSwarm(0, "127.0.0.1", dht=False, extra_peers=[("localhost", free_port()), ("no-such-host.invalid", 1)])
    try:
        run(sw.seed(tmp_path / "t.torrent", tmp_path))
        assert run(sw.connect(tmp_path / "t.torrent", "localhost", free_port())) is True
        assert run(sw.connect(tmp_path / "t.torrent", "no-such-host.invalid", 1)) is False
        dl = run(sw.start(tmp_path / "t.torrent", tmp_path / "dl"))  # starts with the hints that are names
        assert dl is not None
    finally:
        run(sw.close())


def test_publishing_to_and_cloning_from_a_hub_named_in_dns(tmp_path):
    from tests.test_git_publish import FILES, make_repo
    from tests.test_publish import PK, REPO, publisher_swarm
    from tests.test_git_publish import gpush
    from torrenthub import clientswarm as cs

    h = Hub(tmp_path, publish_stall=15.0, public_url_host="localhost")
    try:
        named = h.url.replace("127.0.0.1", "localhost")
        big = os.urandom(1_500_000)
        root = make_repo(tmp_path, files=FILES, big={"big.bin": big})

        class Named:  # the same hub, reached by name
            url = named
            settings = h.settings
            app = h.app
            store = h.store
            swarm = h.swarm

        _, st = run(gpush(Named, root, tmp_path / "s"))
        assert st["state"] == "done"
        # a client fetching a blob from it by name
        key = next(s["lfs"]["sha256"] for s in httpx.get(f"{named}/api/models/{REPO}/revision/main", timeout=10).json()["siblings"] if s["rfilename"] == "big.bin")
        out = cs.fetch_blob(named, key, 1_500_000, tmp_path / "d" / key, tmp_path / "w", cfg=cs.SwarmConfig(webseed=False, dht=False, stall=15.0), say=lambda m: None)
        assert out["via"] == "swarm", out
    finally:
        h.stop()


def test_the_host_refuses_to_start_with_gits_own_variables_in_its_environment(tmp_path):
    """The first host service file named its setting GIT_DIR. systemd exported it, git read it as the repository for every command the host
    ran, and the host reported 'not a git repository' for a perfectly good one. Found by running the unit."""
    key = tmp_path / "k"
    key.write_text("00" * 31 + "2a")
    key.chmod(0o600)
    env = {**os.environ, "PYTHONPATH": str(ROOT), "THUB_DATA": str(tmp_path / "d"), "GIT_DIR": str(tmp_path / "repo")}
    r = subprocess.run([sys.executable, "-m", "torrenthub", "host", "--git", str(tmp_path), "--repo", "a/b", "--key-file", str(key), "--public-url", "http://127.0.0.1:1"],
                       env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode != 0 and "GIT_DIR" in r.stderr and "Unset it" in r.stderr


def test_the_shipped_service_files_do_not_name_their_settings_after_gits(tmp_path):
    for f in (ROOT / "deploy" / "systemd").glob("*"):
        text = f.read_text()
        for bad in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            assert bad not in text, f"{f.name} uses {bad}"
