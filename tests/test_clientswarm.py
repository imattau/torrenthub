"""Big files for a clone come over BitTorrent first, and are checked whichever way they come."""

from __future__ import annotations

import hashlib
import os
import re
import shutil

import httpx
import pytest

pytest.importorskip("libtorrent")

from tests.test_publish import BIG, FILES, REPO, Hub, push, run  # noqa: E402
from torrenthub import clientswarm as cs  # noqa: E402
from torrenthub import pointers  # noqa: E402
from torrenthub.gitrepo import GitError  # noqa: E402

KEY = hashlib.sha256(BIG).hexdigest()


@pytest.fixture()
def hub(tmp_path):
    h = Hub(tmp_path, publish_stall=15.0)
    run(push(h, tmp_path, FILES))
    yield h
    h.stop()


def http_bytes(hub) -> float:
    m = re.search(r"^thub_bytes_served_total\s+([0-9.e+]+)", httpx.get(f"{hub.url}/metrics", timeout=10).text, re.M)
    return float(m.group(1)) if m else 0.0


def cfg(**kw):
    base = dict(webseed=False, dht=False, stall=4.0, timeout=60.0)  # only peers count: no web seed in the torrent
    base.update(kw)
    return cs.SwarmConfig(**base)


def get(hub, tmp_path, **kw):
    dest = tmp_path / "cache" / KEY
    out = cs.fetch_blob(hub.url, KEY, len(BIG), dest, tmp_path / "work", cfg=kw.pop("cfg", None) or cfg(), say=lambda m: None, **kw)
    return out, dest


def test_a_big_file_comes_over_bittorrent_and_the_hub_serves_no_bytes_over_http(hub, tmp_path):
    before = http_bytes(hub)
    out, dest = get(hub, tmp_path, keep_torrent=tmp_path / "t" / f"{KEY}.torrent")
    assert out["via"] == "swarm" and dest.read_bytes() == BIG
    assert http_bytes(hub) == before, "not one byte of the file came over HTTP"
    assert (tmp_path / "t" / f"{KEY}.torrent").exists(), "the torrent is kept so the file can be seeded"
    assert not (tmp_path / "work" / KEY).exists(), "nothing is left in the working folder"


def test_the_hub_says_where_its_swarm_port_is(hub):
    info = httpx.get(f"{hub.url}/api/thub/info", timeout=10).json()
    assert info["swarm"] == {"enabled": True, "port": hub.settings.listen_port} and info["public_url"] == hub.settings.public_url


def test_with_the_swarm_switched_off_it_is_plain_http_and_does_not_ask_for_a_torrent(hub, tmp_path):
    out, dest = get(hub, tmp_path, cfg=cfg(enabled=False))
    assert out["via"] == "web" and dest.read_bytes() == BIG


def test_a_swarm_with_nobody_in_it_falls_back_to_http_after_the_stall(hub, tmp_path):
    torrent = hub.store.torrent_path(KEY)
    run(hub.swarm.forget(torrent))  # the hub stops seeding it, so the torrent has no peer
    out, dest = get(hub, tmp_path, cfg=cfg(stall=2.0))
    assert out["via"] == "web" and dest.read_bytes() == BIG


def test_bytes_the_swarm_delivers_that_are_wrong_are_never_kept(hub, tmp_path):
    p = hub.store.blob_path(KEY)
    bad = bytearray(BIG)
    bad[1000:1010] = b"CORRUPTION"
    p.write_bytes(bytes(bad))  # the hub seeds from seed_mode and does not notice; libtorrent on the client checks every piece
    dest = tmp_path / "cache" / KEY
    with pytest.raises(GitError):
        cs.fetch_blob(hub.url, KEY, len(BIG), dest, tmp_path / "work", cfg=cfg(stall=3.0), say=lambda m: None)
    assert not dest.exists() and not (tmp_path / "work" / KEY).exists()


def test_a_torrent_that_is_not_the_one_the_manifest_names_is_not_used(hub, tmp_path):
    before = http_bytes(hub)
    out, dest = get(hub, tmp_path, infohash="00" * 20)
    assert out["via"] == "web" and dest.read_bytes() == BIG and http_bytes(hub) > before


def test_a_matching_infohash_is_accepted(hub, tmp_path):
    from torrenthub.torrent import infohash_from_torrent

    ih = infohash_from_torrent(hub.store.torrent_path(KEY).read_bytes())
    assert get(hub, tmp_path, infohash=ih)[0]["via"] == "swarm"


def test_a_hub_with_no_torrent_for_it_is_asked_over_http(hub, tmp_path):
    hub.store.torrent_path(KEY).unlink()
    assert get(hub, tmp_path)[0]["via"] == "web"


def test_ensure_cached_goes_through_the_swarm_and_keeps_a_torrent(hub, tmp_path):
    gd = tmp_path / "repo" / ".git"
    gd.mkdir(parents=True)
    before = http_bytes(hub)
    path = pointers.ensure_cached(gd, KEY, len(BIG), [hub.url], cfg=cfg())
    assert path.read_bytes() == BIG and http_bytes(hub) == before
    assert (gd / "thub" / "torrents" / f"{KEY}.torrent").exists()
    assert pointers.ensure_cached(gd, KEY, len(BIG), ["http://127.0.0.1:9"], cfg=cfg()) == path, "a cached file needs no hub at all"


def test_when_every_hub_fails_the_error_says_so(tmp_path):
    gd = tmp_path / "repo" / ".git"
    gd.mkdir(parents=True)
    with pytest.raises(GitError, match="cannot get"):
        pointers.ensure_cached(gd, KEY, len(BIG), ["http://127.0.0.1:9"], cfg=cfg(stall=1.0))


# ------------------------------------------------------------------ settings

def test_settings_come_from_git_config_and_the_environment(tmp_path, monkeypatch):
    import subprocess

    repo = tmp_path / "r"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    for k, v in (("thub.peer", "10.0.0.5:6881"), ("thub.peer", "[::1]:7000"), ("thub.tracker", "udp://t.example:1337/announce"),
                 ("thub.swarm", "false"), ("thub.swarmStall", "7")):
        subprocess.run(["git", "config", "--add", k, v], cwd=repo, check=True)
    c = cs.config_from_env(repo)
    assert c.peers == [("10.0.0.5", 6881), ("::1", 7000)] and c.trackers == ["udp://t.example:1337/announce"] and c.enabled is False and c.stall == 7.0
    monkeypatch.setenv("THUB_CLIENT_SWARM", "1")
    monkeypatch.setenv("THUB_PEERS", "1.2.3.4:5, bad, 9.9.9.9:99999")
    monkeypatch.setenv("THUB_CLIENT_WEBSEED", "0")
    c = cs.config_from_env(repo)
    assert c.enabled is True and ("1.2.3.4", 5) in c.peers and len(c.peers) == 3 and c.webseed is False


def test_only_ordinary_tracker_schemes_are_taken_from_a_torrent():
    from torrenthub.torrent import build_torrent, choose_piece_length

    n = 5000
    raw, _ = build_torrent(name="a" * 64, length=n, piece_length=choose_piece_length(n), pieces=b"\0" * 20,
                           trackers=["udp://ok.example:1/announce", "file:///etc/passwd", "http://ok.example/announce", "ftp://x/y"])
    assert sorted(cs._trackers_of(raw)) == ["http://ok.example/announce", "udp://ok.example:1/announce"]


def test_a_hub_whose_torrent_agrees_with_corrupted_bytes_still_cannot_get_them_accepted(hub, tmp_path):
    """libtorrent is satisfied when the pieces match the torrent, and a hub chooses both. The only guard left is the sha256 of the whole file."""
    from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length

    bad = bytearray(BIG)
    bad[500] ^= 1
    bad = bytes(bad)
    ph = PieceHasher(choose_piece_length(len(bad)))
    ph.update(bad)
    raw, _ = build_torrent(name=KEY, length=len(bad), piece_length=choose_piece_length(len(bad)), pieces=ph.finish(), trackers=[])
    tp, bp = hub.store.torrent_path(KEY), hub.store.blob_path(KEY)
    run(hub.swarm.forget(tp))
    tp.write_bytes(raw)
    bp.write_bytes(bad)
    run(hub.swarm.seed(tp, bp.parent))
    said = []
    dest = tmp_path / "cache" / KEY
    with pytest.raises(GitError):
        cs.fetch_blob(hub.url, KEY, len(BIG), dest, tmp_path / "work", cfg=cfg(), say=said.append)
    assert not dest.exists() and not (tmp_path / "work" / KEY).exists()
    assert any("is not that file" in m for m in said), "the swarm's delivery was caught by the whole-file check, before HTTP was tried"


def test_a_torrent_for_some_other_blob_is_not_used(hub, tmp_path):
    from torrenthub.torrent import PieceHasher, build_torrent, choose_piece_length

    other = os.urandom(300_000)
    ph = PieceHasher(choose_piece_length(len(other)))
    ph.update(other)
    raw, _ = build_torrent(name=hashlib.sha256(other).hexdigest(), length=len(other), piece_length=choose_piece_length(len(other)), pieces=ph.finish())
    hub.store.torrent_path(KEY).write_bytes(raw)  # the hub answers the torrent request for KEY with another blob's torrent
    said = []
    dest = tmp_path / "cache" / KEY
    out = cs.fetch_blob(hub.url, KEY, len(BIG), dest, tmp_path / "work", cfg=cfg(stall=60.0), say=said.append)
    assert out["via"] == "web" and dest.read_bytes() == BIG
    assert any("TorrentRejected" in m for m in said), "the torrent was refused at once, not joined and waited on until it stalled"
