import json
import subprocess
import sys

from tests.fake_upstream import REPO


def run(args, env):
    return subprocess.run([sys.executable, "-m", "torrenthub.cli", *args], env=env, capture_output=True, text=True, timeout=60)


def test_lock_command_records_through_the_anchor_and_is_idempotent(upstream, tmp_path):
    import os

    env = {**os.environ, "THUB_UPSTREAM": upstream.url, "THUB_ANCHOR": "none", "THUB_DATA": str(tmp_path / "d"),
           "THUB_LOCKFILE": str(tmp_path / "t.lock")}
    first = run(["lock", REPO], env)
    assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)["recorded"] is True
    assert json.loads(run(["lock", REPO], env).stdout)["recorded"] is False
    listed = run(["locked"], env).stdout
    assert f"{REPO}@" in listed and "4 files" in listed
    missing = run(["lock", "acme/nope"], env)
    assert missing.returncode != 0 and "RepoNotFound" in missing.stderr
