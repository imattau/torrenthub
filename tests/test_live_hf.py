"""Live smoke test against the real huggingface.co. Opt-in, needs internet.

    THUB_LIVE=1 python -m pytest tests/test_live_hf.py -s

It mirrors a small public repo through the gateway and compares every file, byte for byte,
with what the stock client downloads straight from Hugging Face. This is the check that
the fake upstream cannot give: real redirects, real LFS and Xet behaviour, real headers.

If it fails, the failure message is the finding. Likely suspects:
  * the model-info `siblings[].lfs.sha256` field differs for Xet-backed files
  * redirects from /resolve/ to a CDN that httpx cannot follow without extra headers
  * rate limiting (set HF_TOKEN to a read token)
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from huggingface_hub import snapshot_download

from tests.conftest import Server, free_port
from torrenthub.app import create_app
from torrenthub.config import Settings

pytestmark = pytest.mark.skipif(os.environ.get("THUB_LIVE") != "1", reason="set THUB_LIVE=1 to run")

# Comma separated list. Put an old repo and a recently created one in it: the recent one is the
# more likely to be Xet backed.
REPOS = [r for r in os.environ.get("THUB_LIVE_REPOS", os.environ.get("THUB_LIVE_REPO", "prajjwal1/bert-tiny")).split(",") if r]


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


@pytest.mark.parametrize("REPO", REPOS)
def test_mirror_matches_direct_download(tmp_path, REPO):
    token = os.environ.get("HF_TOKEN") or None
    direct = Path(snapshot_download(REPO, cache_dir=str(tmp_path / "direct"), token=token))

    port = free_port()
    settings = Settings(
        data_dir=tmp_path / "data",
        public_url=f"http://127.0.0.1:{port}",
        hf_token=token,
    )
    gw = Server(create_app(settings), port).start()
    try:
        via = Path(snapshot_download(REPO, endpoint=gw.url, cache_dir=str(tmp_path / "via"), token=False))
        direct_files = sorted(p.relative_to(direct) for p in direct.rglob("*") if p.is_file() or p.is_symlink())
        via_files = sorted(p.relative_to(via) for p in via.rglob("*") if p.is_file() or p.is_symlink())
        assert via_files == direct_files
        for rel in direct_files:
            assert sha256((via / rel).resolve()) == sha256((direct / rel).resolve()), str(rel)
    finally:
        gw.stop()
