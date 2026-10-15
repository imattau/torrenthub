"""A corrupt prefix streamed by the mirror must not survive a retry with the stock HF client.

Upstream corrupts one byte in the middle of the big file on the first request only. The mirror
streams the prefix, finds the sha256 mismatch at the end, and drops the connection before the
held-back tail. Upstream then recovers and the client retries.

Observed with huggingface_hub 2.2.0: the client discards its partial file when the stream is cut,
so the retry downloads from zero and the result is correct. Tools that resume partial files
(curl -C, wget -c, aria2) were not tested and could combine a bad prefix with a good tail.
"""

from __future__ import annotations

import pytest
from huggingface_hub import hf_hub_download

from tests.fake_upstream import REPO


def test_retry_after_aborted_stream_gives_correct_file(gateway, upstream, tmp_path):
    files = upstream.app.state.files
    good = files["model.safetensors"]
    mid = len(good) // 2
    files["model.safetensors"] = good[:mid] + bytes([good[mid] ^ 0xFF]) + good[mid + 1:]

    cache = str(tmp_path / "c")
    with pytest.raises(Exception):
        hf_hub_download(REPO, "model.safetensors", endpoint=gateway.url, cache_dir=cache, token=False)
    assert list((tmp_path / "c").rglob("*.incomplete")) == []

    files["model.safetensors"] = good  # upstream recovers
    final = hf_hub_download(REPO, "model.safetensors", endpoint=gateway.url, cache_dir=cache, token=False)
    assert open(final, "rb").read() == good
