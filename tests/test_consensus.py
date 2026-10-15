"""The agreement rules between upstream hubs, as pure logic. No network."""

import pytest

from torrenthub.federation import (
    Disagreement,
    NotEnoughAnswers,
    choose_consensus,
    fingerprint,
)

A, B = "a" * 40, "b" * 40
H1, H2 = "1" * 64, "2" * 64


def doc(sha, big=H1, small_blob="c" * 40, extra=None):
    d = {
        "sha": sha,
        "siblings": [
            {"rfilename": "config.json", "size": 41, "blobId": small_blob},
            {"rfilename": "model.safetensors", "size": 3_670_016, "blobId": "d" * 40,
             "lfs": {"sha256": big, "size": 3_670_016, "pointerSize": 134}},
        ],
    }
    d.update(extra or {})
    return d


def test_fingerprint_ignores_order_and_unrelated_fields():
    x = doc(A)
    y = doc(A, extra={"downloads": 99, "tags": ["x"]})
    y["siblings"].reverse()
    assert fingerprint(x) == fingerprint(y)


def test_fingerprint_notices_a_changed_hash_size_or_blob_id():
    base = fingerprint(doc(A))
    assert fingerprint(doc(A, big=H2)) != base
    assert fingerprint(doc(A, small_blob="e" * 40)) != base
    changed_size = doc(A)
    changed_size["siblings"][0]["size"] = 42
    assert fingerprint(changed_size) != base


def test_single_answer_with_quorum_one():
    assert choose_consensus([(0, doc(A))], 1, "main")[0] == 0


def test_two_agreeing_answers_meet_quorum_two():
    idx, info = choose_consensus([(0, doc(A)), (1, doc(A))], 2, "main")
    assert idx == 0 and info["sha"] == A


def test_same_commit_different_tables_is_refused_even_at_quorum_one():
    with pytest.raises(Disagreement, match="different file tables"):
        choose_consensus([(0, doc(A)), (1, doc(A, big=H2))], 1, "main")


def test_conflict_is_found_among_the_answers_that_were_received_even_if_quorum_is_met():
    # three hubs: two agree, one lies about the same commit. Majority does not override.
    with pytest.raises(Disagreement):
        choose_consensus([(0, doc(A)), (1, doc(A)), (2, doc(A, big=H2))], 2, "main")


def test_quorum_not_met_because_hubs_lag_on_different_commits():
    with pytest.raises(Disagreement, match="no commit is reported by 2"):
        choose_consensus([(0, doc(A)), (1, doc(B))], 2, "main")


def test_not_enough_answers_is_different_from_disagreement():
    with pytest.raises(NotEnoughAnswers):
        choose_consensus([(0, doc(A))], 2, "main")
    with pytest.raises(NotEnoughAnswers):
        choose_consensus([], 1, "main")


def test_lagging_hubs_highest_priority_group_wins():
    answers = [(0, doc(A)), (1, doc(B)), (2, doc(B)), (3, doc(A))]
    idx, info = choose_consensus(answers, 2, "main")  # both groups have two members
    assert info["sha"] == A and idx == 0
    idx, info = choose_consensus([(0, doc(B)), (1, doc(A)), (2, doc(A)), (3, doc(B))], 2, "main")
    assert info["sha"] == B and idx == 0


def test_a_group_below_quorum_is_ignored_even_if_it_has_the_top_priority_hub():
    answers = [(0, doc(A)), (1, doc(B)), (2, doc(B))]
    idx, info = choose_consensus(answers, 2, "main")
    assert info["sha"] == B and idx == 1


def test_pinned_commit_rejects_an_answer_for_another_commit():
    with pytest.raises(Disagreement, match="pinned"):
        choose_consensus([(0, doc(A)), (1, doc(B))], 1, A)


def test_pinned_commit_with_all_matching_answers_is_fine():
    assert choose_consensus([(0, doc(A)), (1, doc(A))], 2, A)[1]["sha"] == A


def test_missing_sha_is_refused():
    with pytest.raises(Disagreement):
        choose_consensus([(0, {"siblings": []})], 1, "main")


def test_a_branch_named_like_a_short_hex_is_not_treated_as_pinned():
    # only a full 40 hex revision is pinned; a branch called "abc123" is just a branch
    assert choose_consensus([(0, doc(A)), (1, doc(B))], 1, "abc123")[1]["sha"] == A
