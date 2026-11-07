# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Claim Evaluator across all six failure classes (F0–F5)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from c3_claim_checker.evaluator import ClaimEvaluator
from c3_claim_checker.git_verifier import GitVerifier
from c3_claim_checker.models import FailureClass, ReportStratum, VulnerabilityReport


@pytest.fixture
def eval_git_repo(tmp_path: Path) -> Path:
    """Create a git repo for full evaluation of F0–F5 classes."""
    repo = tmp_path / "eval_repo"
    repo.mkdir()

    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Tester"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "tester@invarcore.org"], check=True)

    # File 1: lib/rand.c (5 lines)
    lib = repo / "lib"
    lib.mkdir()
    (lib / "rand.c").write_text(
        "/* line 1 */\n/* line 2 */\nint weak_random(void) {\n    return 1;\n}\n",
        encoding="utf-8",
    )
    # File 2: lib/static.c (unchanged upstream)
    (lib / "static.c").write_text(
        "void stable_fn(void) {\n    return;\n}\n",
        encoding="utf-8",
    )

    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "Release v1.0.0"], check=True)
    subprocess.run(["git", "-C", str(repo), "tag", "v1.0.0"], check=True)

    # Upstream change: modify rand.c on HEAD
    (lib / "rand.c").write_text(
        "/* line 1 */\n/* line 2 */\nint secure_random(void) {\n    return 42;\n}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "Security patch"], check=True)

    return repo


def test_f5_unanchored_prose(eval_git_repo: Path) -> None:
    gv = GitVerifier(eval_git_repo)
    evaluator = ClaimEvaluator(gv)

    rep = VulnerabilityReport(
        id="REPORT-F5",
        title="Vague memory leak vulnerability",
        body="There is a catastrophic buffer overflow in the application memory pool when handling malformed packets.",
        stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
    )
    res = evaluator.evaluate(rep)
    assert res.primary_class == FailureClass.F5_UNANCHORED_PROSE
    assert len(res.files_cited) == 0


def test_f1_phantom_path(eval_git_repo: Path) -> None:
    gv = GitVerifier(eval_git_repo)
    evaluator = ClaimEvaluator(gv)

    rep = VulnerabilityReport(
        id="REPORT-F1",
        title="Null pointer dereference in non-existent file",
        body="Found bug in `lib/nonexistent_auth_handler.c:42` in function `handle_auth()`.",
        stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
        claimed_version="v1.0.0",
    )
    res = evaluator.evaluate(rep)
    assert res.primary_class == FailureClass.F1_PHANTOM_PATH
    assert "lib/nonexistent_auth_handler.c" in res.f1_phantom_paths


def test_f2_phantom_symbol(eval_git_repo: Path) -> None:
    gv = GitVerifier(eval_git_repo)
    evaluator = ClaimEvaluator(gv)

    rep = VulnerabilityReport(
        id="REPORT-F2",
        title="Missing symbol in existing file",
        body="In `lib/static.c:1`, function `ghost_signature_calculator()` causes crash.",
        stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
        claimed_version="v1.0.0",
    )
    res = evaluator.evaluate(rep)
    assert res.primary_class == FailureClass.F2_PHANTOM_SYMBOL
    assert "ghost_signature_calculator" in res.f2_phantom_symbols


def test_f3_line_drift_or_oob(eval_git_repo: Path) -> None:
    gv = GitVerifier(eval_git_repo)
    evaluator = ClaimEvaluator(gv)

    # lib/static.c is only 3 lines long. Citing line 999 is OOB.
    rep = VulnerabilityReport(
        id="REPORT-F3",
        title="Out of bounds line citation",
        body="In `lib/static.c:999-1050`, function `stable_fn()` fails.",
        stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
        claimed_version="v1.0.0",
    )
    res = evaluator.evaluate(rep)
    assert res.primary_class == FailureClass.F3_LINE_DRIFT_OR_OOB
    assert len(res.f3_oob_lines) > 0


def test_f4_upstream_already_fixed(eval_git_repo: Path) -> None:
    gv = GitVerifier(eval_git_repo)
    evaluator = ClaimEvaluator(gv)

    # lib/rand.c had weak_random at v1.0.0, but was modified upstream on HEAD
    rep = VulnerabilityReport(
        id="REPORT-F4",
        title="Report on stale version already fixed upstream",
        body="In `lib/rand.c:3`, function `weak_random()` is predictable.",
        stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
        claimed_version="v1.0.0",
    )
    res = evaluator.evaluate(rep)
    assert res.primary_class == FailureClass.F4_UPSTREAM_ALREADY_FIXED
    assert "lib/rand.c" in res.f4_upstream_modified


def test_f0_valid_anchor(eval_git_repo: Path) -> None:
    gv = GitVerifier(eval_git_repo)
    evaluator = ClaimEvaluator(gv)

    # lib/static.c:1 with stable_fn is valid at v1.0.0 and unchanged on HEAD
    rep = VulnerabilityReport(
        id="REPORT-F0",
        title="Valid report on current code",
        body="In `lib/static.c:1-3`, function `stable_fn()` lacks validation.",
        stratum=ReportStratum.CONFIRMED_ADVISORY,
        claimed_version="v1.0.0",
    )
    res = evaluator.evaluate(rep)
    assert res.primary_class == FailureClass.F0_VALID_ANCHOR
    assert res.f1_phantom_paths == []
    assert res.f2_phantom_symbols == []
    assert res.f3_oob_lines == []
    assert res.f4_upstream_modified == []

