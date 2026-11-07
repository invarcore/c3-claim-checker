# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Candidate C3 CLI commands and summary reports."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path
from unittest.mock import patch

from c3_claim_checker.cli import main, print_evaluation_summary, run_eval, run_fetch
from c3_claim_checker.fetcher import CorpusFetcher
from c3_claim_checker.models import ClaimAuditResult, FailureClass, ReportStratum, VulnerabilityReport


def test_print_evaluation_summary_runs_cleanly(capsys) -> None:
    results = [
        ClaimAuditResult(
            report_id="R1",
            stratum=ReportStratum.REJECTED_OR_INFORMATIVE.value,
            claimed_ref="HEAD",
            files_cited=["lib/rand.c"],
            symbols_cited=["weak_random"],
            f1_phantom_paths=[],
            f2_phantom_symbols=[],
            f3_oob_lines=[],
            f4_upstream_modified=["lib/rand.c"],
            primary_class=FailureClass.F4_UPSTREAM_ALREADY_FIXED,
        ),
        ClaimAuditResult(
            report_id="R2",
            stratum=ReportStratum.CONFIRMED_ADVISORY.value,
            claimed_ref="HEAD",
            files_cited=["lib/static.c"],
            symbols_cited=["stable_fn"],
            f1_phantom_paths=[],
            f2_phantom_symbols=[],
            f3_oob_lines=[],
            f4_upstream_modified=[],
            primary_class=FailureClass.F0_VALID_ANCHOR,
        ),
    ]

    print_evaluation_summary(results)
    captured = capsys.readouterr()
    assert "Candidate C3: Deterministic Claim Verification & Grounding Evaluation" in captured.out
    assert "F4_UPSTREAM_ALREADY_FIXED" in captured.out
    assert "F0_VALID_ANCHOR" in captured.out
    assert "RQ1 - Structural Hallucination Rate" in captured.out


def test_run_eval_cli(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Tester"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "tester@invarcore.org"], check=True)

    src_file = repo / "main.c"
    src_file.write_text("void app_main(void) {}\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "init"], check=True)

    corpus_file = tmp_path / "corpus.jsonl"
    results_file = tmp_path / "results.jsonl"

    rep = VulnerabilityReport(
        id="R1",
        title="Valid report",
        body="In `main.c:1` function `app_main()`",
        stratum=ReportStratum.CONFIRMED_ADVISORY,
    )
    CorpusFetcher.save_reports_jsonl([rep], corpus_file)

    args = argparse.Namespace(
        repo_dir=str(repo),
        corpus=str(corpus_file),
        upstream="HEAD",
        output=str(results_file),
    )
    exit_code = run_eval(args)
    assert exit_code == 0
    assert results_file.exists()


def test_run_fetch_cli(tmp_path: Path) -> None:
    out_file = tmp_path / "fetched.jsonl"
    dummy_rep_a = VulnerabilityReport(id="A#1", title="A", stratum=ReportStratum.REJECTED_OR_INFORMATIVE)
    dummy_rep_b = VulnerabilityReport(id="CVE-B", title="B", stratum=ReportStratum.CONFIRMED_ADVISORY)

    with (
        patch("c3_claim_checker.fetcher.CorpusFetcher.fetch_github_issues", return_value=[dummy_rep_a]),
        patch("c3_claim_checker.fetcher.CorpusFetcher.fetch_curl_osv_advisories", return_value=[dummy_rep_b]),
    ):
        args = argparse.Namespace(
            repo="curl/curl",
            label="vuln:NONE",
            limit=10,
            stratum="all",
            output=str(out_file),
        )
        code = run_fetch(args)
        assert code == 0
        assert out_file.exists()
        loaded = CorpusFetcher.load_reports_jsonl(out_file)
        assert len(loaded) == 2


def test_main_help_exits_cleanly() -> None:
    try:
        import sys

        sys.argv = ["c3-claim-checker", "--help"]
        main()
    except SystemExit as e:
        assert e.code == 0
