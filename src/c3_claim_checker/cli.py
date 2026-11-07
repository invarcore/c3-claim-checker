# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""CLI entrypoint for Candidate C3 Claim Checker."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

from c3_claim_checker.evaluator import ClaimEvaluator
from c3_claim_checker.fetcher import CorpusFetcher
from c3_claim_checker.git_verifier import GitVerifier
from c3_claim_checker.models import ClaimAuditResult, FailureClass, ReportStratum, VulnerabilityReport


def run_fetch(args: argparse.Namespace) -> int:
    """Fetch vulnerability reports and save to JSONL."""
    reports: list[VulnerabilityReport] = []

    if args.stratum in ("A", "all"):
        print(f"[*] Fetching Stratum A (Closed negative controls from {args.repo}, label={args.label})...")
        try:
            stratum_a = CorpusFetcher.fetch_github_issues(
                repo=args.repo,
                label=args.label,
                limit=args.limit,
            )
            print(f"    Found {len(stratum_a)} Stratum A reports.")
            reports.extend(stratum_a)
        except (subprocess.CalledProcessError, OSError, ValueError) as e:
            print(f"[-] Error fetching Stratum A: {e}", file=sys.stderr)

    if args.stratum in ("B", "all"):
        print("[*] Fetching Stratum B (Confirmed ground-truth advisories from curl.se OSV)...")
        try:
            stratum_b = CorpusFetcher.fetch_curl_osv_advisories(limit=args.limit)
            print(f"    Found {len(stratum_b)} Stratum B advisories.")
            reports.extend(stratum_b)
        except (OSError, ValueError) as e:
            print(f"[-] Error fetching Stratum B: {e}", file=sys.stderr)

    out_path = Path(args.output).resolve()
    CorpusFetcher.save_reports_jsonl(reports, out_path)
    print(f"[+] Successfully wrote {len(reports)} total reports to {out_path}")
    return 0


def print_evaluation_summary(results: list[ClaimAuditResult]) -> None:
    """Print ASCII distribution table and research metrics for evaluated claims."""
    stratum_a_counts: Counter[str] = Counter()
    stratum_b_counts: Counter[str] = Counter()

    for r in results:
        if r.stratum == ReportStratum.REJECTED_OR_INFORMATIVE.value:
            stratum_a_counts[r.primary_class.value] += 1
        else:
            stratum_b_counts[r.primary_class.value] += 1

    total_a = sum(stratum_a_counts.values())
    total_b = sum(stratum_b_counts.values())

    print("\n" + "=" * 78)
    print(" Candidate C3: Deterministic Claim Verification & Grounding Evaluation")
    print("=" * 78)
    print(f"{'Failure Class':<30} | {'Stratum A (Negative)':<20} | {'Stratum B (Positive)':<20}")
    print("-" * 78)

    for fc in FailureClass:
        count_a = stratum_a_counts[fc.value]
        pct_a = (count_a / total_a * 100.0) if total_a > 0 else 0.0
        str_a = f"{count_a} ({pct_a:.1f}%)"

        count_b = stratum_b_counts[fc.value]
        pct_b = (count_b / total_b * 100.0) if total_b > 0 else 0.0
        str_b = f"{count_b} ({pct_b:.1f}%)"

        print(f"{fc.value:<30} | {str_a:<20} | {str_b:<20}")

    print("-" * 78)
    print(f"{'TOTAL AUDITED':<30} | {total_a:<20} | {total_b:<20}")
    print("=" * 78)

    # Key Research Metrics
    f1_a = stratum_a_counts[FailureClass.F1_PHANTOM_PATH.value]
    f2_a = stratum_a_counts[FailureClass.F2_PHANTOM_SYMBOL.value]
    f3_a = stratum_a_counts[FailureClass.F3_LINE_DRIFT_OR_OOB.value]
    f4_a = stratum_a_counts[FailureClass.F4_UPSTREAM_ALREADY_FIXED.value]
    f5_a = stratum_a_counts[FailureClass.F5_UNANCHORED_PROSE.value]

    structural_hallucinations_a = f1_a + f2_a + f3_a
    hallucination_rate_a = (structural_hallucinations_a / total_a * 100.0) if total_a > 0 else 0.0
    deterministic_filter_rate_a = (
        ((structural_hallucinations_a + f4_a + f5_a) / total_a * 100.0) if total_a > 0 else 0.0
    )

    false_negatives_b = (
        stratum_b_counts[FailureClass.F1_PHANTOM_PATH.value]
        + stratum_b_counts[FailureClass.F2_PHANTOM_SYMBOL.value]
        + stratum_b_counts[FailureClass.F3_LINE_DRIFT_OR_OOB.value]
    )
    fnr_b = (false_negatives_b / total_b * 100.0) if total_b > 0 else 0.0

    print(
        f"[*] RQ1 - Structural Hallucination Rate (F1+F2+F3 in Stratum A): {hallucination_rate_a:.1f}% ({structural_hallucinations_a}/{total_a})"
    )
    print(
        f"[*] RQ2 - Upstream Fix / Drift Rate (F4 in Stratum A):            {((f4_a / total_a * 100) if total_a else 0):.1f}% ({f4_a}/{total_a})"
    )
    print(f"[*] RQ3 - Zero-LLM Triage Disqualification Rate (Stratum A):      {deterministic_filter_rate_a:.1f}%")
    print(
        f"[*] RQ3 - False Negative Rate on Confirmed Advisories (Stratum B): {fnr_b:.1f}% ({false_negatives_b}/{total_b})"
    )
    print("=" * 78 + "\n")


def run_eval(args: argparse.Namespace) -> int:
    """Evaluate reports in a corpus JSONL against a local git repository."""
    corpus_path = Path(args.corpus).resolve()
    reports = CorpusFetcher.load_reports_jsonl(corpus_path)
    print(f"[*] Loaded {len(reports)} reports from {corpus_path}")

    verifier = GitVerifier(args.repo_dir)
    evaluator = ClaimEvaluator(verifier=verifier, upstream_branch=args.upstream)

    results: list[ClaimAuditResult] = []
    for rep in reports:
        res = evaluator.evaluate(rep)
        results.append(res)

    out_path = Path(args.output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(r.model_dump(), sort_keys=True) + "\n" for r in results)

    print(f"[+] Saved {len(results)} audit results to {out_path}")
    print_evaluation_summary(results)
    return 0


def main() -> None:
    """Main CLI entrypoint."""
    parser = argparse.ArgumentParser(
        prog="c3-claim-checker",
        description="Candidate C3: Deterministic Grounding & Hallucination Verifier for Vulnerability Reports",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: fetch
    fetch_parser = subparsers.add_parser("fetch", help="Fetch Stratum A and Stratum B corpora")
    fetch_parser.add_argument("--repo", default="curl/curl", help="Target GitHub repository (e.g. curl/curl)")
    fetch_parser.add_argument("--label", default="vuln:NONE", help="Issue label for Stratum A negative controls")
    fetch_parser.add_argument("--limit", type=int, default=50, help="Max reports per stratum")
    fetch_parser.add_argument("--stratum", choices=["A", "B", "all"], default="all", help="Which stratum to fetch")
    fetch_parser.add_argument("--output", default="data/c3_sample_corpus.jsonl", help="Output JSONL path")
    fetch_parser.set_defaults(func=run_fetch)

    # Subcommand: eval
    eval_parser = subparsers.add_parser("eval", help="Evaluate corpus against target Git repository")
    eval_parser.add_argument("--repo-dir", required=True, help="Path to local target git clone")
    eval_parser.add_argument("--corpus", default="data/c3_sample_corpus.jsonl", help="Path to input corpus JSONL")
    eval_parser.add_argument("--upstream", default="HEAD", help="Upstream branch to test F4 drift against")
    eval_parser.add_argument("--output", default="data/c3_sample_results.jsonl", help="Output results JSONL path")
    eval_parser.set_defaults(func=run_eval)

    parsed = parser.parse_args()
    sys.exit(parsed.func(parsed))


if __name__ == "__main__":
    main()
