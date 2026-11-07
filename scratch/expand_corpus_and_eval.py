# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Candidate C3: Expanded Multi-Language Corpus Construction & Evaluation.

Evaluates structural code grounding across three distinct language ecosystems:
1. C (curl/curl)
2. Go (go-gitea/gitea)
3. TypeScript / JavaScript (directus/directus)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Ensure package import
C3_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(C3_ROOT / "src"))

from c3_claim_checker.evaluator import ClaimEvaluator
from c3_claim_checker.fetcher import CorpusFetcher
from c3_claim_checker.git_verifier import GitVerifier
from c3_claim_checker.models import (
    ClaimAuditResult,
    FailureClass,
    ReportStratum,
    VulnerabilityReport,
)

DATA_DIR = C3_ROOT / "data"
CURL_REPO = DATA_DIR / "curl-repo"
GITEA_REPO = DATA_DIR / "gitea-repo"
DIRECTUS_REPO = DATA_DIR / "directus-repo"


def fetch_github_issue_item(repo: str, number: int) -> VulnerabilityReport | None:
    """Fetch single GitHub issue by number using gh CLI or API."""
    if shutil.which("gh"):
        cmd = [
            "gh",
            "issue",
            "view",
            str(number),
            "-R",
            repo,
            "--json",
            "number,title,body,createdAt,closedAt,labels",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode == 0:
            item = json.loads(proc.stdout)
            return VulnerabilityReport(
                id=f"{repo}#{item['number']}",
                stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
                title=item.get("title", ""),
                body=item.get("body", "") or "",
                target_repo=repo,
                created_at=item.get("createdAt"),
                closed_at=item.get("closedAt"),
                metadata={
                    "number": item.get("number"),
                    "labels": [lbl.get("name") for lbl in item.get("labels", []) if isinstance(lbl, dict)],
                    "fetch_source": "gh_cli_single",
                },
            )
    return None


def main() -> int:
    print("=" * 80)
    print(" Candidate C3: Multi-Language Corpus Expansion & Evaluation")
    print("=" * 80)

    # 1. Load Baseline curl Corpus (39 reports)
    baseline_corpus_path = DATA_DIR / "c3_sample_corpus.jsonl"
    all_reports: list[VulnerabilityReport] = []
    if baseline_corpus_path.exists():
        curl_reports = CorpusFetcher.load_reports_jsonl(baseline_corpus_path)
        all_reports.extend(curl_reports)
        print(f"[*] Loaded {len(curl_reports)} baseline reports from curl (C)")
    else:
        print("[-] Baseline curl corpus not found!")
        return 1

    # 2. Fetch Stratum A for Gitea (Go)
    gitea_stratum_a_numbers = [38718, 38719, 38726, 39230, 38784, 38769, 39684, 39647]
    gitea_a_reports = []
    print("\n[*] Fetching Stratum A for go-gitea/gitea (Go)...")
    for num in gitea_stratum_a_numbers:
        rep = fetch_github_issue_item("go-gitea/gitea", num)
        if rep:
            gitea_a_reports.append(rep)
            print(f"    [+] Ingested gitea#{num}: {rep.title[:50]}...")
    all_reports.extend(gitea_a_reports)
    print(f"    Total Gitea Stratum A: {len(gitea_a_reports)}")

    # 3. Fetch Stratum B for Gitea (Go - OSV)
    print("\n[*] Fetching Stratum B for go-gitea/gitea from OSV (Go)...")
    gitea_b_reports = CorpusFetcher.fetch_osv_package_advisories(
        package_name="code.gitea.io/gitea",
        ecosystem="Go",
        target_repo="go-gitea/gitea",
        limit=25,
    )
    all_reports.extend(gitea_b_reports)
    print(f"    Total Gitea Stratum B: {len(gitea_b_reports)}")

    # 4. Fetch Stratum A for Directus (TypeScript / Node.js)
    directus_stratum_a_numbers = [5677, 5678, 5686, 7432, 11688, 21159, 21589, 23459]
    directus_a_reports = []
    print("\n[*] Fetching Stratum A for directus/directus (TypeScript)...")
    for num in directus_stratum_a_numbers:
        rep = fetch_github_issue_item("directus/directus", num)
        if rep:
            directus_a_reports.append(rep)
            print(f"    [+] Ingested directus#{num}: {rep.title[:50]}...")
    all_reports.extend(directus_a_reports)
    print(f"    Total Directus Stratum A: {len(directus_a_reports)}")

    # 5. Fetch Stratum B for Directus (TypeScript - OSV)
    print("\n[*] Fetching Stratum B for directus/directus from OSV (npm)...")
    directus_b_reports = CorpusFetcher.fetch_osv_package_advisories(
        package_name="directus",
        ecosystem="npm",
        target_repo="directus/directus",
        limit=25,
    )
    all_reports.extend(directus_b_reports)
    print(f"    Total Directus Stratum B: {len(directus_b_reports)}")

    # Save expanded corpus
    expanded_corpus_path = DATA_DIR / "c3_expanded_corpus.jsonl"
    CorpusFetcher.save_reports_jsonl(all_reports, expanded_corpus_path)
    print(f"\n[+] Saved expanded corpus ({len(all_reports)} reports) to {expanded_corpus_path}")

    # 6. Initialize Verifiers per Repository
    verifiers = {
        "curl/curl": GitVerifier(CURL_REPO),
        "go-gitea/gitea": GitVerifier(GITEA_REPO),
        "directus/directus": GitVerifier(DIRECTUS_REPO),
    }

    evaluators = {repo: ClaimEvaluator(v) for repo, v in verifiers.items()}

    # 7. Execute Evaluation Across Multi-Language Dataset
    print("\n[*] Evaluating reports across all 3 language repositories...")
    results: list[ClaimAuditResult] = []
    for rep in all_reports:
        ev = evaluators.get(rep.target_repo, evaluators["curl/curl"])
        res = ev.evaluate(rep)
        results.append(res)

    # Save expanded results
    expanded_results_path = DATA_DIR / "c3_expanded_results.jsonl"
    with open(expanded_results_path, "w", encoding="utf-8") as f:
        f.writelines(json.dumps(r.model_dump(), sort_keys=True) + "\n" for r in results)
    print(f"[+] Saved evaluation results to {expanded_results_path}")

    # 8. Print Comparative Multi-Language Breakdown
    print("\n" + "=" * 90)
    print(f"{'Repository / Ecosystem':<25} | {'Stratum A (Negative)':<20} | {'Stratum B (Positive)':<20} | {'Total':<10}")
    print("-" * 90)
    repo_counts = Counter(r.target_repo for r in all_reports)
    for repo, count in repo_counts.items():
        a_count = sum(1 for r in all_reports if r.target_repo == repo and r.stratum == ReportStratum.REJECTED_OR_INFORMATIVE)
        b_count = sum(1 for r in all_reports if r.target_repo == repo and r.stratum == ReportStratum.CONFIRMED_ADVISORY)
        print(f"{repo:<25} | {a_count:<20} | {b_count:<20} | {count:<10}")
    print("-" * 90)
    print(f"{'ALL ECOSYSTEMS':<25} | {sum(1 for r in all_reports if r.stratum == ReportStratum.REJECTED_OR_INFORMATIVE):<20} | {sum(1 for r in all_reports if r.stratum == ReportStratum.CONFIRMED_ADVISORY):<20} | {len(all_reports):<10}")
    print("=" * 90)

    # 9. Detailed Cross-Language Grounding Metrics
    print("\n" + "=" * 90)
    print(" Cross-Language Failure Taxonomy Distribution (F0–F5)")
    print("=" * 90)
    print(f"{'Failure Class':<30} | {'Stratum A (Neg, N=' + str(sum(1 for r in all_reports if r.stratum == ReportStratum.REJECTED_OR_INFORMATIVE)) + ')':<25} | {'Stratum B (Pos, N=' + str(sum(1 for r in all_reports if r.stratum == ReportStratum.CONFIRMED_ADVISORY)) + ')':<25}")
    print("-" * 90)

    strat_a_counts = Counter(r.primary_class.value for r in results if r.stratum == ReportStratum.REJECTED_OR_INFORMATIVE.value)
    strat_b_counts = Counter(r.primary_class.value for r in results if r.stratum == ReportStratum.CONFIRMED_ADVISORY.value)
    tot_a = sum(strat_a_counts.values())
    tot_b = sum(strat_b_counts.values())

    for fc in FailureClass:
        ca = strat_a_counts[fc.value]
        cb = strat_b_counts[fc.value]
        pa = (ca / tot_a * 100.0) if tot_a else 0.0
        pb = (cb / tot_b * 100.0) if tot_b else 0.0
        print(f"{fc.value:<30} | {f'{ca} ({pa:.1f}%)':<25} | {f'{cb} ({pb:.1f}%)':<25}")

    print("-" * 90)
    print(f"{'TOTAL AUDITED':<30} | {tot_a:<25} | {tot_b:<25}")
    print("=" * 90)

    # Summary Metrics
    f1_a = strat_a_counts[FailureClass.F1_PHANTOM_PATH.value]
    f2_a = strat_a_counts[FailureClass.F2_PHANTOM_SYMBOL.value]
    f3_a = strat_a_counts[FailureClass.F3_LINE_DRIFT_OR_OOB.value]
    f0_a = strat_a_counts[FailureClass.F0_VALID_ANCHOR.value]
    f5_b = strat_b_counts[FailureClass.F5_UNANCHORED_PROSE.value]
    f0_b = strat_b_counts[FailureClass.F0_VALID_ANCHOR.value]
    false_neg_b = tot_b - (f0_b + f5_b)

    print("\n" + "=" * 90)
    print(" Core Empirical Conclusions Across C, Go, and TypeScript:")
    print(f" 1. Cross-Language Syntactic Grounding Rate (F0): {f0_a}/{tot_a} ({f0_a/tot_a*100.0:.1f}%)")
    print(f" 2. Cross-Language Phantom File Rate (F1):          {f1_a}/{tot_a} ({f1_a/tot_a*100.0:.1f}%)")
    print(f" 3. Cross-Language False Negative Rate on True CVEs: {false_neg_b}/{tot_b} ({false_neg_b/tot_b*100.0:.1f}%)")
    print("=" * 90)

    return 0


if __name__ == "__main__":
    sys.exit(main())
