# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Corpus fetcher and dataset persistence for Stratum A and Stratum B vulnerability reports."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import httpx

from c3_claim_checker.models import ReportStratum, VulnerabilityReport

CURL_VULN_OSV_URL = "https://curl.se/docs/vuln.json"


class CorpusFetcher:
    """Fetches, maps, and serializes vulnerability report corpora."""

    @classmethod
    def fetch_github_issues(
        cls,
        repo: str = "curl/curl",
        label: str = "vuln:NONE",
        state: str = "closed",
        limit: int = 50,
    ) -> list[VulnerabilityReport]:
        """Fetch vulnerability issues from GitHub using gh CLI or httpx REST API fallback."""
        reports: list[VulnerabilityReport] = []

        # Prefer gh CLI if available in environment
        if shutil.which("gh"):
            try:
                cmd = [
                    "gh",
                    "issue",
                    "list",
                    "-R",
                    repo,
                    "--state",
                    state,
                    "--label",
                    label,
                    "--limit",
                    str(limit),
                    "--json",
                    "number,title,body,createdAt,closedAt,labels",
                ]
                proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
                raw_issues = json.loads(proc.stdout)
                for item in raw_issues:
                    rep = VulnerabilityReport(
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
                            "fetch_source": "gh_cli",
                        },
                    )
                    reports.append(rep)
                return reports
            except (subprocess.CalledProcessError, OSError, ValueError, json.JSONDecodeError):
                # Fall through to HTTP client
                pass

        # Fallback to GitHub REST API via httpx
        url = f"https://api.github.com/repos/{repo}/issues"
        params: dict[str, Any] = {
            "state": state,
            "labels": label,
            "per_page": min(limit, 100),
        }
        headers = {"Accept": "application/vnd.github+json"}
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        with httpx.Client(timeout=30.0, headers=headers) as client:
            resp = client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            for item in data[:limit]:
                # Exclude pull requests which GitHub includes in /issues endpoint
                if "pull_request" in item:
                    continue
                rep = VulnerabilityReport(
                    id=f"{repo}#{item['number']}",
                    stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
                    title=item.get("title", ""),
                    body=item.get("body", "") or "",
                    target_repo=repo,
                    created_at=item.get("created_at"),
                    closed_at=item.get("closed_at"),
                    metadata={
                        "number": item.get("number"),
                        "labels": [lbl.get("name") for lbl in item.get("labels", []) if isinstance(lbl, dict)],
                        "fetch_source": "github_rest_api",
                    },
                )
                reports.append(rep)

        return reports

    @classmethod
    def fetch_curl_osv_advisories(
        cls,
        limit: int | None = None,
        url: str = CURL_VULN_OSV_URL,
    ) -> list[VulnerabilityReport]:
        """Fetch confirmed ground-truth CVE advisories from curl.se OSV endpoint (Stratum B)."""
        reports: list[VulnerabilityReport] = []
        with httpx.Client(timeout=30.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            records = resp.json()

        if limit is not None:
            records = records[:limit]

        for item in records:
            cve_id = item.get("id", "UNKNOWN-CVE")
            aliases = item.get("aliases", [])
            primary_id = aliases[0] if aliases else cve_id

            # Extract claimed version from affected array
            claimed_version: str | None = None
            affected_entries = item.get("affected", [])
            if affected_entries:
                first_aff = affected_entries[0]
                versions = first_aff.get("versions", [])
                if versions:
                    # Pick earliest or latest version in range
                    claimed_version = versions[0]

            rep = VulnerabilityReport(
                id=primary_id,
                stratum=ReportStratum.CONFIRMED_ADVISORY,
                title=item.get("summary", ""),
                body=item.get("details", "") or "",
                target_repo="curl/curl",
                claimed_version=claimed_version,
                created_at=item.get("published"),
                closed_at=item.get("modified"),
                metadata={
                    "osv_id": cve_id,
                    "aliases": aliases,
                    "database_specific": item.get("database_specific", {}),
                    "affected": affected_entries,
                    "fetch_source": "curl_se_osv",
                },
            )
            reports.append(rep)

        return reports

    @classmethod
    def save_reports_jsonl(cls, reports: list[VulnerabilityReport], path: Path | str) -> None:
        """Serialize reports to JSONL with RFC 8785 canonical key ordering."""
        out_file = Path(path).resolve()
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8") as f:
            f.writelines(json.dumps(rep.model_dump(), sort_keys=True) + "\n" for rep in reports)

    @classmethod
    def load_reports_jsonl(cls, path: Path | str) -> list[VulnerabilityReport]:
        """Load reports from a JSONL file."""
        inp_file = Path(path).resolve()
        if not inp_file.exists():
            raise FileNotFoundError(f"Corpus file does not exist: {inp_file}")

        reports: list[VulnerabilityReport] = []
        with open(inp_file, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    data = json.loads(stripped)
                    reports.append(VulnerabilityReport.model_validate(data))
        return reports
