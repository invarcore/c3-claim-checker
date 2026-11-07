# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for CorpusFetcher JSONL serialization and mapping."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from c3_claim_checker.fetcher import CorpusFetcher
from c3_claim_checker.models import ReportStratum, VulnerabilityReport


def test_reports_jsonl_roundtrip(tmp_path: Path) -> None:
    rep1 = VulnerabilityReport(
        id="curl/curl#100",
        stratum=ReportStratum.REJECTED_OR_INFORMATIVE,
        title="Sample rejected bug",
        body="Details on weak_random in lib/rand.c",
        target_repo="curl/curl",
        claimed_version="8.18.0",
        metadata={"labels": ["vuln:NONE"]},
    )
    rep2 = VulnerabilityReport(
        id="CVE-2024-5535",
        stratum=ReportStratum.CONFIRMED_ADVISORY,
        title="Confirmed advisory",
        body="Buffer overflow in urlapi.c",
        target_repo="curl/curl",
        claimed_version="8.9.0",
    )

    out_file = tmp_path / "corpus.jsonl"
    CorpusFetcher.save_reports_jsonl([rep1, rep2], out_file)
    assert out_file.exists()

    loaded = CorpusFetcher.load_reports_jsonl(out_file)
    assert len(loaded) == 2
    assert loaded[0].id == rep1.id
    assert loaded[0].stratum == ReportStratum.REJECTED_OR_INFORMATIVE
    assert loaded[1].id == rep2.id
    assert loaded[1].stratum == ReportStratum.CONFIRMED_ADVISORY


def test_load_nonexistent_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        CorpusFetcher.load_reports_jsonl(tmp_path / "does_not_exist.jsonl")


def test_fetch_curl_osv_advisories_mapping() -> None:
    sample_osv_data = [
        {
            "id": "CURL-CVE-2026-9999",
            "aliases": ["CVE-2026-9999"],
            "summary": "Mock vulnerability",
            "details": "Details about mock bug in lib/sendf.c",
            "published": "2026-10-01T00:00:00Z",
            "modified": "2026-10-02T00:00:00Z",
            "affected": [
                {
                    "versions": ["8.10.0", "8.11.0"],
                }
            ],
        }
    ]

    mock_resp = MagicMock()
    mock_resp.json.return_value = sample_osv_data
    mock_resp.raise_for_status.return_value = None

    with patch("httpx.Client.get", return_value=mock_resp):
        reports = CorpusFetcher.fetch_curl_osv_advisories(limit=10)
        assert len(reports) == 1
        rep = reports[0]
        assert rep.id == "CVE-2026-9999"
        assert rep.stratum == ReportStratum.CONFIRMED_ADVISORY
        assert rep.claimed_version == "8.10.0"
        assert rep.title == "Mock vulnerability"


def test_fetch_github_issues_gh_cli() -> None:
    mock_gh_output = json.dumps(
        [
            {
                "number": 23800,
                "title": "Weak PRNG",
                "body": "Body in rand.c",
                "createdAt": "2026-11-07T00:00:00Z",
                "closedAt": "2026-11-07T10:00:00Z",
                "labels": [{"name": "vuln:NONE"}],
            }
        ]
    )

    proc = MagicMock()
    proc.stdout = mock_gh_output
    proc.returncode = 0

    with patch("shutil.which", return_value="/usr/bin/gh"), patch("subprocess.run", return_value=proc):
        reps = CorpusFetcher.fetch_github_issues(repo="curl/curl", limit=5)
        assert len(reps) == 1
        assert reps[0].id == "curl/curl#23800"
        assert reps[0].stratum == ReportStratum.REJECTED_OR_INFORMATIVE
        assert reps[0].metadata["fetch_source"] == "gh_cli"


def test_fetch_github_issues_httpx_fallback() -> None:
    mock_api_data = [
        {
            "number": 1234,
            "title": "HTTPX Issue",
            "body": "Body via REST API",
            "created_at": "2026-11-01T00:00:00Z",
            "closed_at": "2026-11-02T00:00:00Z",
            "labels": [{"name": "not-a-curl-bug"}],
        },
        {
            "number": 1235,
            "pull_request": {},  # Should be excluded
            "title": "PR to skip",
        },
    ]

    mock_resp = MagicMock()
    mock_resp.json.return_value = mock_api_data
    mock_resp.raise_for_status.return_value = None

    with patch("shutil.which", return_value=None), patch("httpx.Client.get", return_value=mock_resp):
        reps = CorpusFetcher.fetch_github_issues(repo="curl/curl", limit=5)
        assert len(reps) == 1
        assert reps[0].id == "curl/curl#1234"
        assert reps[0].metadata["fetch_source"] == "github_rest_api"
