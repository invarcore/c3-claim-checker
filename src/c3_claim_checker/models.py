# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Data models and failure taxonomy for Candidate C3 Claim Verification."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class FailureClass(str, Enum):
    """Six-Class Failure Taxonomy for Vulnerability Report Grounding (F0–F5)."""

    F0_VALID_ANCHOR = "F0_VALID_ANCHOR"
    F1_PHANTOM_PATH = "F1_PHANTOM_PATH"
    F2_PHANTOM_SYMBOL = "F2_PHANTOM_SYMBOL"
    F3_LINE_DRIFT_OR_OOB = "F3_LINE_DRIFT_OR_OOB"
    F4_UPSTREAM_ALREADY_FIXED = "F4_UPSTREAM_ALREADY_FIXED"
    F5_UNANCHORED_PROSE = "F5_UNANCHORED_PROSE"


class ReportStratum(str, Enum):
    """Evaluation stratum for ground-truth controls."""

    REJECTED_OR_INFORMATIVE = "rejected_or_informative"  # Stratum A: Negative controls
    CONFIRMED_ADVISORY = "confirmed_advisory"  # Stratum B: Positive controls (GHSAs/OSV)


class VulnerabilityReport(BaseModel):
    """Standardized ingested vulnerability report schema."""

    id: str
    stratum: ReportStratum = ReportStratum.REJECTED_OR_INFORMATIVE
    title: str = ""
    body: str = ""
    target_repo: str = ""  # e.g. "curl/curl"
    claimed_version: str | None = None
    created_at: str | None = None
    closed_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClaimAuditResult(BaseModel):
    """Deterministic audit record emitted per evaluated vulnerability report."""

    report_id: str
    stratum: str
    claimed_ref: str
    files_cited: list[str] = Field(default_factory=list)
    symbols_cited: list[str] = Field(default_factory=list)
    f1_phantom_paths: list[str] = Field(default_factory=list)
    f2_phantom_symbols: list[str] = Field(default_factory=list)
    f3_oob_lines: list[str] = Field(default_factory=list)
    f4_upstream_modified: list[str] = Field(default_factory=list)
    primary_class: FailureClass
    details: dict[str, Any] = Field(default_factory=dict)
