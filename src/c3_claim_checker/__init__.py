# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Candidate C3: Phantom Findings Verification Engine.

Deterministic verification of code grounding, phantom symbols, and structural
hallucinations in open-source vulnerability reports.
"""

from __future__ import annotations

from c3_claim_checker.evaluator import ClaimEvaluator
from c3_claim_checker.extractor import ClaimExtractor, ExtractedFileClaim
from c3_claim_checker.git_verifier import GitVerifier
from c3_claim_checker.models import (
    ClaimAuditResult,
    FailureClass,
    ReportStratum,
    VulnerabilityReport,
)

__version__ = "0.1.0"
__all__ = [
    "ClaimAuditResult",
    "ClaimEvaluator",
    "ClaimExtractor",
    "ExtractedFileClaim",
    "FailureClass",
    "GitVerifier",
    "ReportStratum",
    "VulnerabilityReport",
]

