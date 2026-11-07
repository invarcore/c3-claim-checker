# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Core evaluation pipeline mapping vulnerability reports to F0–F5 failure classes."""

from __future__ import annotations

from c3_claim_checker.extractor import ClaimExtractor
from c3_claim_checker.git_verifier import GitVerifier
from c3_claim_checker.models import ClaimAuditResult, FailureClass, VulnerabilityReport


class ClaimEvaluator:
    """Evaluates vulnerability reports against target Git repository trees."""

    def __init__(self, verifier: GitVerifier, upstream_branch: str = "HEAD") -> None:
        self.verifier = verifier
        self.upstream_branch = upstream_branch

    def evaluate(self, report: VulnerabilityReport) -> ClaimAuditResult:
        """Execute deterministic claim verification pipeline against report body and metadata."""
        text = f"{report.title}\n\n{report.body}"
        claimed_ref = self.verifier.resolve_ref(report.claimed_version or ClaimExtractor.extract_version_ref(text))

        file_claims = ClaimExtractor.extract_file_claims(text)
        symbols_cited = ClaimExtractor.extract_symbols(text)

        files_cited = sorted({fc.file_path for fc in file_claims})

        # F5: Unanchored Prose (Report cites zero checkable files or symbols)
        if not files_cited and not symbols_cited:
            return ClaimAuditResult(
                report_id=report.id,
                stratum=report.stratum.value,
                claimed_ref=claimed_ref,
                files_cited=[],
                symbols_cited=[],
                f1_phantom_paths=[],
                f2_phantom_symbols=[],
                f3_oob_lines=[],
                f4_upstream_modified=[],
                primary_class=FailureClass.F5_UNANCHORED_PROSE,
                details={"reason": "No checkable file paths or function symbols found in report text"},
            )

        f1_phantom_paths: list[str] = []
        f2_phantom_symbols: list[str] = []
        f3_oob_lines: list[str] = []
        f4_upstream_modified: list[str] = []
        existing_contents: dict[str, str] = {}

        # 1. Verify File Paths and Line Ranges
        for fc in file_claims:
            content = self.verifier.read_file_at_ref(claimed_ref, fc.file_path)
            if content is None:
                if fc.file_path not in f1_phantom_paths:
                    f1_phantom_paths.append(fc.file_path)
                continue

            existing_contents[fc.file_path] = content
            lines = content.splitlines()

            # Check Out-of-Bounds Line Numbers
            if fc.line_start is not None:
                end_lno = fc.line_end if fc.line_end else fc.line_start
                if fc.line_start < 1 or end_lno > len(lines):
                    f3_oob_lines.append(f"{fc.file_path}:{fc.line_start}-{end_lno} (File length: {len(lines)})")

            # Check if file was modified upstream on HEAD
            if (
                self.verifier.is_file_modified_upstream(claimed_ref, self.upstream_branch, fc.file_path)
                and fc.file_path not in f4_upstream_modified
            ):
                f4_upstream_modified.append(fc.file_path)

        # 2. Verify Symbols across cited files or repository tree
        for sym in symbols_cited:
            if existing_contents:
                found_in_cited = any(
                    self.verifier.symbol_exists_in_content(c, sym, fp) for fp, c in existing_contents.items()
                )
                if not found_in_cited and not self.verifier.symbol_exists_in_repo(claimed_ref, sym):
                    f2_phantom_symbols.append(sym)
            else:
                # If no cited files exist, check if symbol exists anywhere in repo tree
                if not self.verifier.symbol_exists_in_repo(claimed_ref, sym):
                    f2_phantom_symbols.append(sym)

        # 3. Assign Primary Failure Taxonomy Class
        if not existing_contents and f1_phantom_paths:
            primary = FailureClass.F1_PHANTOM_PATH
        elif f2_phantom_symbols:
            primary = FailureClass.F2_PHANTOM_SYMBOL
        elif f3_oob_lines:
            primary = FailureClass.F3_LINE_DRIFT_OR_OOB
        elif f4_upstream_modified:
            primary = FailureClass.F4_UPSTREAM_ALREADY_FIXED
        else:
            primary = FailureClass.F0_VALID_ANCHOR

        return ClaimAuditResult(
            report_id=report.id,
            stratum=report.stratum.value,
            claimed_ref=claimed_ref,
            files_cited=files_cited,
            symbols_cited=symbols_cited,
            f1_phantom_paths=f1_phantom_paths,
            f2_phantom_symbols=f2_phantom_symbols,
            f3_oob_lines=f3_oob_lines,
            f4_upstream_modified=f4_upstream_modified,
            primary_class=primary,
            details={
                "existing_files_count": len(existing_contents),
                "claimed_ref": claimed_ref,
            },
        )
