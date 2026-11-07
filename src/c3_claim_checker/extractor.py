# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Heuristic and regex extraction engine for file paths, line ranges, and symbols."""

from __future__ import annotations

import re
from typing import NamedTuple

FILE_EXTS = r"(?:c|h|cc|cpp|py|ts|js|go|rs|java|rb|php|sh|pl)"

FILE_LINE_COLON_RE = re.compile(
    rf"(?:`|\b)([a-zA-Z0-9_./-]+\.{FILE_EXTS})(?::(\d+)(?:-(\d+))?)?(?:`|\b)",
    re.IGNORECASE,
)

FILE_LINE_PROSE_RE = re.compile(
    rf"(?:`|\b)([a-zA-Z0-9_./-]+\.{FILE_EXTS})(?:`|\b)[^.\n\r]*?\b(?:lines?|l\.)\s*(\d+)(?:\s*(?:-|to)\s*(\d+))?",
    re.IGNORECASE,
)

FUNC_CLAIM_RE = re.compile(
    r"(?:function|method|symbol|in|calls)\s+`([a-zA-Z_][a-zA-Z0-9_:]*)`|\b([a-zA-Z_][a-zA-Z0-9_]{2,})\(\)",
    re.IGNORECASE,
)

VERSION_RE = re.compile(
    r"\b(v?\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)\b|\bcurl-(\d+_\d+_\d+)\b",
    re.IGNORECASE,
)

SYSTEM_HEADERS = {
    "assert.h",
    "ctype.h",
    "errno.h",
    "fcntl.h",
    "limits.h",
    "signal.h",
    "stdbool.h",
    "stdint.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
    "time.h",
    "unistd.h",
}


class ExtractedFileClaim(NamedTuple):
    file_path: str
    line_start: int | None
    line_end: int | None


class ClaimExtractor:
    """Extracts verifiable code anchors from raw vulnerability report text."""

    @classmethod
    def normalize_repo_path(cls, raw_path: str) -> str | None:
        """Clean raw file path, stripping GitHub URLs, diff prefixes, and filtering system headers."""
        p = raw_path.strip().lstrip("./").lstrip("/")

        # Clean GitHub URLs (e.g. github.com/curl/curl/blob/<commit>/lib/vquic/vquic.c)
        gh_match = re.search(r"github\.com/[^/]+/[^/]+/blob/[a-f0-9]+/([a-zA-Z0-9_./-]+)", p, re.IGNORECASE)
        if gh_match:
            p = gh_match.group(1)

        # Strip diff patch prefixes 'a/' and 'b/'
        if p.startswith(("a/", "b/")) and len(p) > 2 and "/" in p[2:]:
            p = p[2:]

        # Filter standard system headers
        basename = p.split("/")[-1].lower()
        if basename in SYSTEM_HEADERS:
            return None

        return p

    @classmethod
    def extract_file_claims(cls, text: str) -> list[ExtractedFileClaim]:
        """Extract all cited file paths and optional line numbers."""
        claims_dict: dict[str, ExtractedFileClaim] = {}

        # 1. Match colon format: path/to/file.c:10-20
        for fpath, l_start, l_end in FILE_LINE_COLON_RE.findall(text):
            clean_path = cls.normalize_repo_path(fpath)
            if not clean_path:
                continue
            start = int(l_start) if l_start else None
            end = int(l_end) if l_end else start
            if clean_path not in claims_dict or (start is not None and claims_dict[clean_path].line_start is None):
                claims_dict[clean_path] = ExtractedFileClaim(file_path=clean_path, line_start=start, line_end=end)

        # 2. Match prose format: path/to/file.c (lines 40-84)
        for fpath, l_start, l_end in FILE_LINE_PROSE_RE.findall(text):
            clean_path = cls.normalize_repo_path(fpath)
            if not clean_path:
                continue
            start = int(l_start) if l_start else None
            end = int(l_end) if l_end else start
            if clean_path not in claims_dict or (start is not None and claims_dict[clean_path].line_start is None):
                claims_dict[clean_path] = ExtractedFileClaim(file_path=clean_path, line_start=start, line_end=end)

        return list(claims_dict.values())

    @classmethod
    def extract_symbols(cls, text: str) -> list[str]:
        """Extract cited function, method, or symbol names."""
        matches = FUNC_CLAIM_RE.findall(text)
        symbols = set()
        for m in matches:
            sym = (m[0] or m[1] or "").strip()
            # Filter common false-positive keywords
            if sym and sym.lower() not in {"if", "for", "while", "return", "switch", "assert", "function", "main"}:
                symbols.add(sym)
        return sorted(symbols)

    @classmethod
    def extract_version_ref(cls, text: str) -> str | None:
        """Infer claimed version tag or commit reference."""
        m = VERSION_RE.search(text)
        if not m:
            return None
        return m.group(1) or m.group(2)
