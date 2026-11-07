# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for code anchor and symbol extractor."""

from __future__ import annotations

from c3_claim_checker.extractor import ClaimExtractor


def test_extract_file_claims_colon_format() -> None:
    text = "Vulnerability in `lib/urlapi.c:1355-1362` and `src/tool_operate.c:42`."
    claims = ClaimExtractor.extract_file_claims(text)
    by_path = {c.file_path: c for c in claims}

    assert "lib/urlapi.c" in by_path
    assert by_path["lib/urlapi.c"].line_start == 1355
    assert by_path["lib/urlapi.c"].line_end == 1362

    assert "src/tool_operate.c" in by_path
    assert by_path["src/tool_operate.c"].line_start == 42
    assert by_path["src/tool_operate.c"].line_end == 42


def test_extract_file_claims_prose_format() -> None:
    text = "Examined random generation in `lib/rand.c` (lines 40-84) and `lib/vtls/openssl.c` at line 120."
    claims = ClaimExtractor.extract_file_claims(text)
    by_path = {c.file_path: c for c in claims}

    assert "lib/rand.c" in by_path
    assert by_path["lib/rand.c"].line_start == 40
    assert by_path["lib/rand.c"].line_end == 84

    assert "lib/vtls/openssl.c" in by_path
    assert by_path["lib/vtls/openssl.c"].line_start == 120
    assert by_path["lib/vtls/openssl.c"].line_end == 120


def test_extract_symbols() -> None:
    text = "The weak_random() function calls `Curl_rand` and method `parse_url`."
    symbols = ClaimExtractor.extract_symbols(text)
    assert "weak_random" in symbols
    assert "Curl_rand" in symbols
    assert "parse_url" in symbols
    # Filter keywords
    assert "function" not in symbols


def test_extract_version_ref() -> None:
    text1 = "Reproduced on curl 8.18.0 under Fedora."
    assert ClaimExtractor.extract_version_ref(text1) == "8.18.0"

    text2 = "Affects tag curl-7_88_0 in git."
    assert ClaimExtractor.extract_version_ref(text2) == "7_88_0"

    text3 = "No version mentioned anywhere here."
    assert ClaimExtractor.extract_version_ref(text3) is None

