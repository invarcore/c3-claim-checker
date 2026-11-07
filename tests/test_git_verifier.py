# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Git tree and AST verifier using synthetic repository fixtures."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from c3_claim_checker.git_verifier import GitVerifier


@pytest.fixture
def synthetic_git_repo(tmp_path: Path) -> Path:
    """Create a temporary git repository with tags and history."""
    repo = tmp_path / "test_repo"
    repo.mkdir()

    # git init
    subprocess.run(["git", "-C", str(repo), "init"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test User"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@invarcore.org"], check=True)

    # Commit 1: Tag v1.0.0 / curl-8_18_0
    lib_dir = repo / "lib"
    lib_dir.mkdir()
    rand_c = lib_dir / "rand.c"
    rand_c.write_text(
        "/* rand.c */\nint weak_random(void) {\n    return 42;\n}\n",
        encoding="utf-8",
    )
    mod_py = repo / "module.py"
    mod_py.write_text(
        "class AuthManager:\n    def parse_token(self):\n        return True\n",
        encoding="utf-8",
    )

    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "Initial commit"], check=True)
    subprocess.run(["git", "-C", str(repo), "tag", "v1.0.0"], check=True)
    subprocess.run(["git", "-C", str(repo), "tag", "curl-8_18_0"], check=True)

    # Commit 2: Upstream modification on HEAD
    rand_c.write_text(
        "/* rand.c */\nint secure_random(void) {\n    return 100;\n}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-m", "Secure random fix upstream"], check=True)

    return repo


def test_invalid_repo_raises(tmp_path: Path) -> None:
    non_repo = tmp_path / "not_git"
    non_repo.mkdir()
    with pytest.raises(ValueError, match="not a valid Git repository"):
        GitVerifier(non_repo)


def test_resolve_ref(synthetic_git_repo: Path) -> None:
    gv = GitVerifier(synthetic_git_repo)
    assert gv.resolve_ref("v1.0.0") == "v1.0.0"
    assert gv.resolve_ref("1.0.0") == "v1.0.0"
    assert gv.resolve_ref("8.18.0") == "curl-8_18_0"
    assert gv.resolve_ref("nonexistent_tag") == "HEAD"
    assert gv.resolve_ref(None) == "HEAD"


def test_read_file_at_ref(synthetic_git_repo: Path) -> None:
    gv = GitVerifier(synthetic_git_repo)
    # At tag v1.0.0, weak_random exists
    content_v1 = gv.read_file_at_ref("v1.0.0", "lib/rand.c")
    assert content_v1 is not None
    assert "weak_random" in content_v1

    # At HEAD, secure_random exists
    content_head = gv.read_file_at_ref("HEAD", "lib/rand.c")
    assert content_head is not None
    assert "secure_random" in content_head

    # Missing file returns None
    assert gv.read_file_at_ref("HEAD", "lib/phantom.c") is None


def test_symbol_exists_in_content(synthetic_git_repo: Path) -> None:
    gv = GitVerifier(synthetic_git_repo)

    # Python AST symbol
    py_code = "class Worker:\n    async def process_task(self):\n        pass\n"
    assert gv.symbol_exists_in_content(py_code, "Worker", "app.py") is True
    assert gv.symbol_exists_in_content(py_code, "process_task", "app.py") is True
    assert gv.symbol_exists_in_content(py_code, "missing_func", "app.py") is False

    # Python syntax error fallback to word boundary
    broken_py = "def broken( {\n"
    assert gv.symbol_exists_in_content(broken_py, "broken", "app.py") is True

    # C Function signature
    c_code = "int *Curl_rand(struct Curl_easy *data) {\n    return 0;\n}\n"
    assert gv.symbol_exists_in_content(c_code, "Curl_rand", "rand.c") is True
    assert gv.symbol_exists_in_content(c_code, "phantom_func", "rand.c") is False

    # Word boundary fallback
    header_code = "#define HAVE_LIBPSL 1\n"
    assert gv.symbol_exists_in_content(header_code, "HAVE_LIBPSL", "config.h") is True


def test_is_file_modified_upstream(synthetic_git_repo: Path) -> None:
    gv = GitVerifier(synthetic_git_repo)
    # lib/rand.c changed between v1.0.0 and HEAD
    assert gv.is_file_modified_upstream("v1.0.0", "HEAD", "lib/rand.c") is True
    # module.py is unchanged between v1.0.0 and HEAD
    assert gv.is_file_modified_upstream("v1.0.0", "HEAD", "module.py") is False
    # non-existent file returns False
    assert gv.is_file_modified_upstream("v1.0.0", "HEAD", "missing.c") is False
