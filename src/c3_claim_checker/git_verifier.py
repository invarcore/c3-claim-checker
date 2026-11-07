# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Deterministic Git tree and AST verification engine."""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

STANDARD_SYMBOLS = {
    "FALSE",
    "INT_MAX",
    "INT_MIN",
    "NULL",
    "SIZE_MAX",
    "TRUE",
    "UINT_MAX",
    "bool",
    "errno",
    "exit",
    "free",
    "int16_t",
    "int32_t",
    "int64_t",
    "int8_t",
    "main",
    "malloc",
    "realloc",
    "size_t",
    "ssize_t",
    "stderr",
    "stdin",
    "stdout",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "uint8_t",
}


class GitVerifier:
    """Performs deterministic code and symbol verification against a target Git repository."""

    def __init__(self, repo_dir: str | Path) -> None:
        self.repo_dir = Path(repo_dir).resolve()
        if not (self.repo_dir / ".git").exists():
            raise ValueError(f"Directory is not a valid Git repository: {self.repo_dir}")

    def git_run(self, args: list[str]) -> tuple[int, str]:
        """Execute a git subprocess inside the target repository."""
        proc = subprocess.run(
            ["git", "-C", str(self.repo_dir)] + args,
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout

    def resolve_ref(self, claimed_ref: str | None) -> str:
        """Verify if claimed tag or commit ref exists in git history; falls back to HEAD."""
        if not claimed_ref:
            return "HEAD"
        # Try exact ref
        code, _ = self.git_run(["rev-parse", "--verify", f"{claimed_ref}^{{commit}}"])
        if code == 0:
            return claimed_ref
        # Try with 'v' prefix
        code, _ = self.git_run(["rev-parse", "--verify", f"v{claimed_ref}^{{commit}}"])
        if code == 0:
            return f"v{claimed_ref}"
        # Try curl tag format (e.g. curl-7_88_0)
        curl_fmt = f"curl-{claimed_ref.replace('.', '_')}"
        code, _ = self.git_run(["rev-parse", "--verify", f"{curl_fmt}^{{commit}}"])
        if code == 0:
            return curl_fmt

        return "HEAD"

    def read_file_at_ref(self, ref: str, rel_path: str) -> str | None:
        """Fetch exact file content at specified git ref without touching working tree."""
        # Normalize Windows path separators to POSIX
        posix_path = rel_path.replace("\\", "/").lstrip("/")
        code, stdout = self.git_run(["show", f"{ref}:{posix_path}"])
        if code == 0:
            return stdout
        return None

    def symbol_exists_in_content(self, content: str, symbol: str, file_path: str) -> bool:
        """Verify existence of a symbol/function identifier in file content using AST or symbol table."""
        # 1. Python AST parsing
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == symbol:
                        return True
            except SyntaxError:
                pass

        # 2. C/C++ regex function signature matcher
        if file_path.endswith((".c", ".h", ".cc", ".cpp")):
            c_func_pattern = re.compile(
                r"\b[A-Za-z0-9_]+\s+(?:\*)?\s*" + re.escape(symbol) + r"\s*\(",
                re.MULTILINE,
            )
            if c_func_pattern.search(content):
                return True

        # 3. Fallback word-boundary symbol token search
        token = symbol.split("::")[-1].split(".")[-1]
        pattern = re.compile(r"\b" + re.escape(token) + r"\b")
        return bool(pattern.search(content))

    def symbol_exists_in_repo(self, ref: str, symbol: str) -> bool:
        """Verify if symbol is defined or exported anywhere in the repository tree at ref."""
        if symbol in STANDARD_SYMBOLS:
            return True
        token = symbol.split("::")[-1].split(".")[-1]
        code, _ = self.git_run(["grep", "-q", "-E", rf"\b{re.escape(token)}\b", ref])
        return code == 0

    def is_file_modified_upstream(self, claimed_ref: str, upstream_ref: str, rel_path: str) -> bool:
        """Check if file content at claimed_ref differs from upstream_ref."""
        content_claimed = self.read_file_at_ref(claimed_ref, rel_path)
        content_upstream = self.read_file_at_ref(upstream_ref, rel_path)
        if content_claimed is None:
            return False
        # If deleted upstream, or bytes modified
        return content_upstream is None or content_claimed != content_upstream
