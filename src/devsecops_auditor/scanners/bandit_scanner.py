"""Run Bandit against Python files and return normalized security findings."""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404
import sys
from pathlib import Path
from typing import Any


_EXCLUDED_DIRECTORIES = {
    ".git",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "cache",
    "coverage",
    "dist",
    "generated",
    "node_modules",
    "output",
    "outputs",
    "venv",
}


def _raise_walk_error(error: OSError) -> None:
    """Do not silently report a partial scan when a directory cannot be read."""
    raise error


def _python_files(root: Path) -> list[Path]:
    """Return Python source paths relative to root, skipping generated folders."""
    files: list[Path] = []
    for current_directory, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=_raise_walk_error
    ):
        current_path = Path(current_directory)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _EXCLUDED_DIRECTORIES
            and not (current_path / name).is_symlink()
        )
        files.extend(
            (current_path / name).relative_to(root)
            for name in sorted(file_names)
            if name.endswith(".py") and not (current_path / name).is_symlink()
        )
    return files


def _normalize_finding(result: dict[str, Any], root: Path) -> dict[str, Any]:
    """Translate one Bandit JSON result to the project's common finding shape."""
    reported_path = Path(result["filename"])
    full_path = reported_path if reported_path.is_absolute() else root / reported_path
    relative_path = full_path.resolve().relative_to(root)

    return {
        "scanner": "bandit",
        "rule_id": str(result.get("test_id", "")),
        "severity": str(result.get("issue_severity", "unknown")).lower(),
        "file": relative_path.as_posix(),
        "line": int(result.get("line_number", 1)),
        "message": str(result.get("issue_text", "")),
        "recommendation": str(
            result.get("more_info", "Review this finding and follow Bandit's guidance.")
        ),
        "evidence": str(result.get("code", "")).strip(),
    }


def scan_python(target_folder: str | Path) -> list[dict[str, Any]]:
    """Scan Python source files without executing them; return normalized findings."""
    root = Path(target_folder).expanduser()
    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Scan target is not a directory: {root}")

    root = root.resolve()
    files = _python_files(root)
    if not files:
        return []

    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                "-q",
                *map(str, files),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )  # nosec B603
    except OSError as error:
        raise RuntimeError(f"Unable to start Bandit scanner: {error}") from error

    if completed.returncode not in (0, 1):
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(
            f"Bandit scanner failed with exit code {completed.returncode}: {detail}"
        )

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        detail = completed.stderr.strip() or "Bandit returned no valid JSON report."
        raise RuntimeError(f"Bandit scanner failed: {detail}") from error

    if report.get("errors"):
        details = "; ".join(str(item) for item in report["errors"])
        raise RuntimeError(f"Bandit could not scan all requested files: {details}")

    return [
        _normalize_finding(result, root)
        for result in report.get("results", [])
    ]
