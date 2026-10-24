
"""Tests for the project-level security scanner."""

import sys
from pathlib import Path

import pytest

# Make the src-layout package importable when running pytest.
SRC_PATH = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC_PATH))

from devsecops_auditor.scanners import project_scanner


def test_scan_project_combines_all_scanner_findings(
    tmp_path, monkeypatch
):
    (tmp_path / "app.py").write_text(
        "print('hello')\n", encoding="utf-8"
    )
    (tmp_path / "requirements.txt").write_text(
        "packaging==26.3\n", encoding="utf-8"
    )

    bandit_findings = [
        {"scanner": "bandit", "severity": "LOW"}
    ]
    secret_findings = [
        {"scanner": "secrets", "severity": "HIGH"}
    ]
    dependency_findings = [
        {"scanner": "pip-audit", "severity": "MEDIUM"}
    ]

    monkeypatch.setattr(
        project_scanner,
        "scan_python",
        lambda folder: bandit_findings,
    )
    monkeypatch.setattr(
        project_scanner,
        "scan_secrets",
        lambda folder: secret_findings,
    )
    monkeypatch.setattr(
        project_scanner,
        "scan_dependencies",
        lambda folder: dependency_findings,
    )

    findings = project_scanner.scan_project(tmp_path)

    assert findings == (
        bandit_findings
        + secret_findings
        + dependency_findings
    )


def test_missing_manifest_raises_error(tmp_path, monkeypatch):
    """A project without a supported manifest must not appear clean."""
    (tmp_path / "app.py").write_text(
        "print('hello')\n", encoding="utf-8"
    )

    monkeypatch.setattr(
        project_scanner, "scan_python", lambda folder: []
    )
    monkeypatch.setattr(
        project_scanner, "scan_secrets", lambda folder: []
    )

    with pytest.raises(FileNotFoundError, match="No supported"):
        project_scanner.scan_project(tmp_path)


def test_missing_project_directory_raises_error(tmp_path):
    missing = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError):
        project_scanner.scan_project(missing)
