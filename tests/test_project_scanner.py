
from pathlib import Path

import pytest

from devsecops_auditor.scanners import project_scanner


def test_scan_project_combines_all_scanner_findings(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "print('hello')\n", encoding="utf-8"
    )
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "packaging==26.3\n", encoding="utf-8"
    )

    bandit_findings = [{"scanner": "bandit", "severity": "LOW"}]
    secret_findings = [{"scanner": "secrets", "severity": "HIGH"}]
    dependency_findings = [
        {"scanner": "pip-audit", "severity": "MEDIUM"}
    ]

    monkeypatch.setattr(
        project_scanner, "scan_python",
        lambda folder: bandit_findings,
    )
    monkeypatch.setattr(
        project_scanner, "scan_secrets",
        lambda folder: secret_findings,
    )
    monkeypatch.setattr(
        project_scanner, "scan_requirements",
        lambda file: dependency_findings,
    )

    findings = project_scanner.scan_project(tmp_path)

    assert findings == (
        bandit_findings + secret_findings + dependency_findings
    )


def test_skips_dependency_scan_without_requirements(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(
        "print('hello')\n", encoding="utf-8"
    )

    monkeypatch.setattr(
        project_scanner, "scan_python", lambda folder: []
    )
    monkeypatch.setattr(
        project_scanner, "scan_secrets", lambda folder: []
    )

    def unexpected_dependency_scan(file):
        pytest.fail("Dependency scan should be skipped")

    monkeypatch.setattr(
        project_scanner, "scan_requirements",
        unexpected_dependency_scan,
    )

    assert project_scanner.scan_project(tmp_path) == []


def test_missing_project_directory_raises_error(tmp_path):
    missing = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError):
        project_scanner.scan_project(missing)
