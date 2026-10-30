from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners.pip_audit_scanner import scan_requirements  # noqa: E402


def run_scan(tmp_path: Path, report: dict) -> list[dict]:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=1 if report.get("dependencies") else 0,
            stdout=json.dumps(report),
            stderr="",
        ),
    ):
        return scan_requirements(requirements)


def test_maps_vulnerability_report(tmp_path: Path) -> None:
    report = {
        "dependencies": [
            {
                "name": "sample-package",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-123",
                        "description": "A sample vulnerability.",
                        "fix_versions": ["1.1"],
                    }
                ],
            }
        ],
        "fixes": [],
    }

    findings = run_scan(tmp_path, report)

    assert findings == [
        {
            "scanner": "pip-audit",
            "rule_id": "PYSEC-2024-123",
            "severity": "unknown",
            "file": "requirements.txt",
            "line": None,
            "message": "A sample vulnerability.",
            "recommendation": "Upgrade to one of these versions: 1.1.",
            "evidence": "sample-package==1.0",
        }
    ]


def test_deduplicates_repeated_identical_advisory_records(
    tmp_path: Path,
) -> None:
    vulnerability = {
        "id": "PYSEC-2024-123",
        "description": "A sample vulnerability.",
        "fix_versions": ["1.1"],
    }
    report = {
        "dependencies": [
            {
                "name": "sample-package",
                "version": "1.0",
                "vulns": [vulnerability, vulnerability.copy()],
            },
            {
                "name": "sample-package",
                "version": "1.0",
                "vulns": [vulnerability.copy()],
            },
        ],
        "fixes": [],
    }

    findings = run_scan(tmp_path, report)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PYSEC-2024-123"
    assert findings[0]["evidence"] == "sample-package==1.0"
    assert findings[0]["recommendation"] == (
        "Upgrade to one of these versions: 1.1."
    )
    assert findings[0]["file"] == "requirements.txt"
    assert findings[0]["line"] is None


def test_duplicate_advisory_records_combine_fix_versions(
    tmp_path: Path,
) -> None:
    report = {
        "dependencies": [
            {
                "name": "sample-package",
                "version": "1.0",
                "vulns": [
                    {
                        "id": "PYSEC-2024-123",
                        "description": "A sample vulnerability.",
                        "fix_versions": ["1.1"],
                    },
                    {
                        "id": "PYSEC-2024-123",
                        "description": "A sample vulnerability.",
                        "fix_versions": ["1.2", "1.1"],
                    },
                ],
            }
        ],
        "fixes": [],
    }

    findings = run_scan(tmp_path, report)

    assert len(findings) == 1
    assert findings[0]["recommendation"] == (
        "Upgrade to one of these versions: 1.1, 1.2."
    )


def test_similar_records_for_different_packages_versions_and_advisories_stay_separate(
    tmp_path: Path,
) -> None:
    def vulnerability(advisory_id: str) -> dict:
        return {
            "id": advisory_id,
            "description": "A sample vulnerability.",
            "fix_versions": ["2.0"],
        }

    report = {
        "dependencies": [
            {
                "name": "sample-package",
                "version": "1.0",
                "vulns": [
                    vulnerability("PYSEC-2024-123"),
                    vulnerability("PYSEC-2024-456"),
                ],
            },
            {
                "name": "sample-package",
                "version": "1.1",
                "vulns": [vulnerability("PYSEC-2024-123")],
            },
            {
                "name": "other-package",
                "version": "1.0",
                "vulns": [vulnerability("PYSEC-2024-123")],
            },
        ],
        "fixes": [],
    }

    findings = run_scan(tmp_path, report)

    assert len(findings) == 4
    assert {
        (finding["evidence"], finding["rule_id"])
        for finding in findings
    } == {
        ("sample-package==1.0", "PYSEC-2024-123"),
        ("sample-package==1.0", "PYSEC-2024-456"),
        ("sample-package==1.1", "PYSEC-2024-123"),
        ("other-package==1.0", "PYSEC-2024-123"),
    }


def test_empty_report_returns_no_findings(tmp_path: Path) -> None:
    findings = run_scan(
        tmp_path,
        {"dependencies": [], "fixes": []},
    )

    assert findings == []


def test_missing_requirements_file_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_requirements(tmp_path / "missing.txt")


def test_failed_pip_audit_raises_error(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="pip-audit could not run",
        ),
    ):
        with pytest.raises(RuntimeError, match="pip-audit failed"):
            scan_requirements(requirements)