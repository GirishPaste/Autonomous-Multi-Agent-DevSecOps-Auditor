
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners.pip_audit_scanner import (
    scan_dependencies,
    scan_requirements,
)


def test_maps_vulnerability_report(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

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

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=1,
            stdout=json.dumps(report),
            stderr="",
        ),
    ):
        findings = scan_requirements(requirements)

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


def test_empty_report_returns_no_findings(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"dependencies": [], "fixes": []}),
            stderr="",
        ),
    ):
        assert scan_requirements(requirements) == []


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


def test_scan_dependencies_uses_requirements_file(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.scan_requirements",
        return_value=[],
    ) as mock_scan:
        assert scan_dependencies(tmp_path) == []

    mock_scan.assert_called_once_with(requirements)


def test_scan_dependencies_reports_missing_manifest(tmp_path: Path) -> None:
    with pytest.raises(
        FileNotFoundError,
        match="No supported dependency manifest",
    ):
        scan_dependencies(tmp_path)


def test_scan_dependencies_reports_pyproject_without_dependencies(
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'sample-project'\nversion = '1.0.0'\n",
        encoding="utf-8",
    )

    with pytest.raises(
        RuntimeError,
        match="no standard project dependencies to audit",
    ):
        scan_dependencies(tmp_path)


def test_scan_dependencies_reads_pyproject_dependencies(
    tmp_path: Path,
) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\n'
        'name = "sample-project"\n'
        'version = "1.0.0"\n'
        'dependencies = ["sample-package>=1.0"]\n',
        encoding="utf-8",
    )

    captured_dependencies: list[str] = []

    def fake_scan(requirements_file: str | Path) -> list[dict]:
        temporary_file = Path(requirements_file)
        captured_dependencies.append(
            temporary_file.read_text(encoding="utf-8")
        )
        return []

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.scan_requirements",
        side_effect=fake_scan,
    ) as mock_scan:
        assert scan_dependencies(tmp_path) == []

    mock_scan.assert_called_once()
    assert captured_dependencies == ["sample-package>=1.0\n"]
