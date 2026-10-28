from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners.pip_audit_scanner import (  # noqa: E402
    scan_locked_project,
    scan_requirements,
)


def _vulnerable_report() -> dict[str, object]:
    return {
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


def test_maps_requirements_vulnerability_report(tmp_path: Path) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("sample-package==1.0\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=1,
            stdout=json.dumps(_vulnerable_report()),
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


def test_empty_requirements_report_returns_no_findings(tmp_path: Path) -> None:
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


def test_locked_project_uses_pip_audit_locked_mode(tmp_path: Path) -> None:
    lock_file = tmp_path / "pylock.toml"
    lock_file.write_text("# test lockfile\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=1,
            stdout=json.dumps(_vulnerable_report()),
            stderr="",
        ),
    ) as run:
        findings = scan_locked_project(tmp_path, "pylock.toml")

    command = run.call_args.args[0]
    assert "--locked" in command
    assert str(tmp_path.resolve()) in command
    assert findings[0]["file"] == "pylock.toml"


def test_locked_project_empty_report_returns_no_findings(tmp_path: Path) -> None:
    (tmp_path / "pylock.toml").write_text("# test lockfile\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.pip_audit_scanner.subprocess.run",
        return_value=SimpleNamespace(
            returncode=0,
            stdout=json.dumps({"dependencies": [], "fixes": []}),
            stderr="",
        ),
    ):
        assert scan_locked_project(tmp_path, "pylock.toml") == []


def test_missing_locked_project_directory_raises(tmp_path: Path) -> None:
    with pytest.raises(NotADirectoryError):
        scan_locked_project(tmp_path / "missing", "pylock.toml")


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