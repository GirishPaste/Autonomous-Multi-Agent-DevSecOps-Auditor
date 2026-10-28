import json
import zipfile
from pathlib import Path

import pytest

from devsecops_auditor import cli
from devsecops_auditor.cli import main, write_reports
from devsecops_auditor.scanners import project_scanner


def test_write_reports_creates_json_and_markdown(tmp_path: Path) -> None:
    findings = [
        {
            "scanner": "bandit",
            "severity": "HIGH",
            "message": "Unsafe function detected",
            "line": 12,
        }
    ]

    json_path, markdown_path = write_reports(findings, tmp_path / "reports")

    assert json_path.exists()
    assert markdown_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8")) == findings

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# DevSecOps Auditor Report" in markdown
    assert "Unsafe function detected" in markdown
    assert "Total findings:** 1" in markdown


def test_write_reports_handles_no_findings(tmp_path: Path) -> None:
    _, markdown_path = write_reports([], tmp_path)

    assert "No security findings" in markdown_path.read_text(encoding="utf-8")


def test_main_scans_project_and_writes_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    output = tmp_path / "out"
    expected_findings = [{"scanner": "test", "severity": "LOW"}]

    monkeypatch.setattr(cli, "scan_project", lambda target: expected_findings)
    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(project), "--output", str(output)],
    )

    assert main() == 0
    assert json.loads((output / "report.json").read_text(encoding="utf-8")) == (
        expected_findings
    )
    assert (output / "report.md").exists()


def test_main_scans_real_zip_end_to_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "project.zip"
    output = tmp_path / "zip-reports"
    expected_findings = [
        {
            "scanner": "bandit",
            "severity": "HIGH",
            "file": "app.py",
        }
    ]

    with zipfile.ZipFile(archive, "w") as zip_file:
        zip_file.writestr("app.py", "print('hello')\n")

    monkeypatch.setattr(
        project_scanner,
        "scan_python",
        lambda folder: expected_findings,
    )
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_requirements", lambda file: [])
    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(archive), "--output", str(output)],
    )

    assert main() == 0
    assert json.loads((output / "report.json").read_text(encoding="utf-8")) == (
        expected_findings
    )
    assert (output / "report.md").exists()


def test_main_reports_invalid_zip_cleanly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"not a ZIP archive")

    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(archive)],
    )

    with pytest.raises(SystemExit) as error:
        main()

    assert error.value.code == 2
    assert "File is not a zip file" in capsys.readouterr().err


def test_fail_on_high_returns_failure_for_high_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    findings = [{"scanner": "bandit", "severity": "HIGH"}]

    monkeypatch.setattr(cli, "scan_project", lambda target: findings)
    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(project), "--fail-on", "high"],
    )

    assert main() == 1


def test_fail_on_high_does_not_fail_for_medium_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    findings = [{"scanner": "bandit", "severity": "medium"}]

    monkeypatch.setattr(cli, "scan_project", lambda target: findings)
    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(project), "--fail-on", "high"],
    )

    assert main() == 0


def test_fail_on_any_includes_unknown_severity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    project = tmp_path / "project"
    project.mkdir()
    findings = [{"scanner": "pip-audit", "severity": "unknown"}]

    monkeypatch.setattr(cli, "scan_project", lambda target: findings)
    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(project), "--fail-on", "any"],
    )

    assert main() == 1