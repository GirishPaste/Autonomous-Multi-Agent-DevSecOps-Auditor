
import json

from devsecops_auditor.cli import main, write_reports


def test_write_reports_creates_json_and_markdown(tmp_path):
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


def test_write_reports_handles_no_findings(tmp_path):
    _, markdown_path = write_reports([], tmp_path)

    assert "No security findings" in markdown_path.read_text(encoding="utf-8")


def test_main_scans_project_and_writes_reports(tmp_path, monkeypatch):
    import devsecops_auditor.cli as cli

    project = tmp_path / "project"
    project.mkdir()

    monkeypatch.setattr(
        cli,
        "scan_project",
        lambda target: [{"scanner": "test", "severity": "LOW"}],
    )
    monkeypatch.setattr(
        "sys.argv",
        ["devsecops-auditor", str(project), "--output", str(tmp_path / "out")],
    )

    assert main() == 0
    assert (tmp_path / "out" / "report.json").exists()
    assert (tmp_path / "out" / "report.md").exists()
