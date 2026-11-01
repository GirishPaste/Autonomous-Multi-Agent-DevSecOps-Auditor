
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

    json_path, markdown_path = write_reports(
        findings,
        tmp_path / "reports",
    )

    assert json_path.exists()
    assert markdown_path.exists()
    assert json.loads(
        json_path.read_text(encoding="utf-8")
    ) == findings

    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# DevSecOps Auditor Report" in markdown
    assert "Unsafe function detected" in markdown
    assert "Total findings:** 1" in markdown


def test_write_reports_handles_no_findings(tmp_path):
    _, markdown_path = write_reports([], tmp_path)

    assert "No security findings" in markdown_path.read_text(
        encoding="utf-8"
    )


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
        [
            "devsecops-auditor",
            str(project),
            "--output",
            str(tmp_path / "out"),
        ],
    )

    assert main() == 0
    assert (tmp_path / "out" / "report.json").exists()
    assert (tmp_path / "out" / "report.md").exists()


def test_write_reports_redacts_secrets_from_complete_reports(tmp_path):
    fake_secret = "FAKE_TEST_CREDENTIAL_987654"

    findings = [
        {
            "scanner": "bandit",
            "severity": "HIGH",
            "rule_id": "B105",
            "message": f"Possible hardcoded password: {fake_secret}",
            "evidence": f"password = '{fake_secret}'",
            "agent_analysis": {
                "risk_explanation": (
                    f"The detected credential is {fake_secret}"
                ),
                "recommendation": "Rotate the exposed credential.",
            },
        }
    ]

    json_path, markdown_path = write_reports(
        findings,
        tmp_path / "secure_reports",
        secret_values=[fake_secret],
    )

    json_report = json_path.read_text(encoding="utf-8")
    markdown_report = markdown_path.read_text(encoding="utf-8")

    # The fake credential must not appear in either report.
    assert fake_secret not in json_report
    assert fake_secret not in markdown_report

    # The reports must contain the redaction marker.
    assert "[REDACTED]" in json_report
    assert "[REDACTED]" in markdown_report

    # Important finding information must remain available.
    parsed_json = json.loads(json_report)

    assert len(parsed_json) == 1
    assert parsed_json[0]["scanner"] == "bandit"
    assert parsed_json[0]["severity"] == "HIGH"
    assert parsed_json[0]["rule_id"] == "B105"

    # Nested agent analysis must also be sanitized.
    assert (
        "[REDACTED]"
        in parsed_json[0]["agent_analysis"]["risk_explanation"]
    )
    assert (
        parsed_json[0]["agent_analysis"]["recommendation"]
        == "Rotate the exposed credential."
    )
