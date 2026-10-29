from typing import Any

from devsecops_auditor.agents.code_risk_agent import analyze_bandit_findings


def _bandit_finding(
    rule_id: str = "B603",
    **extra: Any,
) -> dict[str, Any]:
    finding: dict[str, Any] = {
        "scanner": "bandit",
        "rule_id": rule_id,
        "severity": "low",
        "file": "scanners/example.py",
        "line": 12,
        "message": "subprocess call detected",
        "recommendation": "https://example.com/bandit-rule",
        "evidence": "Source excerpt omitted.",
    }
    finding.update(extra)
    return finding


def test_explains_subprocess_without_shell() -> None:
    finding = _bandit_finding("B603")

    result = analyze_bandit_findings([finding])[0]

    assert result["severity"] == "low"
    assert "shell=False" in result["agent_analysis"]["possible_fix"]
    assert "subprocess call" in result["agent_analysis"]["risk_explanation"]


def test_explains_subprocess_with_shell() -> None:
    finding = _bandit_finding("B602")

    result = analyze_bandit_findings([finding])[0]

    assert "command injection" in result["agent_analysis"]["risk_explanation"]
    assert "Avoid shell=True" in result["agent_analysis"]["possible_fix"]


def test_unknown_rule_uses_finding_details() -> None:
    finding = _bandit_finding(
        "B999",
        message="A custom security pattern was detected.",
        file="app.py",
        line=7,
    )

    result = analyze_bandit_findings([finding])[0]

    assert "B999" in result["agent_analysis"]["risk_explanation"]
    assert "app.py, line 7" in result["agent_analysis"]["risk_explanation"]
    assert result["agent_analysis"]["reference"] == finding["recommendation"]


def test_non_bandit_finding_is_preserved() -> None:
    finding = {
        "scanner": "secrets",
        "rule_id": "test-rule",
        "severity": "high",
    }

    result = analyze_bandit_findings([finding])

    assert result == [finding]
    assert "agent_analysis" not in result[0]


def test_missing_bandit_fields_do_not_crash() -> None:
    result = analyze_bandit_findings([{"scanner": "bandit"}])
    analysis = result[0]["agent_analysis"]

    assert "bandit rule unknown" in analysis["risk_explanation"].casefold()
    assert "review the code at unknown file" in (
        analysis["risk_explanation"].casefold()
    )
    assert analysis["reference"] is None


def test_original_findings_are_not_modified() -> None:
    finding = _bandit_finding()
    original = dict(finding)

    result = analyze_bandit_findings([finding])

    assert finding == original
    assert "agent_analysis" not in finding
    assert "agent_analysis" in result[0]


def test_empty_input_returns_empty_list() -> None:
    assert analyze_bandit_findings([]) == []