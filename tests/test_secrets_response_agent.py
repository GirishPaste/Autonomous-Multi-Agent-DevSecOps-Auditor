from __future__ import annotations

import sys
from pathlib import Path

# Make the src/ package importable when pytest runs from the repository root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.agents.secrets_response_agent import (  # noqa: E402
    analyze_secret_findings,
)


def test_empty_input_returns_empty_list() -> None:
    assert analyze_secret_findings([]) == []


def test_adds_safe_analysis_and_preserves_finding_fields() -> None:
    finding = {
        "scanner": "secrets",
        "rule_id": "generic_password",
        "severity": "high",
        "file": "settings.py",
        "line": 12,
        "message": "Potential credential detected; value redacted.",
        "recommendation": "Rotate the credential and remove it from history.",
        "evidence": 'password = "[REDACTED]"',
    }

    result = analyze_secret_findings([finding])

    assert len(result) == 1
    assert result[0]["scanner"] == "secrets"
    assert result[0]["file"] == "settings.py"
    assert result[0]["line"] == 12
    assert result[0]["evidence"] == 'password = "[REDACTED]"'
    assert result[0]["agent_analysis"]["agent"] == "secrets_response"
    assert "access the related service" in result[0]["agent_analysis"][
        "risk_explanation"
    ]
    assert "Rotate the credential" in result[0]["recommendation"]


def test_missing_fields_get_safe_defaults() -> None:
    result = analyze_secret_findings([{"scanner": "secrets"}])

    assert result[0]["rule_id"] == "unknown"
    assert result[0]["severity"] == "unknown"
    assert result[0]["file"] == "unknown file"
    assert result[0]["recommendation"]
    assert result[0]["agent_analysis"]["rule_id"] == "unknown"


def test_analysis_does_not_repeat_evidence_or_finding_message() -> None:
    finding = {
        "scanner": "secrets",
        "rule_id": "generic_password",
        "severity": "high",
        "file": "settings.py",
        "message": "A scanner message that should not be copied into analysis.",
        "evidence": 'password = "[REDACTED]"',
    }

    result = analyze_secret_findings([finding])
    analysis = result[0]["agent_analysis"]

    assert finding["message"] not in analysis["risk_explanation"]
    assert finding["evidence"] not in analysis["risk_explanation"]