from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Allow tests to import the package from the project's src directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.agents.dependency_risk_agent import (  # noqa: E402
    analyze_dependency_findings,
)


def make_finding(**overrides):
    """Create a finding using the real pip-audit scanner's field names."""
    finding = {
        "scanner": "pip-audit",
        "rule_id": "PYSEC-2024-123",
        "severity": "unknown",
        "file": "requirements.txt",
        "line": None,
        "message": "A sample vulnerability.",
        "recommendation": "Upgrade to one of these versions: 1.1.",
        "evidence": "sample-package==1.0",
    }
    finding.update(overrides)
    return finding


def test_known_fix_version_is_recommended():
    result = analyze_dependency_findings([make_finding()])[0]

    assert result["upgrade_recommendation"] == (
        "pip-audit provided these fix version(s): 1.1. "
        "Review the advisory and test the upgrade before adopting it."
    )
    assert result["risk_explanation"] == (
        "Reported vulnerability: A sample vulnerability. "
        "Package/version evidence: sample-package==1.0"
    )


def test_multiple_fix_versions_are_preserved():
    finding = make_finding(
        recommendation="Upgrade to one of these versions: 1.1, 1.2."
    )

    result = analyze_dependency_findings([finding])[0]

    assert "1.1, 1.2" in result["upgrade_recommendation"]


def test_no_fix_version_recommends_advisory_review():
    finding = make_finding(
        recommendation="Check the vulnerability advisory for an available fix."
    )

    result = analyze_dependency_findings([finding])[0]

    assert result["upgrade_recommendation"] == (
        "No fix version was provided by the scanner. "
        "Review the vulnerability advisory for further guidance."
    )


def test_other_scanner_finding_is_unchanged():
    finding = {
        "scanner": "bandit",
        "rule_id": "B301",
        "severity": "medium",
        "message": "An example Bandit finding.",
        "custom_field": {"preserve": True},
    }

    result = analyze_dependency_findings([finding])[0]

    assert result is finding
    assert "risk_explanation" not in result
    assert "upgrade_recommendation" not in result


def test_all_original_fields_are_preserved():
    finding = make_finding(
        custom_field={"source": "original"},
        extra_evidence="additional original data",
    )
    original = finding.copy()

    result = analyze_dependency_findings([finding])[0]

    for key, value in original.items():
        assert key in result
        assert result[key] == value

    assert result is not finding
    assert finding == original


def test_unknown_severity_is_preserved():
    finding = make_finding(severity="unknown")

    result = analyze_dependency_findings([finding])[0]

    assert result["severity"] == "unknown"


@pytest.mark.parametrize(
    "finding",
    [
        make_finding(message=None, evidence=None),
        make_finding(message=123, evidence=["malformed"]),
        make_finding(recommendation=None),
        make_finding(recommendation="Upgrade to one of these versions: ."),
        make_finding(recommendation="Upgrade to one of these versions: 1.1, ."),
    ],
)
def test_missing_or_malformed_fields_do_not_crash(finding):
    result = analyze_dependency_findings([finding])[0]

    assert result["scanner"] == "pip-audit"
    assert "risk_explanation" in result
    assert "upgrade_recommendation" in result


def test_missing_fix_version_never_invents_a_version():
    finding = make_finding(recommendation=None)

    result = analyze_dependency_findings([finding])[0]

    assert "No fix version was provided" in result["upgrade_recommendation"]
    assert "1.1" not in result["upgrade_recommendation"]


def test_input_finding_is_not_mutated():
    finding = make_finding()
    original = finding.copy()

    analyze_dependency_findings([finding])

    assert finding == original
    assert "risk_explanation" not in finding
    assert "upgrade_recommendation" not in finding


def test_non_dictionary_entry_is_returned_unchanged():
    invalid_entry = "not a finding"

    result = analyze_dependency_findings([invalid_entry])

    assert result == [invalid_entry]
    assert result[0] is invalid_entry


def test_same_input_produces_same_output():
    finding = make_finding()

    first = analyze_dependency_findings([finding])
    second = analyze_dependency_findings([finding])

    assert first == second