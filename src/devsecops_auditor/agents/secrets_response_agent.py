"""Explain secrets-scanner findings without repeating secret values."""

from __future__ import annotations

from typing import Any


_DEFAULT_RECOMMENDATION = (
    "Revoke and rotate the credential, remove it from the source and repository "
    "history, and store future credentials in an environment variable or secret "
    "manager."
)


def analyze_secret_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Add a safe, beginner-friendly response to each secrets finding.

    The analysis deliberately does not include the finding's evidence or message,
    since those fields could contain sensitive text.
    """
    analyzed: list[dict[str, Any]] = []

    for finding in findings:
        result = dict(finding)

        rule_id = str(result.get("rule_id") or "unknown")
        severity = str(result.get("severity") or "unknown")
        file_path = str(result.get("file") or "unknown file")

        result.setdefault("rule_id", rule_id)
        result.setdefault("severity", severity)
        result.setdefault("file", file_path)
        result.setdefault("recommendation", _DEFAULT_RECOMMENDATION)

        result["agent_analysis"] = {
            "agent": "secrets_response",
            "risk_explanation": (
                "The secrets scanner reported a value that may be a credential. "
                "If it is valid and exposed, someone could use it to access the "
                "related service. The scan cannot confirm whether it is active."
            ),
            "recommended_action": _DEFAULT_RECOMMENDATION,
            "location": file_path,
            "rule_id": rule_id,
            "severity": severity,
            "verification_note": (
                "Verify the finding securely. Do not copy a credential into "
                "reports, tickets, or chat."
            ),
        }

        analyzed.append(result)

    return analyzed