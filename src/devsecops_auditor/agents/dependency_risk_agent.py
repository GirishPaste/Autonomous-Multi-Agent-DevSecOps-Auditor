"""Explain pip-audit dependency findings without modifying scanner data."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


_SCANNER_NAME = "pip-audit"
_FIX_PREFIX = "Upgrade to one of these versions:"


def _extract_fix_versions(recommendation: Any) -> list[str]:
    """Extract fix versions from the existing pip-audit scanner format."""
    if not isinstance(recommendation, str):
        return []

    text = recommendation.strip()

    if not text.startswith(_FIX_PREFIX) or not text.endswith("."):
        return []

    versions_text = text[len(_FIX_PREFIX):-1].strip()
    if not versions_text:
        return []

    versions = [version.strip() for version in versions_text.split(",")]

    # Reject malformed lists instead of guessing a version.
    if any(not version for version in versions):
        return []

    return versions


def _build_risk_explanation(finding: dict[str, Any]) -> str:
    """Explain only the description and evidence actually supplied."""
    message = finding.get("message")
    evidence = finding.get("evidence")

    if isinstance(message, str) and message.strip():
        description = f"Reported vulnerability: {message.strip()}"
    else:
        description = "The scanner did not provide a vulnerability description."

    if isinstance(evidence, str) and evidence.strip():
        package_evidence = f"Package/version evidence: {evidence.strip()}"
    else:
        package_evidence = (
            "The scanner did not provide valid package/version evidence."
        )

    return f"{description} {package_evidence}"


def analyze_dependency_findings(
    findings: Iterable[Any],
) -> list[Any]:
    """Enrich pip-audit findings while leaving other findings unchanged.

    Original fields and severity are preserved. Input dictionaries are not
    mutated. This function does not install packages, edit files, or make
    network/API calls.
    """
    results: list[Any] = []

    for finding in findings:
        # Leave malformed entries and findings from other scanners unchanged.
        if not isinstance(finding, dict):
            results.append(finding)
            continue

        if finding.get("scanner") != _SCANNER_NAME:
            results.append(finding)
            continue

        # Work on a copy so the original finding remains unchanged.
        enriched = finding.copy()

        enriched["risk_explanation"] = _build_risk_explanation(finding)

        fix_versions = _extract_fix_versions(finding.get("recommendation"))

        if fix_versions:
            versions = ", ".join(fix_versions)
            enriched["upgrade_recommendation"] = (
                f"pip-audit provided these fix version(s): {versions}. "
                "Review the advisory and test the upgrade before adopting it."
            )
        else:
            enriched["upgrade_recommendation"] = (
                "No fix version was provided by the scanner. "
                "Review the vulnerability advisory for further guidance."
            )

        results.append(enriched)

    return results