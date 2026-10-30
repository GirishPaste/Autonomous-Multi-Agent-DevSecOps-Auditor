from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def scan_requirements(requirements_file: str | Path) -> list[dict[str, Any]]:
    """Scan requirements with pip-audit and normalize vulnerability findings."""
    requirements = Path(requirements_file).expanduser().resolve()
    if not requirements.is_file():
        raise FileNotFoundError(f"Requirements file not found: {requirements}")

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--requirement",
                str(requirements),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"Unable to start pip-audit: {error}") from error

    # pip-audit uses exit code 1 when it finds vulnerabilities.
    if result.returncode not in (0, 1):
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"pip-audit failed: {detail}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        detail = result.stderr.strip() or "pip-audit returned invalid JSON."
        raise RuntimeError(f"Could not read pip-audit results: {detail}") from error

    findings: list[dict[str, Any]] = []
    findings_by_identity: dict[tuple[str, str, str], dict[str, Any]] = {}
    fix_versions_by_identity: dict[tuple[str, str, str], list[str]] = {}

    for dependency in report.get("dependencies", []):
        package = str(dependency.get("name", "unknown"))
        version = str(dependency.get("version", "unknown"))

        for vulnerability in dependency.get("vulns", []):
            vulnerability_id = str(vulnerability.get("id", "unknown"))
            fix_versions = [
                str(fix_version)
                for fix_version in (vulnerability.get("fix_versions") or [])
            ]

            # All three fields are needed to identify an advisory occurrence.
            # If pip-audit omits one, retain the finding instead of risking
            # collapsing unrelated or insufficiently identified records.
            identity = None
            if (
                package
                and package.casefold() != "unknown"
                and version
                and version.casefold() != "unknown"
                and vulnerability_id
                and vulnerability_id.casefold() != "unknown"
            ):
                identity = (
                    package.casefold(),
                    version,
                    vulnerability_id,
                )

            if identity is not None and identity in findings_by_identity:
                # Preserve all fix information supplied by repeated copies.
                combined_fixes = fix_versions_by_identity[identity]
                for fix_version in fix_versions:
                    if fix_version not in combined_fixes:
                        combined_fixes.append(fix_version)

                findings_by_identity[identity]["recommendation"] = (
                    "Upgrade to one of these versions: "
                    f"{', '.join(combined_fixes)}."
                    if combined_fixes
                    else "Check the vulnerability advisory for an available fix."
                )
                continue

            recommendation = (
                "Upgrade to one of these versions: "
                f"{', '.join(fix_versions)}."
                if fix_versions
                else "Check the vulnerability advisory for an available fix."
            )

            finding = {
                "scanner": "pip-audit",
                "rule_id": vulnerability_id,
                "severity": "unknown",
                "file": requirements.name,
                "line": None,
                "message": str(
                    vulnerability.get("description")
                    or f"{package} {version} has vulnerability "
                    f"{vulnerability_id}."
                ),
                "recommendation": recommendation,
                "evidence": f"{package}=={version}",
            }
            findings.append(finding)

            if identity is not None:
                findings_by_identity[identity] = finding
                fix_versions_by_identity[identity] = list(fix_versions)

    return findings