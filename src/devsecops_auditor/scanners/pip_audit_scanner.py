


import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def scan_requirements(requirements_file: str | Path) -> list[dict[str, Any]]:
    """Scan a requirements file with pip-audit and normalize vulnerability findings."""
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

    for dependency in report.get("dependencies", []):
        package = str(dependency.get("name", "unknown"))
        version = str(dependency.get("version", "unknown"))

        for vulnerability in dependency.get("vulns", []):
            vulnerability_id = str(vulnerability.get("id", "unknown"))
            fix_versions = vulnerability.get("fix_versions") or []

            recommendation = (
                f"Upgrade to one of these versions: {', '.join(map(str, fix_versions))}."
                if fix_versions
                else "Check the vulnerability advisory for an available fix."
            )

            findings.append(
                {
                    "scanner": "pip-audit",
                    "rule_id": vulnerability_id,
                    "severity": "unknown",
                    "file": requirements.name,
                    "line": None,
                    "message": str(
                        vulnerability.get("description")
                        or f"{package} {version} has vulnerability {vulnerability_id}."
                    ),
                    "recommendation": recommendation,
                    "evidence": f"{package}=={version}",
                }
            )

    # Remove duplicate findings for the same package, version, and vulnerability.
    unique_findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for finding in findings:
        key = (
            finding["evidence"],
            finding["rule_id"],
            finding["scanner"],
        )

        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return unique_findings
