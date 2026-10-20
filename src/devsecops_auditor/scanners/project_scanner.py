"""Run the project's security scanners together."""

from pathlib import Path
from typing import Any

from .bandit_scanner import scan_python
from .pip_audit_scanner import scan_requirements
from .secrets import scan_secrets


def scan_project(target_folder: str | Path) -> list[dict[str, Any]]:
    """Run Bandit, secret detection, and pip-audit when applicable."""
    root = Path(target_folder).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Scan target is not a directory: {root}")

    findings: list[dict[str, Any]] = []

    findings.extend(scan_python(root))
    findings.extend(scan_secrets(root))

    requirements_file = root / "requirements.txt"

    if requirements_file.is_file():
        findings.extend(scan_requirements(requirements_file))

    return findings
