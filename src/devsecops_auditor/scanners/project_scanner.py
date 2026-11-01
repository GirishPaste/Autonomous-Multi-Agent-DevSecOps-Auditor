

"""Run the project's security scanners together."""

import tempfile
from pathlib import Path
from typing import Any

from .bandit_scanner import scan_python
from .pip_audit_scanner import scan_requirements
from .redaction import redact_sensitive_data
from .safe_zip import safe_extract_zip
from .secrets import scan_secrets_with_values


def scan_project(target_folder: str | Path) -> list[dict[str, Any]]:
    """Run scanners and redact detected credentials across all findings."""
    root = Path(target_folder).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(
            f"Scan target is not a directory: {root}"
        )

    findings: list[dict[str, Any]] = []

    # Run the source-code scanner.
    findings.extend(scan_python(root))

    # Detect secrets and retain their values internally for redaction.
    secret_findings, detected_secret_values = scan_secrets_with_values(root)
    findings.extend(secret_findings)

    # Run dependency scanning when requirements.txt exists.
    requirements_file = root / "requirements.txt"

    if requirements_file.is_file():
        findings.extend(scan_requirements(requirements_file))

    # Redact credentials across findings from every scanner.
    return redact_sensitive_data(findings, detected_secret_values)


def scan_zip_project(archive_path: str | Path) -> list[dict[str, Any]]:
    """Safely extract a ZIP project, scan it, and clean up temporary files."""
    archive = Path(archive_path).expanduser().resolve()

    if not archive.exists():
        raise FileNotFoundError(f"ZIP archive does not exist: {archive}")

    if not archive.is_file():
        raise IsADirectoryError(
            f"ZIP archive path is not a file: {archive}"
        )

    with tempfile.TemporaryDirectory(
        prefix="devsecops-auditor-"
    ) as temp_dir:
        extracted_root = Path(temp_dir) / "project"

        safe_extract_zip(archive, extracted_root)

        return scan_project(extracted_root)
