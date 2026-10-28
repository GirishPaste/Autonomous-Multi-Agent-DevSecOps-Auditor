
"""Run the project's security scanners together."""

import tempfile
from pathlib import Path
from typing import Any

from .bandit_scanner import scan_python
from .pip_audit_scanner import scan_requirements
from .safe_zip import safe_extract_zip
from .secrets import scan_secrets


def scan_project(target_folder: str | Path) -> list[dict[str, Any]]:
    """Run Bandit, secret detection, and pip-audit when applicable."""
    root = Path(target_folder).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(
            f"Scan target is not a directory: {root}"
        )

    findings: list[dict[str, Any]] = []
    findings.extend(scan_python(root))
    findings.extend(scan_secrets(root))

    requirements_file = root / "requirements.txt"
    if requirements_file.is_file():
        findings.extend(scan_requirements(requirements_file))

    return findings


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
