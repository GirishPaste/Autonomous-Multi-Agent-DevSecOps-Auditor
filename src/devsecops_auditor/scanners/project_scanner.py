"""Run the project's security scanners together."""

import os
from pathlib import Path
from typing import Any

from .bandit_scanner import scan_python
from .pip_audit_scanner import scan_requirements
from .secrets import scan_secrets


_EXCLUDED_DEPENDENCY_DIRECTORIES = {
    ".git",
    ".pytest_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "node_modules",
    "site-packages",
    "venv",
}


def _find_requirements_files(root: Path) -> list[Path]:
    requirements_files: list[Path] = []

    for current_directory, directory_names, file_names in os.walk(
        root,
        followlinks=False,
    ):
        current_path = Path(current_directory)
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name.casefold() not in _EXCLUDED_DEPENDENCY_DIRECTORIES
            and not (current_path / name).is_symlink()
        )

        for file_name in file_names:
            requirements_file = current_path / file_name
            if (
                "requirements" in file_name.casefold()
                and requirements_file.suffix.casefold() == ".txt"
                and not requirements_file.is_symlink()
            ):
                requirements_files.append(requirements_file)

    return sorted(
        requirements_files,
        key=lambda path: path.relative_to(root).as_posix().casefold(),
    )


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

    for requirements_file in _find_requirements_files(root):
        relative_file = requirements_file.relative_to(root).as_posix()
        dependency_findings = scan_requirements(requirements_file)

        for finding in dependency_findings:
            normalized_finding = dict(finding)
            if "file" in normalized_finding:
                normalized_finding["file"] = relative_file
            findings.append(normalized_finding)

    return findings