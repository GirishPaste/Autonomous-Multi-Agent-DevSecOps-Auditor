"""Run the project's security scanners together."""

import os
from pathlib import Path
from typing import Any

from .bandit_scanner import scan_python
from .pip_audit_scanner import scan_locked_project, scan_requirements
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


def _find_dependency_files(
    root: Path,
) -> tuple[list[Path], dict[Path, list[Path]]]:
    """Find requirements files and group pylock files by project directory."""
    requirements_files: list[Path] = []
    lock_files_by_directory: dict[Path, list[Path]] = {}

    for current_directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        current_path = Path(current_directory)

        directory_names[:] = sorted(
            name
            for name in directory_names
            if name.casefold() not in _EXCLUDED_DEPENDENCY_DIRECTORIES
            and not (current_path / name).is_symlink()
        )

        for file_name in sorted(file_names):
            file_path = current_path / file_name

            if file_path.is_symlink():
                continue

            lowered_name = file_name.casefold()

            if "requirements" in lowered_name and file_path.suffix.casefold() == ".txt":
                requirements_files.append(file_path)
            elif lowered_name.startswith("pylock") and lowered_name.endswith(".toml"):
                lock_files_by_directory.setdefault(current_path, []).append(file_path)

    requirements_files.sort(
        key=lambda path: path.relative_to(root).as_posix().casefold()
    )

    for lock_files in lock_files_by_directory.values():
        lock_files.sort(key=lambda path: path.name.casefold())

    return requirements_files, lock_files_by_directory


def _relative_lock_label(
    root: Path,
    project_directory: Path,
    lock_files: list[Path],
) -> str:
    """Return a root-relative label for one or more lockfiles."""
    if len(lock_files) == 1:
        return lock_files[0].relative_to(root).as_posix()

    relative_directory = project_directory.relative_to(root).as_posix()
    pattern = "pylock*.toml"

    if relative_directory == ".":
        return pattern

    return f"{relative_directory}/{pattern}"


def scan_project(target_folder: str | Path) -> list[dict[str, Any]]:
    """Run Bandit, secret detection, and dependency scans on a project."""
    root = Path(target_folder).expanduser().resolve()

    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Scan target is not a directory: {root}")

    findings: list[dict[str, Any]] = []
    findings.extend(scan_python(root))
    findings.extend(scan_secrets(root))

    requirements_files, lock_files_by_directory = _find_dependency_files(root)

    for requirements_file in requirements_files:
        relative_file = requirements_file.relative_to(root).as_posix()
        dependency_findings = scan_requirements(requirements_file)

        for finding in dependency_findings:
            normalized_finding = dict(finding)
            if "file" in normalized_finding:
                normalized_finding["file"] = relative_file
            findings.append(normalized_finding)

    sorted_lock_directories = sorted(
        lock_files_by_directory,
        key=lambda path: path.relative_to(root).as_posix().casefold(),
    )

    for project_directory in sorted_lock_directories:
        lock_files = lock_files_by_directory[project_directory]
        source_file = _relative_lock_label(root, project_directory, lock_files)
        dependency_findings = scan_locked_project(project_directory, source_file)

        for finding in dependency_findings:
            normalized_finding = dict(finding)
            if "file" in normalized_finding:
                normalized_finding["file"] = source_file
            findings.append(normalized_finding)

    return findings