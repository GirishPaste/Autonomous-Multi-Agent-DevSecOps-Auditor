
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings


_EXCLUDED_DIRECTORIES = {
    ".git",
    ".cache",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "cache",
    "coverage",
    "dist",
    "generated",
    "node_modules",
    "output",
    "outputs",
    "venv",
}


def _raise_walk_error(error: OSError) -> None:
    """Raise directory traversal errors so the caller knows the scan was incomplete."""
    raise error


def _source_files(root: Path) -> list[Path]:
    """List files to scan, skipping excluded folders and symbolic links."""
    files: list[Path] = []

    for current_directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=_raise_walk_error,
    ):
        current_path = Path(current_directory)

        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _EXCLUDED_DIRECTORIES
            and not (current_path / name).is_symlink()
        )

        files.extend(
            current_path / name
            for name in sorted(file_names)
            if not (current_path / name).is_symlink()
        )

    return files


def _redact_line(line: str, secret_values: list[str]) -> str:
    """Remove detected secret values from evidence."""
    redacted = line.rstrip("\r\n")

    for secret_value in sorted(
        set(secret_values),
        key=len,
        reverse=True,
    ):
        if secret_value:
            redacted = redacted.replace(secret_value, "[REDACTED]")

    return redacted


def _rule_id(rule_type: str) -> str:
    """Convert detector names to simple machine-readable IDs."""
    return re.sub(r"[^a-z0-9]+", "_", rule_type.lower()).strip("_")


def scan_secrets_with_values(
    target_folder: str | Path,
) -> tuple[list[dict[str, Any]], list[str]]:
    """
    Scan a folder and return redacted findings plus detected values.

    Detected values are returned separately for internal redaction
    of findings produced by other scanners.
    """
    root = Path(target_folder).expanduser()

    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(
            f"Scan target is not a directory: {root}"
        )

    root = root.resolve()
    collection = SecretsCollection()

    with default_settings():
        for path in _source_files(root):
            collection.scan_file(str(path))

    findings: list[dict[str, Any]] = []

    detected_secret_values = sorted(
        {
            secret.secret_value
            for secrets in collection.data.values()
            for secret in secrets
            if isinstance(secret.secret_value, str)
            and secret.secret_value
        },
        key=len,
        reverse=True,
    )

    for filename, secrets in collection.data.items():
        path = Path(filename)
        line_numbers = sorted(
            {secret.line_number for secret in secrets}
        )

        if not line_numbers:
            continue

        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as source:
            lines = source.readlines()

        for line_number in line_numbers:
            if line_number < 1 or line_number > len(lines):
                evidence = "[REDACTED]"
            else:
                line = lines[line_number - 1]

                secret_values = [
                    secret.secret_value or ""
                    for secret in secrets
                    if secret.line_number == line_number
                ]

                evidence = _redact_line(line, secret_values)

            for secret in sorted(
                (
                    item
                    for item in secrets
                    if item.line_number == line_number
                ),
                key=lambda item: item.type,
            ):
                findings.append(
                    {
                        "scanner": "secrets",
                        "rule_id": _rule_id(secret.type),
                        "severity": "high",
                        "file": path.relative_to(root).as_posix(),
                        "line": line_number,
                        "message": (
                            f"Potential {secret.type} detected; "
                            "secret value redacted."
                        ),
                        "recommendation": (
                            "Revoke and rotate the exposed credential, then remove "
                            "it from the file and any repository history."
                        ),
                        "evidence": evidence,
                    }
                )

    return findings, detected_secret_values


def scan_secrets(target_folder: str | Path) -> list[dict[str, Any]]:
    """
    Preserve the original public interface.

    Existing callers still receive a list of findings.
    """
    findings, _ = scan_secrets_with_values(target_folder)
    return findings
