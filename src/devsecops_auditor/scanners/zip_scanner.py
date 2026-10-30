
"""Safely extract and scan ZIP project archives."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from .project_scanner import scan_project
from .safe_zip import safe_extract_zip


def scan_zip(archive_path: str | Path) -> list[dict[str, Any]]:
    """Safely extract a ZIP archive and scan the extracted project."""
    archive = Path(archive_path).expanduser().resolve()

    if not archive.is_file():
        raise FileNotFoundError(f"ZIP archive not found: {archive}")

    with tempfile.TemporaryDirectory(
        prefix="devsecops-zip-"
    ) as temp_dir:
        workspace = Path(temp_dir)
        extracted_project = workspace / "project"

        safe_extract_zip(archive, extracted_project)

        return scan_project(extracted_project)
