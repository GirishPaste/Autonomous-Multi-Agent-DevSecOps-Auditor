from pathlib import Path
import zipfile

import pytest

from devsecops_auditor.scanners.safe_zip import (
    UnsafeZipError,
    safe_extract_zip,
)


def _make_zip(zip_path: Path, members: dict[str, str]) -> None:
    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, content in members.items():
            archive.writestr(name, content)


def test_extracts_safe_files(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        {
            "hello.txt": "Hello, ZIP!",
            "nested/info.txt": "Nested file",
        },
    )

    safe_extract_zip(archive_path, destination)

    assert (destination / "hello.txt").read_text(encoding="utf-8") == "Hello, ZIP!"
    assert (destination / "nested" / "info.txt").read_text(encoding="utf-8") == "Nested file"


def test_rejects_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.zip"
    destination = tmp_path / "extracted"
    _make_zip(archive_path, {"../outside.txt": "should not be extracted"})

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination)

    assert not (tmp_path / "outside.txt").exists()


def test_rejects_file_over_size_limit(tmp_path: Path) -> None:
    archive_path = tmp_path / "large.zip"
    destination = tmp_path / "extracted"
    _make_zip(archive_path, {"large.txt": "x" * 10})

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(
            archive_path,
            destination,
            max_file_size=5,
        )