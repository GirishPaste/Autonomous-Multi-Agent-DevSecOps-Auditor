from pathlib import Path
import stat
import zipfile

import pytest

from devsecops_auditor.scanners.safe_zip import (
    UnsafeZipError,
    safe_extract_zip,
)


def _make_zip(
    zip_path: Path,
    members: list[tuple[str, str | bytes]],
) -> None:
    with zipfile.ZipFile(
        zip_path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, content in members:
            archive.writestr(name, content)


def test_extracts_safe_files(tmp_path: Path) -> None:
    archive_path = tmp_path / "safe.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        [
            ("hello.txt", "Hello, ZIP!"),
            ("nested/info.txt", "Nested file"),
        ],
    )

    extracted = safe_extract_zip(archive_path, destination)

    assert (destination / "hello.txt").read_text(encoding="utf-8") == "Hello, ZIP!"
    assert (destination / "nested" / "info.txt").read_text(encoding="utf-8") == "Nested file"
    assert len(extracted) == 2


@pytest.mark.parametrize(
    "member_name",
    [
        "../outside.txt",
        "folder/../../outside.txt",
        "/rooted.txt",
        r"C:\outside.txt",
        r"..\outside.txt",
    ],
    ids=[
        "parent-traversal",
        "nested-traversal",
        "posix-absolute-path",
        "windows-drive-path",
        "windows-traversal",
    ],
)
def test_rejects_unsafe_paths(tmp_path: Path, member_name: str) -> None:
    archive_path = tmp_path / "unsafe.zip"
    destination = tmp_path / "extracted"
    _make_zip(archive_path, [(member_name, "should not be extracted")])

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination)

    assert not destination.exists()
    assert not (tmp_path / "outside.txt").exists()


@pytest.mark.parametrize(
    "file_type",
    [stat.S_IFLNK, stat.S_IFIFO],
    ids=["symlink", "fifo-special-file"],
)
def test_rejects_links_and_special_files(
    tmp_path: Path,
    file_type: int,
) -> None:
    archive_path = tmp_path / "special.zip"
    destination = tmp_path / "extracted"

    member = zipfile.ZipInfo("special-entry")
    member.create_system = 3
    member.external_attr = (file_type | 0o777) << 16

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr(member, "not a regular file")

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination)

    assert not destination.exists()


def test_rejects_duplicate_member_paths(tmp_path: Path) -> None:
    archive_path = tmp_path / "duplicate.zip"
    destination = tmp_path / "extracted"

    with pytest.warns(UserWarning, match="Duplicate name"):
        _make_zip(
            archive_path,
            [
                ("duplicate.txt", "first"),
                ("duplicate.txt", "second"),
            ],
        )

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination)


def test_rejects_case_insensitive_duplicate_paths(tmp_path: Path) -> None:
    archive_path = tmp_path / "case-duplicate.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        [
            ("Report.txt", "first"),
            ("report.txt", "second"),
        ],
    )

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination)


def test_rejects_file_used_as_parent_directory(tmp_path: Path) -> None:
    archive_path = tmp_path / "conflict.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        [
            ("bundle", "this is a file"),
            ("bundle/item.txt", "this needs bundle to be a directory"),
        ],
    )

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination)


def test_rejects_too_many_members(tmp_path: Path) -> None:
    archive_path = tmp_path / "many.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        [
            ("one.txt", "one"),
            ("two.txt", "two"),
        ],
    )

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(archive_path, destination, max_members=1)


def test_rejects_total_uncompressed_size_over_limit(tmp_path: Path) -> None:
    archive_path = tmp_path / "total-size.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        [
            ("one.txt", "1234"),
            ("two.txt", "5678"),
        ],
    )

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(
            archive_path,
            destination,
            max_total_size=7,
        )


def test_rejects_high_compression_ratio(tmp_path: Path) -> None:
    archive_path = tmp_path / "compressed.zip"
    destination = tmp_path / "extracted"
    _make_zip(archive_path, [("repetitive.txt", b"A" * 10_000)])

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(
            archive_path,
            destination,
            max_compression_ratio=2,
        )


def test_rejects_file_over_size_limit(tmp_path: Path) -> None:
    archive_path = tmp_path / "large.zip"
    destination = tmp_path / "extracted"
    _make_zip(archive_path, [("large.txt", "x" * 10)])

    with pytest.raises(UnsafeZipError):
        safe_extract_zip(
            archive_path,
            destination,
            max_file_size=5,
        )


def test_refuses_existing_destination_without_changing_it(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "safe.zip"
    destination = tmp_path / "already-exists"
    _make_zip(archive_path, [("new.txt", "new content")])
    destination.mkdir()
    marker = destination / "keep.txt"
    marker.write_text("keep this", encoding="utf-8")

    with pytest.raises(FileExistsError):
        safe_extract_zip(archive_path, destination)

    assert marker.read_text(encoding="utf-8") == "keep this"


def test_removes_partial_output_after_extraction_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive_path = tmp_path / "failure.zip"
    destination = tmp_path / "extracted"
    _make_zip(
        archive_path,
        [
            ("first.txt", "this extracts before the failure"),
            ("second.txt", "this triggers the failure"),
        ],
    )

    original_open = zipfile.ZipFile.open

    def fail_on_second_member(
        zip_file: zipfile.ZipFile,
        member: str | zipfile.ZipInfo,
        *args: object,
        **kwargs: object,
    ):
        member_name = member.filename if isinstance(member, zipfile.ZipInfo) else member
        if member_name == "second.txt":
            raise RuntimeError("simulated extraction failure")
        return original_open(zip_file, member, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", fail_on_second_member)

    with pytest.raises(RuntimeError, match="simulated extraction failure"):
        safe_extract_zip(archive_path, destination)

    assert not destination.exists()