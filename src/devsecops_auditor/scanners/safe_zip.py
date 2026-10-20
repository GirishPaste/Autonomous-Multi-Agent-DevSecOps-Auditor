from __future__ import annotations

import os
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


class UnsafeZipError(ValueError):
    pass


_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def _validated_member(info: zipfile.ZipInfo) -> tuple[str, bool]:
    name = info.filename.replace("\\", "/")
    is_directory = name.endswith("/")

    if is_directory:
        name = name[:-1]

    if not name or name.startswith("/") or PureWindowsPath(name).drive:
        raise UnsafeZipError(f"Absolute or empty ZIP path: {info.filename!r}")

    parts = name.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise UnsafeZipError(f"Unsafe ZIP path: {info.filename!r}")

    for part in parts:
        invalid = any(ord(char) < 32 or char in '<>:"|?*' for char in part)
        if invalid or part.endswith((".", " ")):
            raise UnsafeZipError(f"Invalid path component: {info.filename!r}")
        if part.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
            raise UnsafeZipError(f"Reserved Windows path: {info.filename!r}")

    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise UnsafeZipError(
            f"Links and special files are not allowed: {info.filename!r}"
        )
    if file_type == stat.S_IFDIR:
        is_directory = True
    elif file_type == stat.S_IFREG and is_directory:
        raise UnsafeZipError(f"Invalid directory entry: {info.filename!r}")

    if is_directory and info.file_size != 0:
        raise UnsafeZipError(f"Directory entry contains data: {info.filename!r}")

    return "/".join(parts), is_directory


def safe_extract_zip(
    archive_path: str | Path,
    destination: str | Path,
    *,
    max_members: int = 10_000,
    max_total_size: int = 500 * 1024 * 1024,
    max_file_size: int = 100 * 1024 * 1024,
    max_compression_ratio: float = 1_000,
) -> list[Path]:
    """Safely extract a ZIP archive into a new destination directory."""
    if min(max_members, max_total_size, max_file_size) <= 0:
        raise ValueError("All extraction limits must be greater than zero")
    if max_compression_ratio <= 0:
        raise ValueError("All extraction limits must be greater than zero")

    extracted_names: list[str] = []
    destination_path: Path | None = None
    destination_created = False
    extraction_complete = False

    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > max_members:
                raise UnsafeZipError("ZIP archive contains too many members")

            validated: list[tuple[zipfile.ZipInfo, str, bool]] = []
            entries: dict[str, tuple[str, bool]] = {}
            declared_total = 0

            for info in members:
                if info.flag_bits & 0x1:
                    raise UnsafeZipError(
                        f"Encrypted ZIP member is not supported: {info.filename!r}"
                    )

                name, is_directory = _validated_member(info)
                key = name.casefold()
                if key in entries:
                    raise UnsafeZipError(
                        f"Duplicate ZIP member path: {info.filename!r}"
                    )
                entries[key] = (name, is_directory)

                if not is_directory:
                    if info.file_size > max_file_size:
                        raise UnsafeZipError(
                            f"ZIP member exceeds the file size limit: {info.filename!r}"
                        )

                    declared_total += info.file_size
                    if declared_total > max_total_size:
                        raise UnsafeZipError(
                            "ZIP archive exceeds the total uncompressed size limit"
                        )

                    ratio = info.file_size / max(info.compress_size, 1)
                    if ratio > max_compression_ratio:
                        raise UnsafeZipError(
                            f"ZIP member exceeds the compression ratio limit: "
                            f"{info.filename!r}"
                        )

                validated.append((info, name, is_directory))

            parent_keys: set[str] = set()
            for _, name, _ in validated:
                parts = name.split("/")
                parent_keys.update(
                    "/".join(parts[:index]).casefold()
                    for index in range(1, len(parts))
                )

            for key, (name, is_directory) in entries.items():
                if not is_directory and key in parent_keys:
                    raise UnsafeZipError(
                        f"A file is also used as a directory: {name!r}"
                    )

            requested = Path(os.path.abspath(Path(destination).expanduser()))
            requested.parent.mkdir(parents=True, exist_ok=True)
            destination_path = requested.parent.resolve() / requested.name

            if destination_path.exists() or destination_path.is_symlink():
                raise FileExistsError(
                    f"Destination already exists: {destination_path}"
                )

            destination_path.mkdir()
            destination_created = True
            written_total = 0

            for info, name, is_directory in validated:
                target = destination_path.joinpath(*PurePosixPath(name).parts)

                if is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                written_file = 0

                with archive.open(info) as source, target.open("xb") as output:
                    while chunk := source.read(64 * 1024):
                        written_file += len(chunk)
                        written_total += len(chunk)

                        if (
                            written_file > max_file_size
                            or written_total > max_total_size
                        ):
                            raise UnsafeZipError(
                                "ZIP data exceeded the configured extraction limits"
                            )

                        output.write(chunk)

                if written_file != info.file_size:
                    raise UnsafeZipError(
                        "ZIP member size does not match its metadata: "
                        f"{info.filename!r}"
                    )

                extracted_names.append(name)

            extraction_complete = True
            return [
                destination_path.joinpath(*PurePosixPath(name).parts)
                for name in extracted_names
            ]
    finally:
        if (
            destination_created
            and not extraction_complete
            and destination_path is not None
        ):
            shutil.rmtree(destination_path, ignore_errors=True)