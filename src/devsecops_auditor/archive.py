from __future__ import annotations

import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath


def _safe_relative_path(member_name: str) -> Path:
    """Convert a ZIP member name to a safe path beneath the extraction folder."""
    normalized = member_name.replace("\\", "/")

    if (
        not normalized
        or "\x00" in normalized
        or normalized.startswith("/")
        or ":" in normalized
    ):
        raise ValueError(f"Unsafe path in ZIP archive: {member_name!r}")

    relative = PurePosixPath(normalized)

    if not relative.parts or any(part == ".." for part in relative.parts):
        raise ValueError(f"Unsafe path in ZIP archive: {member_name!r}")

    return Path(*relative.parts)


def extract_zip_safely(
    archive_path: str | Path,
    destination: str | Path,
    *,
    max_members: int = 5_000,
    max_uncompressed_bytes: int = 100 * 1024 * 1024,
) -> Path:
    """Extract a ZIP into a new folder after checking its contents."""
    archive_file = Path(archive_path).expanduser()
    if not archive_file.is_file():
        raise FileNotFoundError(f"ZIP archive does not exist: {archive_file}")

    if max_members < 1 or max_uncompressed_bytes < 1:
        raise ValueError("Archive limits must be positive.")

    output = Path(destination).expanduser()
    if output.exists():
        raise FileExistsError(
            f"Extraction destination must be a new folder: {output}"
        )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir()
    root = output.resolve()

    try:
        with zipfile.ZipFile(archive_file) as archive:
            members = archive.infolist()
            if len(members) > max_members:
                raise ValueError(f"ZIP contains more than {max_members} entries.")

            entries: list[tuple[zipfile.ZipInfo, Path, bool]] = []
            seen: dict[str, bool] = {}
            total_size = 0

            for member in members:
                relative = _safe_relative_path(member.filename)
                target = root / relative

                try:
                    target.resolve().relative_to(root)
                except ValueError as error:
                    raise ValueError(
                        f"ZIP path escapes the extraction folder: "
                        f"{member.filename!r}"
                    ) from error

                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(
                        f"Symbolic links are not allowed in ZIP files: "
                        f"{member.filename!r}"
                    )

                is_directory = member.is_dir() or member.filename.endswith(
                    ("/", "\\")
                )
                key = relative.as_posix().casefold()
                if key in seen:
                    raise ValueError(
                        f"Duplicate path in ZIP archive: {member.filename!r}"
                    )

                seen[key] = is_directory
                entries.append((member, relative, is_directory))

                if not is_directory:
                    if member.file_size < 0:
                        raise ValueError("ZIP contains an invalid file size.")
                    total_size += member.file_size
                    if total_size > max_uncompressed_bytes:
                        raise ValueError("ZIP exceeds the uncompressed size limit.")

            for key in seen:
                parts = key.split("/")
                for index in range(1, len(parts)):
                    parent = "/".join(parts[:index])
                    if parent in seen and not seen[parent]:
                        raise ValueError(
                            f"A file is used as a folder in the ZIP: {parent!r}"
                        )

            extracted_size = 0
            for member, relative, is_directory in entries:
                target = root / relative

                if is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("xb") as output_file:
                    while chunk := source.read(64 * 1024):
                        extracted_size += len(chunk)
                        if extracted_size > max_uncompressed_bytes:
                            raise ValueError(
                                "ZIP exceeds the uncompressed size limit."
                            )
                        output_file.write(chunk)

        return root
    except Exception:
        shutil.rmtree(root, ignore_errors=True)
        raise