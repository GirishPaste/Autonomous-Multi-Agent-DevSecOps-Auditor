from pathlib import Path
import sys
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.archive import extract_zip_safely


def test_extracts_valid_zip(tmp_path: Path) -> None:
    archive = tmp_path / "project.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("src/app.py", "print('hello')")

    result = extract_zip_safely(archive, tmp_path / "extracted")

    assert (result / "src" / "app.py").read_text() == "print('hello')"


def test_rejects_zip_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../outside.txt", "unsafe")

    with pytest.raises(ValueError):
        extract_zip_safely(archive, tmp_path / "extracted")

    assert not (tmp_path / "outside.txt").exists()