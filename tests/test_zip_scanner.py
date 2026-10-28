import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners import zip_scanner
from devsecops_auditor.scanners.safe_zip import UnsafeZipError

def test_scan_zip_returns_findings_and_cleans_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive_path = tmp_path / "project.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")

    expected_findings = [
        {"scanner": "secrets", "severity": "LOW"}
    ]
    scanned_directories = []

    def fake_scan_project(folder):
        folder = Path(folder)
        scanned_directories.append(folder)

        assert (folder / "app.py").is_file()
        return expected_findings

    monkeypatch.setattr(
        zip_scanner, "scan_project", fake_scan_project
    )

    findings = zip_scanner.scan_zip(archive_path)

    assert findings == expected_findings
    assert len(scanned_directories) == 1
    assert not scanned_directories[0].exists()
def test_scan_zip_missing_file_raises_error(tmp_path: Path):
    missing_archive = tmp_path / "missing.zip"

    with pytest.raises(FileNotFoundError, match="ZIP archive not found"):
        zip_scanner.scan_zip(missing_archive)


def test_scan_zip_rejects_unsafe_archive(tmp_path: Path):
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("../outside.txt", "unsafe content")
    with pytest.raises(UnsafeZipError):
        zip_scanner.scan_zip(archive_path)
def test_scan_zip_cleans_up_when_project_scan_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    archive_path = tmp_path / "project.zip"

    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("app.py", "print('hello')\n")

    scanned_directories = []

    def failing_scan_project(folder):
        folder = Path(folder)
        scanned_directories.append(folder)
        assert (folder / "app.py").is_file()
        raise RuntimeError("Simulated scanner failure")

    monkeypatch.setattr(
        zip_scanner, "scan_project", failing_scan_project
    )

    with pytest.raises(RuntimeError, match="Simulated scanner failure"):
        zip_scanner.scan_zip(archive_path)

    assert len(scanned_directories) == 1
    assert not scanned_directories[0].exists()
