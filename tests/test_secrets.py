from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make the src/ package importable while running pytest from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners.secrets import scan_secrets  # noqa: E402


def test_detects_fake_secret_and_redacts_it_from_finding(tmp_path: Path) -> None:
    fake_secret = "fake-test-secret-84d07b3c9a"
    (tmp_path / "settings.py").write_text(
        f'password = "{fake_secret}"\n', encoding="utf-8"
    )

    findings = scan_secrets(tmp_path)

    assert findings
    finding = findings[0]
 feature/python-code-scanner


 main
    assert set(finding) == {
        "scanner",
        "rule_id",
        "severity",
        "file",
        "line",
        "message",
        "recommendation",
        "evidence",
    }
    assert finding["scanner"] == "secrets"
    assert finding["rule_id"].islower()
    assert finding["severity"] == "high"
    assert finding["file"] == "settings.py"
    assert finding["line"] == 1
    assert "[REDACTED]" in finding["evidence"]
    assert fake_secret not in repr(findings)


def test_returns_no_findings_for_clean_file(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
 feature/python-code-scanner
        "def greet(name):\n    return f'Hello, {name}'\n",
        encoding="utf-8",

        "def greet(name):\n    return f'Hello, {name}'\n", encoding="utf-8"
 main
    )

    assert scan_secrets(tmp_path) == []


 feature/python-code-scanner
def test_raises_error_for_missing_folder(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_secrets(tmp_path / "missing")


def test_raises_error_when_target_is_a_file(tmp_path: Path) -> None:
    target_file = tmp_path / "not-a-folder.txt"
    target_file.write_text("test", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        scan_secrets(target_file)



 main
@pytest.mark.parametrize(
    "excluded_directory",
    [
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".cache",
        "cache",
        "dist",
        "generated",
        "outputs",
    ],
)
def test_skips_excluded_directories(
    tmp_path: Path, excluded_directory: str
) -> None:
    fake_secret = "fake-test-secret-51a9c7e8d2"
    excluded_file = tmp_path / excluded_directory / "settings.py"
    excluded_file.parent.mkdir()
    excluded_file.write_text(
        f'password = "{fake_secret}"\n', encoding="utf-8"
    )

    assert scan_secrets(tmp_path) == []


def test_raises_a_clear_error_for_missing_target(tmp_path: Path) -> None:
    missing_target = tmp_path / "does-not-exist"

    with pytest.raises(FileNotFoundError, match="Scan target does not exist"):
        scan_secrets(missing_target)


def test_raises_a_clear_error_when_target_is_a_file(tmp_path: Path) -> None:
    target_file = tmp_path / "not-a-directory.txt"
    target_file.write_text("nothing to scan", encoding="utf-8")

    with pytest.raises(NotADirectoryError, match="Scan target is not a directory"):
 feature/python-code-scanner
        scan_secrets(target_file)

        scan_secrets(target_file)
 main
