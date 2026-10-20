from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners.secrets import scan_secrets  # noqa: E402


def test_detects_and_redacts_fake_secret(tmp_path: Path) -> None:
    fake_secret = "fake-test-secret-84d07b3c9a"
    (tmp_path / "settings.py").write_text(
        f'password = "{fake_secret}"\n', encoding="utf-8"
    )

    findings = scan_secrets(tmp_path)

    assert findings
    finding = findings[0]
    assert finding["scanner"] == "secrets"
    assert finding["severity"] == "high"
    assert finding["file"] == "settings.py"
    assert finding["line"] == 1
    assert "[REDACTED]" in finding["evidence"]
    assert fake_secret not in repr(findings)


def test_returns_no_findings_for_clean_file(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def greet(name):\n    return f'Hello, {name}'\n",
        encoding="utf-8",
    )

    assert scan_secrets(tmp_path) == []


def test_raises_error_for_missing_folder(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        scan_secrets(tmp_path / "missing")


def test_raises_error_when_target_is_a_file(tmp_path: Path) -> None:
    target_file = tmp_path / "not-a-folder.txt"
    target_file.write_text("test", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        scan_secrets(target_file)