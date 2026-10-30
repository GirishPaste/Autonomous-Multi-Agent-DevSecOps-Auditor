from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from devsecops_auditor.scanners.bandit_scanner import scan_python  # noqa: E402


def test_maps_bandit_json_to_normalized_finding(tmp_path: Path) -> None:
    source = tmp_path / "src" / "unsafe.py"
    source.parent.mkdir()
    source.write_text("import pickle\n", encoding="utf-8")
    report = {
        "results": [
            {
                "filename": "src/unsafe.py",
                "test_id": "B403",
                "issue_severity": "Low",
                "line_number": 1,
                "issue_text": "Consider possible security implications",
                "more_info": "https://bandit.readthedocs.io/",
                "code": "import pickle",
            }
        ]
    }
    completed = SimpleNamespace(returncode=1, stdout=json.dumps(report), stderr="")

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ) as run:
        findings = scan_python(tmp_path)

    assert findings == [
        {
            "scanner": "bandit",
            "rule_id": "B403",
            "severity": "low",
            "file": "src/unsafe.py",
            "line": 1,
            "message": "Consider possible security implications",
            "recommendation": "https://bandit.readthedocs.io/",
            "evidence": "Bandit rule B403 flagged line 1; source excerpt omitted.",
        }
    ]
    args = run.call_args.args[0]
    assert args[:5] == [sys.executable, "-m", "bandit", "-f", "json"]
    assert Path(args[-1]) == Path("src") / "unsafe.py"
    assert run.call_args.kwargs["cwd"] == tmp_path.resolve()
    assert run.call_args.kwargs["check"] is False


def test_returns_empty_list_for_clean_python_project(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    completed = SimpleNamespace(
        returncode=0, stdout=json.dumps({"results": []}), stderr=""
    )

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ):
        assert scan_python(tmp_path) == []


def test_scans_python_files_only_and_skips_venv(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not Python", encoding="utf-8")
    virtualenv_file = tmp_path / ".venv" / "ignored.py"
    virtualenv_file.parent.mkdir()
    virtualenv_file.write_text("pass\n", encoding="utf-8")
    completed = SimpleNamespace(
        returncode=0, stdout=json.dumps({"results": []}), stderr=""
    )

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ) as run:
        assert scan_python(tmp_path) == []

    assert run.call_args.args[0][-1] == "app.py"


def test_returns_empty_list_without_starting_bandit_when_no_python_files(
    tmp_path: Path,
) -> None:
    (tmp_path / "readme.txt").write_text("text only", encoding="utf-8")
    with patch("devsecops_auditor.scanners.bandit_scanner.subprocess.run") as run:
        assert scan_python(tmp_path) == []
    run.assert_not_called()


def test_reports_a_clear_error_when_bandit_is_missing(tmp_path: Path) -> None:
    completed = SimpleNamespace(
        returncode=1, stdout="", stderr="No module named bandit"
    )
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ), pytest.raises(RuntimeError, match="Bandit scanner failed"):
        scan_python(tmp_path)


def test_reports_a_clear_error_when_bandit_cannot_start(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        side_effect=FileNotFoundError("python executable missing"),
    ), pytest.raises(RuntimeError, match="Unable to start Bandit scanner"):
        scan_python(tmp_path)


def test_reports_a_clear_error_for_failed_bandit_run(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    completed = SimpleNamespace(
        returncode=2, stdout="", stderr="Bandit could not parse input"
    )

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ), pytest.raises(RuntimeError, match="Bandit scanner failed with exit code 2"):
        scan_python(tmp_path)


def test_reports_files_bandit_could_not_scan(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")
    report = {"errors": [{"filename": "app.py", "error": "permission denied"}]}
    completed = SimpleNamespace(
        returncode=1, stdout=json.dumps(report), stderr=""
    )

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ), pytest.raises(RuntimeError, match="could not scan all requested files"):
        scan_python(tmp_path)


def test_reports_a_clear_error_for_missing_target(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Scan target does not exist"):
        scan_python(tmp_path / "missing")


def test_reports_a_clear_error_when_target_is_a_file(tmp_path: Path) -> None:
    target = tmp_path / "file.py"
    target.write_text("pass\n", encoding="utf-8")
    with pytest.raises(NotADirectoryError, match="Scan target is not a directory"):
        scan_python(target)

@pytest.mark.parametrize("rule_id", ["B105", "B106", "B107"])
def test_redacts_hardcoded_password_from_sensitive_bandit_messages(
    tmp_path: Path, rule_id: str
) -> None:
    secret = "fake-regression-secret-73921"
    (tmp_path / "app.py").write_text(
        f'API_TOKEN = "{secret}"\n', encoding="utf-8"
    )

    report = {
        "results": [
            {
                "filename": "app.py",
                "test_id": rule_id,
                "issue_severity": "Low",
                "line_number": 1,
                "issue_text": f"Possible hardcoded password: '{secret}'",
                "more_info": "https://bandit.readthedocs.io/",
            }
        ]
    }
    completed = SimpleNamespace(
        returncode=1, stdout=json.dumps(report), stderr=""
    )

    with patch(
        "devsecops_auditor.scanners.bandit_scanner.subprocess.run",
        return_value=completed,
    ):
        findings = scan_python(tmp_path)

    assert len(findings) == 1
    assert secret not in repr(findings)
    assert findings[0]["rule_id"] == rule_id
    assert findings[0]["message"] == (
        "Potential hardcoded password or secret detected."
    )
    assert findings[0]["file"] == "app.py"
    assert findings[0]["line"] == 1
