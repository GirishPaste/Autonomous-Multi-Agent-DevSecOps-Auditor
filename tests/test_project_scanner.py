from pathlib import Path

import pytest

from devsecops_auditor.scanners import project_scanner


def test_scan_project_combines_all_scanner_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "app.py").write_text(
        "print('hello')\n",
        encoding="utf-8",
    )
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("packaging==26.3\n", encoding="utf-8")

    bandit_findings = [{"scanner": "bandit", "severity": "LOW"}]
    secret_findings = [{"scanner": "secrets", "severity": "HIGH"}]
    dependency_findings = [{"scanner": "pip-audit", "severity": "MEDIUM"}]

    monkeypatch.setattr(
        project_scanner,
        "scan_python",
        lambda folder: bandit_findings,
    )
    monkeypatch.setattr(
        project_scanner,
        "scan_secrets",
        lambda folder: secret_findings,
    )
    monkeypatch.setattr(
        project_scanner,
        "scan_requirements",
        lambda file: dependency_findings,
    )

    findings = project_scanner.scan_project(tmp_path)

    assert findings == bandit_findings + secret_findings + dependency_findings


def test_scans_nested_requirements_and_skips_virtual_environments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_requirements = tmp_path / "requirements.txt"
    nested_requirements = tmp_path / "services" / "api" / "dev-requirements.txt"
    excluded_requirements = (
        tmp_path / ".venv" / "lib" / "requirements.txt"
    )

    root_requirements.write_text("root-package==1.0\n", encoding="utf-8")
    nested_requirements.parent.mkdir(parents=True)
    nested_requirements.write_text("api-package==1.0\n", encoding="utf-8")
    excluded_requirements.parent.mkdir(parents=True)
    excluded_requirements.write_text("venv-package==1.0\n", encoding="utf-8")

    scanned_files: list[str] = []

    def fake_scan_requirements(file: str | Path) -> list[dict[str, str]]:
        path = Path(file)
        relative_path = path.relative_to(tmp_path).as_posix()
        scanned_files.append(relative_path)
        return [{"scanner": "pip-audit", "file": path.name}]

    monkeypatch.setattr(project_scanner, "scan_python", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: [])
    monkeypatch.setattr(
        project_scanner,
        "scan_requirements",
        fake_scan_requirements,
    )

    findings = project_scanner.scan_project(tmp_path)

    expected_files = [
        "requirements.txt",
        "services/api/dev-requirements.txt",
    ]
    assert scanned_files == expected_files
    assert [finding["file"] for finding in findings] == expected_files


def test_skips_dependency_scan_without_requirements(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "app.py").write_text(
        "print('hello')\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(project_scanner, "scan_python", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: [])

    def unexpected_dependency_scan(file: str | Path) -> list[dict[str, str]]:
        pytest.fail("Dependency scan should be skipped")

    monkeypatch.setattr(
        project_scanner,
        "scan_requirements",
        unexpected_dependency_scan,
    )

    assert project_scanner.scan_project(tmp_path) == []


def test_missing_project_directory_raises_error(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError):
        project_scanner.scan_project(missing)