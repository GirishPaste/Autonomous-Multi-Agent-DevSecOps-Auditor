from pathlib import Path

import pytest

from devsecops_auditor.scanners import project_scanner


def test_scan_project_combines_scanner_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text(
        "sample-package==1.0\n",
        encoding="utf-8",
    )

    bandit_findings = [{"scanner": "bandit", "severity": "low"}]
    secret_findings = [{"scanner": "secrets", "severity": "high"}]
    dependency_findings = [{"scanner": "pip-audit", "severity": "unknown"}]

    monkeypatch.setattr(project_scanner, "scan_python", lambda folder: bandit_findings)
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: secret_findings)
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
    excluded_requirements = tmp_path / ".venv" / "lib" / "requirements.txt"

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


def test_scans_root_and_nested_lockfiles_and_skips_virtual_environments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root_lock = tmp_path / "pylock.toml"
    nested_lock = tmp_path / "services" / "api" / "pylock.3.11.toml"
    excluded_lock = tmp_path / ".venv" / "pylock.toml"

    root_lock.write_text("# root lock\n", encoding="utf-8")
    nested_lock.parent.mkdir(parents=True)
    nested_lock.write_text("# nested lock\n", encoding="utf-8")
    excluded_lock.parent.mkdir(parents=True)
    excluded_lock.write_text("# ignored lock\n", encoding="utf-8")

    scanned_projects: list[tuple[str, str]] = []

    def fake_scan_locked_project(
        project_directory: str | Path,
        source_file: str,
    ) -> list[dict[str, str]]:
        project_path = Path(project_directory)
        relative_directory = project_path.relative_to(tmp_path).as_posix()
        scanned_projects.append((relative_directory, source_file))
        return [{"scanner": "pip-audit", "file": source_file}]

    monkeypatch.setattr(project_scanner, "scan_python", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_locked_project", fake_scan_locked_project)

    findings = project_scanner.scan_project(tmp_path)

    assert scanned_projects == [
        (".", "pylock.toml"),
        ("services/api", "services/api/pylock.3.11.toml"),
    ]
    assert [finding["file"] for finding in findings] == [
        "pylock.toml",
        "services/api/pylock.3.11.toml",
    ]


def test_scans_multiple_lockfiles_in_a_directory_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "pylock.3.11.toml").write_text("# first\n", encoding="utf-8")
    (tmp_path / "pylock.3.12.toml").write_text("# second\n", encoding="utf-8")

    scanned_labels: list[str] = []

    def fake_scan_locked_project(
        project_directory: str | Path,
        source_file: str,
    ) -> list[dict[str, str]]:
        scanned_labels.append(source_file)
        return []

    monkeypatch.setattr(project_scanner, "scan_python", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_locked_project", fake_scan_locked_project)

    project_scanner.scan_project(tmp_path)

    assert scanned_labels == ["pylock*.toml"]


def test_skips_dependency_scan_without_manifests(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")

    monkeypatch.setattr(project_scanner, "scan_python", lambda folder: [])
    monkeypatch.setattr(project_scanner, "scan_secrets", lambda folder: [])

    def unexpected_scan(*args: object, **kwargs: object) -> list[dict[str, str]]:
        pytest.fail("Dependency scanning should be skipped")

    monkeypatch.setattr(project_scanner, "scan_requirements", unexpected_scan)
    monkeypatch.setattr(project_scanner, "scan_locked_project", unexpected_scan)

    assert project_scanner.scan_project(tmp_path) == []


def test_missing_project_directory_raises_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        project_scanner.scan_project(tmp_path / "does_not_exist")