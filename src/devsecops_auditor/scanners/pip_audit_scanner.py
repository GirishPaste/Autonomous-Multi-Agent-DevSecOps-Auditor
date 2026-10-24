
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any


def scan_requirements(requirements_file: str | Path) -> list[dict[str, Any]]:
    """Scan a requirements file with pip-audit and normalize vulnerability findings."""
    requirements = Path(requirements_file).expanduser().resolve()

    if not requirements.is_file():
        raise FileNotFoundError(f"Requirements file not found: {requirements}")

    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--requirement",
                str(requirements),
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"Unable to start pip-audit: {error}") from error

    # pip-audit can return exit code 1 when vulnerabilities are found.
    if result.returncode not in (0, 1):
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"pip-audit failed: {detail}")

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        detail = result.stderr.strip() or "pip-audit returned invalid JSON."
        raise RuntimeError(f"Could not read pip-audit results: {detail}") from error

    findings: list[dict[str, Any]] = []

    for dependency in report.get("dependencies", []):
        package = str(dependency.get("name", "unknown"))
        version = str(dependency.get("version", "unknown"))

        for vulnerability in dependency.get("vulns", []):
            vulnerability_id = str(vulnerability.get("id", "unknown"))
            fix_versions = vulnerability.get("fix_versions") or []

            recommendation = (
                f"Upgrade to one of these versions: {', '.join(map(str, fix_versions))}."
                if fix_versions
                else "Check the vulnerability advisory for an available fix."
            )

            findings.append(
                {
                    "scanner": "pip-audit",
                    "rule_id": vulnerability_id,
                    "severity": "unknown",
                    "file": requirements.name,
                    "line": None,
                    "message": str(
                        vulnerability.get("description")
                        or f"{package} {version} has vulnerability {vulnerability_id}."
                    ),
                    "recommendation": recommendation,
                    "evidence": f"{package}=={version}",
                }
            )

    return findings


def scan_dependencies(project_folder: str | Path) -> list[dict[str, Any]]:
    """Scan requirements.txt or standard project dependencies in pyproject.toml."""
    root = Path(project_folder).expanduser().resolve()

    if not root.is_dir():
        raise NotADirectoryError(f"Project folder not found: {root}")

    requirements_file = root / "requirements.txt"
    pyproject_file = root / "pyproject.toml"

    # Prefer requirements.txt when both supported files exist.
    if requirements_file.is_file():
        return scan_requirements(requirements_file)

    if pyproject_file.is_file():
        try:
            with pyproject_file.open("rb") as file:
                project_data = tomllib.load(file)
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise RuntimeError(
                f"Could not read pyproject.toml: {error}"
            ) from error

        project = project_data.get("project", {})
        dependencies = list(project.get("dependencies", []))

        optional_dependencies = project.get("optional-dependencies", {})
        for group_dependencies in optional_dependencies.values():
            dependencies.extend(group_dependencies)

        if not dependencies:
            raise RuntimeError(
                "pyproject.toml contains no standard project dependencies to audit."
            )

        # pip-audit accepts requirements-style dependency entries.
        temporary_path: Path | None = None

        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".txt",
                encoding="utf-8",
                delete=False,
            ) as temporary_file:
                temporary_file.write("\n".join(dependencies) + "\n")
                temporary_path = Path(temporary_file.name)

            findings = scan_requirements(temporary_path)

            # Report the real source manifest, not the temporary file.
            for finding in findings:
                finding["file"] = "pyproject.toml"

            return findings
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    raise FileNotFoundError(
        f"No supported dependency manifest found in project: {root}. "
        "Expected requirements.txt or pyproject.toml."
    )
