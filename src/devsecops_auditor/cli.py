"""Command-line interface for the DevSecOps Auditor."""

import argparse
import json
import zipfile
from pathlib import Path
from typing import Any

from .scanners.project_scanner import scan_project
from .scanners.zip_scanner import scan_zip


_SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_FAIL_ON_CHOICES = ("any", "critical", "high", "medium", "low", "info")


def scan_target(target: str | Path) -> list[dict[str, Any]]:
    """Scan a project directory or a ZIP archive."""
    target_path = Path(target).expanduser()

    if target_path.is_dir():
        return scan_project(target_path)

    if target_path.suffix.lower() == ".zip":
        return scan_zip(target_path)

    return scan_project(target_path)


def _should_fail(
    findings: list[dict[str, Any]],
    fail_on: str | None,
) -> bool:
    if fail_on is None:
        return False

    if fail_on == "any":
        return bool(findings)

    threshold = _SEVERITY_LEVELS[fail_on]
    return any(
        _SEVERITY_LEVELS.get(
            str(finding.get("severity", "")).casefold(),
            -1,
        )
        >= threshold
        for finding in findings
    )


def write_reports(
    findings: list[dict[str, Any]],
    output_dir: str | Path,
) -> tuple[Path, Path]:
    """Write findings to JSON and Markdown reports."""
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)

    json_path = destination / "report.json"
    markdown_path = destination / "report.md"

    json_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# DevSecOps Auditor Report",
        "",
        f"**Total findings:** {len(findings)}",
        "",
    ]

    if not findings:
        lines.append("No security findings were reported.")
    else:
        for number, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"## Finding {number}",
                    "",
                ]
            )

            for key, value in finding.items():
                if key.lower() in {"secret", "secret_value", "raw_secret"}:
                    value = "[REDACTED]"
                lines.append(f"- **{key.replace('_', ' ').title()}:** {value}")

            lines.append("")

    markdown_path.write_text(
        "\n".join(lines).rstrip() + "\n",
        encoding="utf-8",
    )

    return json_path, markdown_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Scan a project directory or ZIP archive and generate "
            "JSON and Markdown reports."
        )
    )
    parser.add_argument(
        "project",
        help="Path to a project directory or .zip archive to scan",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports (default: reports)",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_ON_CHOICES,
        default=None,
        help=(
            "Return exit code 1 for findings at or above this severity. "
            "'any' fails for every finding, including unknown severity."
        ),
    )
    args = parser.parse_args()

    try:
        findings = scan_target(args.project)
        json_path, markdown_path = write_reports(findings, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        parser.error(str(exc))

    print(f"Scan complete. Findings: {len(findings)}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")

    if _should_fail(findings, args.fail_on):
        print(f"Scan failed: findings met the --fail-on {args.fail_on} threshold.")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())