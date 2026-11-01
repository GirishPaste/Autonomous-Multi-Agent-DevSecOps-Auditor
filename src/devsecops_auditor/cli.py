
"""Command-line interface for the DevSecOps Auditor."""

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .scanners.project_scanner import scan_project
from .scanners.redaction import redact_sensitive_data
from .scanners.zip_scanner import scan_zip


def write_reports(
    findings: list[dict[str, Any]],
    output_dir: str | Path,
    *,
    secret_values: Iterable[str] | None = None,
) -> tuple[Path, Path]:
    """Write sanitized findings to JSON and Markdown reports."""
    # Sanitize findings before writing either report.
    safe_findings = redact_sensitive_data(
        findings,
        secret_values,
    )

    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)

    json_path = destination / "report.json"
    markdown_path = destination / "report.md"

    # Write sanitized JSON report.
    json_path.write_text(
        json.dumps(
            safe_findings,
            indent=2,
            ensure_ascii=False,
        ) + "\n",
        encoding="utf-8",
    )

    # Generate sanitized Markdown report.
    lines = [
        "# DevSecOps Auditor Report",
        "",
        f"**Total findings:** {len(safe_findings)}",
        "",
    ]

    if not safe_findings:
        lines.append("No security findings were reported.")
    else:
        for number, finding in enumerate(safe_findings, start=1):
            lines.extend(
                [
                    f"## Finding {number}",
                    "",
                ]
            )

            for key, value in finding.items():
                lines.append(
                    f"- **{key.replace('_', ' ').title()}:** {value}"
                )

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
        help="Path to the project directory or ZIP archive to scan",
    )

    parser.add_argument(
        "--zip",
        action="store_true",
        help="Treat the project argument as a ZIP archive",
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports (default: reports)",
    )

    args = parser.parse_args()

    try:
        if args.zip:
            findings = scan_zip(args.project)
        else:
            findings = scan_project(args.project)

        json_path, markdown_path = write_reports(
            findings,
            args.output,
        )

    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Scan complete. Findings: {len(findings)}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
