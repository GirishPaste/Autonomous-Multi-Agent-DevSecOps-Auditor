
"""Command-line interface for the DevSecOps Auditor."""

import argparse
import json
from pathlib import Path
from typing import Any

from .scanners.project_scanner import scan_project


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
                # Avoid accidentally publishing raw secret values.
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
        description="Scan a project and generate JSON and Markdown reports."
    )
    parser.add_argument(
        "project",
        help="Path to the project directory to scan",
    )
    parser.add_argument(
        "--output",
        default="reports",
        help="Directory for generated reports (default: reports)",
    )
    args = parser.parse_args()

    try:
        findings = scan_project(args.project)
        json_path, markdown_path = write_reports(findings, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    print(f"Scan complete. Findings: {len(findings)}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
