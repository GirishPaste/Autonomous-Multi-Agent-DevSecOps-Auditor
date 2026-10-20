
import argparse
import json
from pathlib import Path
from packaging.requirements import Requirement
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def parse_requirements(file_path):
    """Read requirements.txt and extract dependency information."""
    dependencies = []

    with Path(file_path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            try:
                requirement = Requirement(line)
            except Exception as error:
                dependencies.append({
                    "line": line_number,
                    "requirement": line,
                    "error": str(error),
                })
                continue

            pinned_versions = [
                spec.version
                for spec in requirement.specifier
                if spec.operator in ("==", "===")
                and "*" not in spec.version
            ]

            dependencies.append({
                "name": requirement.name,
                "version": pinned_versions[0]
                if len(pinned_versions) == 1 else None,
                "line": line_number,
                "pinned": len(pinned_versions) == 1,
            })

    return dependencies

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


OSV_API_URL = "https://api.osv.dev/v1/query"


def check_vulnerabilities(package_name, version, timeout=10):
    """Check one exact PyPI package version against the OSV database."""

    if not package_name or not version:
        raise ValueError("Package name and exact version are required.")

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI",
        },
        "version": version,
    }

    request = Request(
        OSV_API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))

    except HTTPError as error:
        raise RuntimeError(
            f"OSV API returned HTTP {error.code}"
        ) from error
    except (URLError, TimeoutError) as error:
        raise RuntimeError(
            f"Could not reach OSV API: {error}"
        ) from error
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "OSV API returned invalid JSON"
        ) from error

    return data.get("vulns", [])


def scan_requirements(file_path, timeout=10):
    """Scan requirements and report known vulnerabilities."""
    dependencies = parse_requirements(file_path)
    results = []

    for dependency in dependencies:
        # Invalid requirement lines are reported, not ignored.
        if "error" in dependency:
            results.append({
                **dependency,
                "status": "invalid_requirement",
            })
            continue

        name = dependency["name"]
        version = dependency["version"]

        # We cannot query OSV accurately without an exact version.
        if not dependency["pinned"]:
            results.append({
                **dependency,
                "status": "version_not_pinned",
                "message": "An exact version is needed for this check.",
            })
            continue

        try:
            vulnerabilities = check_vulnerabilities(
                name, version, timeout=timeout
            )

            results.append({
                **dependency,
                "status": (
                    "vulnerable"
                    if vulnerabilities
                    else "no_known_vulnerabilities"
                ),
                "vulnerabilities": vulnerabilities,
            })

        except (RuntimeError, ValueError) as error:
            results.append({
                **dependency,
                "status": "scan_error",
                "message": str(error),
            })

    return results

def main():
    parser = argparse.ArgumentParser(
        description="Scan Python dependencies for known vulnerabilities."
    )
    parser.add_argument(
        "requirements_file",
        help="Path to the requirements.txt file to scan",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="OSV request timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    try:
        results = scan_requirements(
            args.requirements_file,
            timeout=args.timeout,
        )
    except OSError as error:
        parser.exit(1, f"Error reading requirements file: {error}\n")

    print(json.dumps(results, indent=2))

    if any(
        result["status"] in ("vulnerable", "scan_error", "invalid_requirement")
        for result in results
    ):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

def scan_requirements(file_path, timeout=10):
    """Scan dependencies for known vulnerabilities."""
    dependencies = parse_requirements(file_path)
    results = []

    for dependency in dependencies:
        # Report invalid requirement lines.
        if "error" in dependency:
            results.append({
                **dependency,
                "status": "invalid_requirement",
            })
            continue

        name = dependency["name"]
        version = dependency["version"]

        # An exact version is needed for this check.
        if not dependency["pinned"]:
            results.append({
                **dependency,
                "status": "version_not_pinned",
                "message": "An exact version is needed for this check.",
            })
            continue

        try:
            vulnerabilities = check_vulnerabilities(
                name, version, timeout=timeout
            )

            results.append({
                **dependency,
                "status": (
                    "vulnerable"
                    if vulnerabilities
                    else "no_known_vulnerabilities"
                ),
                "vulnerabilities": vulnerabilities,
            })

        except (RuntimeError, ValueError) as error:
            results.append({
                **dependency,
                "status": "scan_error",
                "message": str(error),
            })

    return results
def main():
    parser = argparse.ArgumentParser(
        description="Scan Python dependencies for known vulnerabilities."
    )

    parser.add_argument(
        "requirements_file",
        help="Path to the requirements.txt file to scan",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="OSV request timeout in seconds (default: 10)",
    )

    args = parser.parse_args()

    try:
        results = scan_requirements(
            args.requirements_file,
            timeout=args.timeout,
        )
    except OSError as error:
        parser.exit(1, f"Error reading requirements file: {error}\n")

    print(json.dumps(results, indent=2))

    if any(
        result["status"] in (
            "vulnerable",
            "scan_error",
            "invalid_requirement",
        )
        for result in results
    ):
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())