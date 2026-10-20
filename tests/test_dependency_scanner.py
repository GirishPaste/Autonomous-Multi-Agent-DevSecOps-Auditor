from dependency_scanner import (
    check_vulnerabilities,
    parse_requirements,
    scan_requirements,
)
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

class TestParseRequirements(unittest.TestCase):
    def test_parses_pinned_and_unpinned_packages(self):
        content = (
            "requests==2.31.0\n"
            "packaging>=23.0\n"
            "# this is a comment\n"
            "\n"
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "requirements.txt"
            file_path.write_text(content, encoding="utf-8")
            result = parse_requirements(file_path)

        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "requests")
        self.assertEqual(result[0]["version"], "2.31.0")
        self.assertTrue(result[0]["pinned"])
        self.assertEqual(result[1]["name"], "packaging")
        self.assertIsNone(result[1]["version"])
        self.assertFalse(result[1]["pinned"])


class TestVulnerabilityChecker(unittest.TestCase):
    @patch("dependency_scanner.urlopen")
    def test_returns_vulnerabilities_from_osv(self, mock_urlopen):
        response = MagicMock()
        response.__enter__.return_value.read.return_value = (
            json.dumps({
                "vulns": [{"id": "GHSA-test-1234"}]
            }).encode("utf-8")
        )
        mock_urlopen.return_value = response

        result = check_vulnerabilities("example-package", "1.0.0")

        self.assertEqual(result[0]["id"], "GHSA-test-1234")
        mock_urlopen.assert_called_once()

class TestScanRequirements(unittest.TestCase):
    @patch("dependency_scanner.check_vulnerabilities")
    def test_reports_vulnerable_pinned_package(self, mock_check):
        mock_check.return_value = [{"id": "GHSA-test-1234"}]

        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "requirements.txt"
            file_path.write_text(
                "requests==2.31.0\n",
                encoding="utf-8",
            )

            results = scan_requirements(file_path)

        self.assertEqual(results[0]["status"], "vulnerable")
        self.assertEqual(
            results[0]["vulnerabilities"][0]["id"],
            "GHSA-test-1234",
        )

    def test_marks_unpinned_package(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "requirements.txt"
            file_path.write_text(
                "packaging>=23.0\n",
                encoding="utf-8",
            )

            results = scan_requirements(file_path)

        self.assertEqual(
            results[0]["status"],
            "version_not_pinned",
        )

if __name__ == "__main__":
    unittest.main()
