# Autonomous Multi-Agent DevSecOps Auditor

A local security scanner for Python projects. It checks source code, dependencies, and files for potential security issues, then presents findings in reports and a web interface.

## Features

- **Python code scanning:** Uses Bandit to identify common risky code patterns.
- **Secret scanning:** Looks for exposed credentials and redacts detected values from its own evidence.
- **Dependency scanning:** Uses pip-audit to check a root `requirements.txt` file for known vulnerabilities.
- **Finding explanations:** The web workflow uses local agents to explain code, dependency, and secret findings.
- **ZIP scanning:** Safely extracts ZIP archives before scanning.
- **GitHub scanning:** Scans HTTPS GitHub repository URLs. Public repositories need no token; private repositories can use an optional GitHub token.
- **Reports:** The CLI creates JSON and Markdown reports. The web interface provides a downloadable JSON report.
- **Live progress:** The web interface shows the status of each scan stage.

The agents use local rule-based analysis. An AI or other model API key is not required.

## Requirements

- Python 3.11
- Git installed and available on `PATH` for GitHub repository scans
- Internet access for GitHub cloning and dependency vulnerability checks

## Install on Windows

Open PowerShell in the project folder and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
$env:PYTHONPATH = "$PWD\src"