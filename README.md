# Autonomous Multi-Agent DevSecOps Auditor

A beginner-friendly security auditing tool that helps identify potential security issues in software projects, including exposed secrets, vulnerable Python dependencies, and risky Python code.

## Features

- **Secret scanning:** Detects potential secrets in project files.
- **Dependency scanning:** Checks Python dependencies for known vulnerabilities.
- **Python code scanning:** Uses Bandit to identify potential security issues in Python code.
- **Project scanning:** Combines supported scanners into a project-level scan.
- **Automated testing:** Uses pytest to check scanner functionality.

## Requirements

- Python 3.11
- pip
- Git

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/GirishPaste/Autonomous-Multi-Agent-DevSecOps-Auditor.git
cd Autonomous-Multi-Agent-DevSecOps-Auditor
```

### 2. Create a virtual environment

For Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this in the current terminal session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment again.

### 3. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
```

### 4. Run the tests

```powershell
python -m pytest -q
```

The tests check supported functionality and help catch regressions.

## Continuous Integration

GitHub Actions runs the test suite when changes are pushed to `main` or feature branches, and when pull requests target `main`.

## Project Status

This project is under development. Scan results should be reviewed before making security decisions. Scanner coverage depends on the tools and checks implemented in the repository.

## Contributing
Create a feature branch, make focused changes, run the tests, and submit a pull request for review.