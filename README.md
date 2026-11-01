# Autonomous Multi-Agent DevSecOps Auditor

A local security auditing tool for Python projects. Scan a ZIP archive or GitHub repository, review findings in a web interface, and download a security report with explanations and recommended fixes.

## Features

- **Python code scanning:** Uses Bandit to find potentially risky code patterns.
- **Secret scanning:** Detects possible credentials and redacts their values from findings and reports.
- **Dependency scanning:** Uses pip-audit to check a root `requirements.txt` for known vulnerabilities.
- **Finding explanations:** Provides problem descriptions, potential impact, and recommended solutions. The web report can use OpenRouter's `openrouter/free` model route, with local explanations as a fallback.
- **Safe ZIP handling:** Checks archives before extracting them for scanning.
- **GitHub repository scanning:** Accepts HTTPS repository URLs. Public repositories do not need a token; private repositories can use an optional GitHub token.
- **Live scan progress:** Shows each scanner's status in the web interface.
- **Reports:** The CLI generates JSON and Markdown reports. The web interface downloads a Markdown report.

The tool reports findings and recommendations. It does not automatically modify the scanned project's code.

## Requirements

- Python 3.11
- Git on `PATH` for GitHub repository scans
- Internet access for GitHub scans, dependency vulnerability checks, and optional AI report explanations

## Install on Windows

Open PowerShell in the project folder and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pytest
$env:PYTHONPATH = "$PWD\src"
```

## Start the website

After installation, start the website from the project folder:

```powershell
.\start_website.bat
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser. Keep the terminal window open while using the website. Press **Ctrl+C** in that terminal to stop the server.

## Optional AI report explanations

The report agent requests the OpenRouter `openrouter/free` model route when an API key is configured. If the route is unavailable, the app uses local explanations instead.

To enable it, create a `.env` file in the project root containing:

```text
OPENROUTER_API_KEY=your-openrouter-api-key
```

The repository's `.gitignore` excludes `.env`. Do not add API keys to source files or commit them. AI report generation is optional; scanning and local explanations work without an API key.

The report agent sends sanitized finding descriptions for explanation. It does not send scanned source code or scanner evidence.

## Scan a GitHub repository

In the website, enter the repository's HTTPS URL and select **Scan repository**.

- Public repositories can be scanned without a token.
- For a private repository, expand the token section and enter a GitHub token with access to that repository.

## Run a scan from the command line

Set the source folder and choose an output folder:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m devsecops_auditor.cli .\path\to\project --output .\reports\scan
```

To return a nonzero exit code when a high-severity finding is present:

```powershell
python -m devsecops_auditor.cli .\path\to\project --output .\reports\scan --fail-on high
```

The CLI writes JSON and Markdown reports to the selected output folder.

## Run the tests

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m pytest -q
```

## Notes

- Secret detection can produce false positives. Verify findings in their context without copying credential values into reports or messages.
- Dependency checks require an internet connection.
- OpenRouter model availability and limits may change; local report explanations remain available as a fallback.