@echo off
cd /d "%~dp0"
set "PYTHONPATH=%CD%\src"

if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -m uvicorn devsecops_auditor.web.app:app --reload --app-dir "%CD%\src"
) else (
    python -m uvicorn devsecops_auditor.web.app:app --reload --app-dir "%CD%\src"
)

pause
