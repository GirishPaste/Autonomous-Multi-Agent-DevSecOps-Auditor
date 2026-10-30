"""FastAPI entry point and live scan stream for the web interface."""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from ..agents.code_risk_agent import analyze_bandit_findings
from ..agents.dependency_risk_agent import analyze_dependency_findings
from ..agents.secrets_response_agent import analyze_secret_findings
from ..scanners.bandit_scanner import scan_python
from ..scanners.pip_audit_scanner import scan_requirements
from ..scanners.safe_zip import safe_extract_zip
from ..scanners.secrets import scan_secrets
from .repository import (
    InvalidRepositoryURL,
    RepositoryCloneError,
    clone_github_repository,
    normalize_github_repository_url,
)

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
MAX_REPOSITORY_REQUEST_BYTES = 16 * 1024

app = FastAPI(
    title="DevSecOps Auditor",
    version="0.1.0",
)

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    """Serve the web interface."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health_check() -> dict[str, str]:
    """Confirm that the local web server is running."""
    return {
        "status": "ok",
        "application": "DevSecOps Auditor",
    }


def _sse_message(payload: dict[str, Any]) -> str:
    """Format one Server-Sent Event message."""
    return f"data: {json.dumps(payload)}\n\n"


async def _scan_project_event_stream(
    project_root: Path,
) -> AsyncIterator[str]:
    """Run scanners on an extracted or cloned project and stream stage updates."""
    current_stage = "Code Risk"
    current_agent: str | None = "code"

    try:
        all_findings: list[dict[str, Any]] = []

        yield _sse_message(
            {
                "type": "stage",
                "stage": "code",
                "state": "running",
                "progress": 16,
                "message": "Running Bandit and Code Risk analysis...",
            }
        )

        bandit_findings = await asyncio.to_thread(
            scan_python,
            project_root,
        )
        code_findings = await asyncio.to_thread(
            analyze_bandit_findings,
            bandit_findings,
        )
        all_findings.extend(code_findings)

        yield _sse_message(
            {
                "type": "stage",
                "stage": "code",
                "state": "passed",
                "progress": 42,
                "finding_count": len(code_findings),
                "message": f"Code Risk complete: {len(code_findings)} finding(s).",
            }
        )

        current_stage = "Dependency Risk"
        current_agent = "dependencies"
        requirements_file = project_root / "requirements.txt"

        if requirements_file.is_file():
            yield _sse_message(
                {
                    "type": "stage",
                    "stage": "dependencies",
                    "state": "running",
                    "progress": 48,
                    "message": "Checking dependencies and reviewing their risks...",
                }
            )

            raw_dependency_findings = await asyncio.to_thread(
                scan_requirements,
                requirements_file,
            )
            dependency_findings = await asyncio.to_thread(
                analyze_dependency_findings,
                raw_dependency_findings,
            )
            all_findings.extend(dependency_findings)

            yield _sse_message(
                {
                    "type": "stage",
                    "stage": "dependencies",
                    "state": "passed",
                    "progress": 70,
                    "finding_count": len(dependency_findings),
                    "message": (
                        "Dependency Risk complete: "
                        f"{len(dependency_findings)} finding(s)."
                    ),
                }
            )
        else:
            yield _sse_message(
                {
                    "type": "stage",
                    "stage": "dependencies",
                    "state": "skipped",
                    "progress": 70,
                    "finding_count": 0,
                    "message": (
                        "Dependency check skipped: "
                        "no root requirements.txt found."
                    ),
                }
            )

        current_stage = "Secrets Response"
        current_agent = "secrets"

        yield _sse_message(
            {
                "type": "stage",
                "stage": "secrets",
                "state": "running",
                "progress": 76,
                "message": (
                    "Scanning for secrets and preparing safe response guidance..."
                ),
            }
        )

        raw_secret_findings = await asyncio.to_thread(
            scan_secrets,
            project_root,
        )
        secret_findings = await asyncio.to_thread(
            analyze_secret_findings,
            raw_secret_findings,
        )
        all_findings.extend(secret_findings)

        yield _sse_message(
            {
                "type": "stage",
                "stage": "secrets",
                "state": "passed",
                "progress": 96,
                "finding_count": len(secret_findings),
                "message": (
                    f"Secrets review complete: {len(secret_findings)} finding(s)."
                ),
            }
        )

        current_stage = "Report preparation"
        current_agent = None

        yield _sse_message(
            {
                "type": "complete",
                "progress": 100,
                "finding_count": len(all_findings),
                "findings": all_findings,
                "message": f"Scan complete: {len(all_findings)} total finding(s).",
            }
        )

    except Exception:
        logger.exception("Web scan failed during %s", current_stage)
        yield _sse_message(
            {
                "type": "error",
                "stage": current_agent,
                "message": (
                    f"The scan stopped during {current_stage}. "
                    "Check the server terminal for details."
                ),
            }
        )


async def _scan_zip_event_stream(
    archive_path: Path,
    project_root: Path,
) -> AsyncIterator[str]:
    """Safely extract a ZIP and stream the project's scan updates."""
    try:
        yield _sse_message(
            {
                "type": "status",
                "progress": 4,
                "message": "ZIP received. Checking its paths and size limits...",
            }
        )

        await asyncio.to_thread(
            safe_extract_zip,
            archive_path,
            project_root,
        )

        yield _sse_message(
            {
                "type": "status",
                "progress": 12,
                "message": "ZIP validated and safely extracted.",
            }
        )

        async for event in _scan_project_event_stream(project_root):
            yield event

    except Exception:
        logger.exception("Web scan failed during ZIP safety validation")
        yield _sse_message(
            {
                "type": "error",
                "stage": None,
                "message": (
                    "The scan stopped during ZIP safety validation. "
                    "Check the server terminal for details."
                ),
            }
        )


@app.post("/api/scan")
async def scan_uploaded_zip(request: Request) -> StreamingResponse:
    """Save a ZIP upload, then stream scan progress to the browser."""
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", maxsplit=1)[0].strip().lower()

    if media_type != "application/zip":
        raise HTTPException(
            status_code=415,
            detail="Upload a ZIP file to start the scan.",
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail="Invalid upload size.",
            ) from error

        if declared_size > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="The ZIP is larger than the 100 MB upload limit.",
            )

    upload_workspace = tempfile.TemporaryDirectory(
        prefix="devsecops-auditor-web-"
    )
    temporary_root = Path(upload_workspace.name)
    archive_path = temporary_root / "upload.zip"
    project_root = temporary_root / "project"

    uploaded_bytes = 0

    try:
        with archive_path.open("wb") as archive_file:
            async for chunk in request.stream():
                if not chunk:
                    continue

                uploaded_bytes += len(chunk)
                if uploaded_bytes > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail="The ZIP is larger than the 100 MB upload limit.",
                    )

                archive_file.write(chunk)

        if uploaded_bytes == 0:
            raise HTTPException(
                status_code=400,
                detail="The uploaded ZIP is empty.",
            )

    except BaseException:
        upload_workspace.cleanup()
        raise

    async def stream_and_cleanup() -> AsyncIterator[str]:
        try:
            async for event in _scan_zip_event_stream(
                archive_path,
                project_root,
            ):
                yield event
        finally:
            upload_workspace.cleanup()

    return StreamingResponse(
        stream_and_cleanup(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/api/scan/repository")
async def scan_github_repository(request: Request) -> StreamingResponse:
    """Clone a GitHub repository, then stream the project's scan updates."""
    content_type = request.headers.get("content-type", "")
    media_type = content_type.split(";", maxsplit=1)[0].strip().lower()

    if media_type != "application/json":
        raise HTTPException(
            status_code=415,
            detail="Send the repository URL as JSON.",
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            declared_size = int(content_length)
        except ValueError as error:
            raise HTTPException(
                status_code=400,
                detail="Invalid request size.",
            ) from error

        if declared_size > MAX_REPOSITORY_REQUEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail="The repository request is too large.",
            )

    try:
        payload = await request.json()
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail="The repository request is not valid JSON.",
        ) from error

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400,
            detail="The repository request must be a JSON object.",
        )

    try:
        repository_url = normalize_github_repository_url(
            payload.get("repository_url")
        )
    except InvalidRepositoryURL as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error

    github_token = payload.get("github_token")
    if github_token is not None and not isinstance(github_token, str):
        raise HTTPException(
            status_code=400,
            detail="The GitHub token must be text.",
        )

    if github_token is not None:
        if len(github_token) > 4096 or any(
            ord(character) < 32 for character in github_token
        ):
            raise HTTPException(
                status_code=400,
                detail="The GitHub token format is invalid.",
            )

        github_token = github_token.strip() or None

    scan_workspace = tempfile.TemporaryDirectory(
        prefix="devsecops-auditor-repository-"
    )
    temporary_root = Path(scan_workspace.name)
    project_root = temporary_root / "repository"

    async def clone_scan_and_cleanup() -> AsyncIterator[str]:
        try:
            yield _sse_message(
                {
                    "type": "status",
                    "progress": 4,
                    "message": "Connecting to GitHub and cloning the repository...",
                }
            )

            await asyncio.to_thread(
                clone_github_repository,
                repository_url,
                project_root,
                github_token=github_token,
            )

            yield _sse_message(
                {
                    "type": "status",
                    "progress": 12,
                    "message": "Repository cloned. Starting security checks...",
                }
            )

            async for event in _scan_project_event_stream(project_root):
                yield event

        except RepositoryCloneError as error:
            logger.warning("GitHub repository clone failed: %s", error)
            yield _sse_message(
                {
                    "type": "error",
                    "stage": None,
                    "message": str(error),
                }
            )
        except Exception:
            logger.exception("Repository scan failed during GitHub clone")
            yield _sse_message(
                {
                    "type": "error",
                    "stage": None,
                    "message": (
                        "The repository scan could not start. "
                        "Check the server terminal for details."
                    ),
                }
            )
        finally:
            scan_workspace.cleanup()

    return StreamingResponse(
        clone_scan_and_cleanup(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )