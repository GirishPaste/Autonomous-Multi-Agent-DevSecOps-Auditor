import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from devsecops_auditor.web import app as web_app
from devsecops_auditor.web.repository import RepositoryCloneError


def _make_request(
    body: bytes,
    *,
    content_type: str = "application/json",
    content_length: int | None = None,
) -> Request:
    headers = [(b"content-type", content_type.encode("ascii"))]

    if content_length is not None:
        headers.append(
            (b"content-length", str(content_length).encode("ascii"))
        )

    async def receive() -> dict[str, Any]:
        return {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }

    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/api/scan/repository",
        "headers": headers,
        "query_string": b"",
    }
    return Request(scope, receive)


def _json_request(
    payload: Any,
    *,
    content_type: str = "application/json",
    content_length: int | None = None,
) -> Request:
    body = json.dumps(payload).encode("utf-8")
    return _make_request(
        body,
        content_type=content_type,
        content_length=content_length,
    )


def _read_stream(response: Any) -> str:
    async def collect() -> str:
        chunks: list[str] = []

        async for chunk in response.body_iterator:
            chunks.append(
                chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk
            )

        return "".join(chunks)

    return asyncio.run(collect())


def _parse_events(stream: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    for block in stream.strip().split("\n\n"):
        if block.startswith("data:"):
            events.append(json.loads(block[len("data:"):].strip()))

    return events


def test_repository_endpoint_clones_scans_and_cleans_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    bandit_findings = [
        {
            "scanner": "bandit",
            "rule_id": "B603",
            "severity": "low",
            "file": "app.py",
            "line": 4,
            "message": "subprocess call detected",
            "recommendation": "Review command arguments.",
            "evidence": "Source excerpt omitted.",
        }
    ]

    def fake_clone(
        repository_url: str,
        destination: str | Path,
        *,
        github_token: str | None = None,
    ) -> Path:
        destination_path = Path(destination)
        destination_path.mkdir()
        captured["url"] = repository_url
        captured["token"] = github_token
        captured["destination"] = destination_path
        return destination_path

    monkeypatch.setattr(
        web_app,
        "clone_github_repository",
        fake_clone,
    )
    monkeypatch.setattr(
        web_app,
        "scan_python",
        lambda project_root: bandit_findings,
    )
    monkeypatch.setattr(
        web_app,
        "analyze_bandit_findings",
        lambda findings: findings,
    )
    monkeypatch.setattr(
        web_app,
        "scan_secrets",
        lambda project_root: [],
    )
    monkeypatch.setattr(
        web_app,
        "analyze_secret_findings",
        lambda findings: [],
    )

    request = _json_request(
        {
            "repository_url": "https://github.com/example/project",
            "github_token": "fake-test-token",
        }
    )
    response = asyncio.run(web_app.scan_github_repository(request))

    assert response.media_type == "text/event-stream"

    stream = _read_stream(response)
    events = _parse_events(stream)
    complete_event = next(event for event in events if event["type"] == "complete")

    assert captured["url"] == "https://github.com/example/project.git"
    assert captured["token"] == "fake-test-token"
    assert complete_event["finding_count"] == 1
    assert complete_event["findings"] == bandit_findings
    assert "fake-test-token" not in stream
    assert not captured["destination"].exists()


def test_repository_endpoint_rejects_invalid_url() -> None:
    request = _json_request(
        {"repository_url": "https://example.com/owner/project"}
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(web_app.scan_github_repository(request))

    assert error.value.status_code == 400


def test_repository_endpoint_rejects_non_json_request() -> None:
    request = _make_request(
        b"https://github.com/example/project",
        content_type="text/plain",
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(web_app.scan_github_repository(request))

    assert error.value.status_code == 415


def test_repository_endpoint_rejects_oversized_request() -> None:
    request = _json_request(
        {"repository_url": "https://github.com/example/project"},
        content_length=web_app.MAX_REPOSITORY_REQUEST_BYTES + 1,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(web_app.scan_github_repository(request))

    assert error.value.status_code == 413


def test_repository_clone_error_is_returned_as_stream_event(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_clone(
        repository_url: str,
        destination: str | Path,
        *,
        github_token: str | None = None,
    ) -> Path:
        raise RepositoryCloneError(
            "Git could not clone the repository. Check the URL and your access."
        )

    monkeypatch.setattr(
        web_app,
        "clone_github_repository",
        failed_clone,
    )

    request = _json_request(
        {"repository_url": "https://github.com/example/project"}
    )
    response = asyncio.run(web_app.scan_github_repository(request))

    events = _parse_events(_read_stream(response))
    error_event = next(event for event in events if event["type"] == "error")

    assert "could not clone" in error_event["message"].lower()