
import asyncio
import json

import devsecops_auditor.web.app as web_app


def test_web_sse_redacts_secrets_from_agent_findings(
    tmp_path, monkeypatch
):
    fake_secret = "FAKE_TEST_CREDENTIAL_987654"

    archive_path = tmp_path / "sample.zip"
    project_root = tmp_path / "project"

    archive_path.write_bytes(b"fake zip content")

    code_agent_findings = [
        {
            "scanner": "bandit",
            "severity": "HIGH",
            "message": f"Potential credential exposure: {fake_secret}",
            "agent_analysis": {
                "risk_explanation": (
                    f"The detected credential is {fake_secret}"
                )
            },
        }
    ]

    monkeypatch.setattr(
        web_app,
        "safe_extract_zip",
        lambda archive, destination: destination.mkdir(
            parents=True,
            exist_ok=True,
        ),
    )

    monkeypatch.setattr(
        web_app,
        "scan_python",
        lambda folder: [],
    )

    monkeypatch.setattr(
        web_app,
        "analyze_bandit_findings",
        lambda findings: code_agent_findings,
    )

    monkeypatch.setattr(
        web_app,
        "scan_secrets_with_values",
        lambda folder: ([], [fake_secret]),
    )

    monkeypatch.setattr(
        web_app,
        "analyze_secret_findings",
        lambda findings: [],
    )

    async def collect_events():
        events = []

        async for event in web_app._scan_event_stream(
            archive_path,
            project_root,
        ):
            payload = json.loads(
                event.removeprefix("data: ").strip()
            )
            events.append(payload)

        return events

    events = asyncio.run(collect_events())

    completion_events = [
        event
        for event in events
        if event.get("type") == "complete"
    ]

    assert len(completion_events) == 1

    completion = completion_events[0]

    serialized_findings = json.dumps(completion["findings"])

    assert fake_secret not in serialized_findings
    assert "[REDACTED]" in serialized_findings

    assert completion["finding_count"] == 1
    assert completion["findings"][0]["scanner"] == "bandit"
    assert completion["findings"][0]["severity"] == "HIGH"

    assert (
        "[REDACTED]"
        in completion["findings"][0]["agent_analysis"]["risk_explanation"]
    )
