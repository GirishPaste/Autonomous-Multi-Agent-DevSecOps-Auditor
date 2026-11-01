from devsecops_auditor.agents import ai_report_agent as agent


def _finding() -> dict:
    return {
        "scanner": "bandit",
        "rule_id": "B105",
        "severity": "low",
        "file": "probe.py",
        "line": 1,
        "message": "Potential hardcoded password or secret detected.",
        "recommendation": "Remove and rotate the credential.",
        "evidence": 'PASSWORD = "SYNTHETIC_SECRET_VALUE_7F1A9C"',
    }


def _ai_result() -> dict:
    return {
        "summary": "One possible credential issue needs review.",
        "findings": [
            {
                "index": 0,
                "problem": "Possible hardcoded password.",
                "impact": "If real, another person may use it.",
                "solution": "Remove it and rotate the credential.",
            }
        ],
    }


def test_redact_sensitive_text_hides_password_value() -> None:
    marker = "SYNTHETIC_SECRET_VALUE_7F1A9C"

    result = agent.redact_sensitive_text(f'PASSWORD = "{marker}"')

    assert marker not in result
    assert "[REDACTED]" in result


def test_report_uses_local_explanation_without_openrouter_key(
    monkeypatch,
) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setattr(agent, "_read_dotenv_openrouter_key", lambda: "")

    result = agent.build_human_report([_finding()])

    assert result["provider"] == "local"
    assert result["findings"][0]["file"] == "probe.py"
    assert result["findings"][0]["line"] == 1
    assert result["findings"][0]["problem"]


def test_report_calls_only_free_openrouter_route(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    captured = {}

    def fake_call(findings, *, api_key):
        captured["findings"] = findings
        captured["api_key"] = api_key
        return _ai_result()

    monkeypatch.setattr(agent, "_call_openrouter", fake_call)

    result = agent.build_human_report([_finding()])

    assert captured["api_key"] == "test-key"
    assert "file" not in captured["findings"][0]
    assert "line" not in captured["findings"][0]
    assert "evidence" not in captured["findings"][0]
    assert result["provider"] == "openrouter"
    assert result["model"] == "openrouter/free"
    assert result["findings"][0]["file"] == "probe.py"


def test_openrouter_error_uses_local_fallback(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")

    def fail_call(*args, **kwargs):
        raise RuntimeError("simulated API failure")

    monkeypatch.setattr(agent, "_call_openrouter", fail_call)

    result = agent.build_human_report([_finding()])

    assert result["provider"] == "local"
    assert result["findings"][0]["problem"]


def test_model_response_cannot_replace_local_file_or_line(monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "test-key")
    result_from_api = _ai_result()
    result_from_api["findings"][0]["file"] = "attacker-controlled.py"
    result_from_api["findings"][0]["line"] = 999

    monkeypatch.setattr(
        agent, "_call_openrouter", lambda *args, **kwargs: result_from_api
    )

    result = agent.build_human_report([_finding()])

    assert result["findings"][0]["file"] == "probe.py"
    assert result["findings"][0]["line"] == 1