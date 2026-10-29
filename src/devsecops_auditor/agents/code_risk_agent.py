"""Explain Bandit findings and suggest safe next steps."""

from typing import Any


_RULE_GUIDANCE: dict[str, tuple[str, str]] = {
    "B404": (
        (
            "The subprocess module can launch external commands. Importing it "
            "alone does not prove a vulnerability; risk depends on how commands "
            "are built and whether untrusted input can affect them."
        ),
        (
            "Keep the executable fixed, pass arguments as a list, keep "
            "shell=False, and validate values that come from scanned files."
        ),
    ),
    "B603": (
        (
            "Bandit found a subprocess call. With shell=False, arguments are "
            "not interpreted by a shell, but untrusted values could still "
            "select unsafe commands or options."
        ),
        (
            "Use a fixed executable and an argument list, keep shell=False, "
            "and validate or allowlist any untrusted values."
        ),
    ),
    "B602": (
        (
            "Using a subprocess call with shell=True makes shell metacharacters "
            "active. Untrusted input in the command can create a command "
            "injection risk."
        ),
        (
            "Avoid shell=True. Pass the executable and arguments as a list, "
            "validate inputs, and use an allowlist when commands must vary."
        ),
    ),
}


def analyze_bandit_findings(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Add explanations to Bandit findings while preserving the input data."""
    analyzed: list[dict[str, Any]] = []

    for finding in findings:
        result = dict(finding)

        if str(result.get("scanner", "")).casefold() != "bandit":
            analyzed.append(result)
            continue

        raw_rule_id = result.get("rule_id")
        rule_id = str(raw_rule_id).strip().upper() if raw_rule_id else "unknown"

        message = str(result.get("message") or "").strip()
        if not message:
            message = "No Bandit message was provided"
        else:
            message = message.rstrip(".!?")

        file_name = str(result.get("file") or "unknown file")
        line_number = result.get("line")
        recommendation = result.get("recommendation")

        guidance = _RULE_GUIDANCE.get(rule_id)

        if guidance:
            risk_explanation, possible_fix = guidance
        else:
            location = (
                f"{file_name}, line {line_number}"
                if line_number
                else file_name
            )
            risk_explanation = (
                f"Bandit rule {rule_id} flagged this finding: {message}. "
                f"Review the code at {location} to confirm its impact."
            )
            possible_fix = (
                "Review the linked Bandit rule guidance and correct the "
                "underlying pattern. Suppress the finding only if you verify "
                "it is a false positive and document why."
            )

        result["agent_analysis"] = {
            "agent": "code-risk",
            "risk_explanation": risk_explanation,
            "possible_fix": possible_fix,
            "reference": recommendation,
        }
        analyzed.append(result)

    return analyzed