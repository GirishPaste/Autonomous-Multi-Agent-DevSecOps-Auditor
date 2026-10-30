
"""Utilities for redacting sensitive information from scan findings."""

from collections.abc import Iterable
import re
from typing import Any

REDACTED = "[REDACTED]"

SENSITIVE_KEYS = {
    "secret",
    "secretvalue",
    "rawsecret",
    "password",
    "passwd",
    "token",
    "apikey",
    "accesskey",
    "clientsecret",
    "privatekey",
    "authorization",
    "credential",
    "credentials",
}


def _normalize_key(key: Any) -> str:
    """Normalize a dictionary key for sensitive-field matching."""
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _clean_secret_values(
    secret_values: Iterable[str] | None,
) -> list[str]:
    """Return unique, non-empty secret values, longest first."""
    if secret_values is None:
        return []

    cleaned = {
        value
        for value in secret_values
        if isinstance(value, str) and value
    }

    return sorted(cleaned, key=len, reverse=True)


def redact_text(
    text: str,
    secret_values: Iterable[str] | None = None,
) -> str:
    """Replace detected secret values in a string."""
    secrets = _clean_secret_values(secret_values)

    for secret in secrets:
        text = text.replace(secret, REDACTED)

    return text


def _redact_value(
    value: Any,
    secret_values: list[str],
    field_name: str | None = None,
) -> Any:
    """Recursively redact sensitive values."""
    if field_name and _normalize_key(field_name) in SENSITIVE_KEYS:
        return REDACTED

    if isinstance(value, dict):
        return {
            key: _redact_value(item, secret_values, str(key))
            for key, item in value.items()
        }

    if isinstance(value, list):
        return [
            _redact_value(item, secret_values)
            for item in value
        ]

    if isinstance(value, tuple):
        return tuple(
            _redact_value(item, secret_values)
            for item in value
        )

    if isinstance(value, str):
        return redact_text(value, secret_values)

    return value


def redact_sensitive_data(
    value: Any,
    secret_values: Iterable[str] | None = None,
) -> Any:
    """Redact sensitive fields and detected secret values recursively."""
    secrets = _clean_secret_values(secret_values)
    return _redact_value(value, secrets)
