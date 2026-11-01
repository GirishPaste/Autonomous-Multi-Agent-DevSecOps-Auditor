"""Validate and clone GitHub repositories for local scanning."""

from __future__ import annotations

import base64
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


_COMPONENT_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_CLONE_TIMEOUT_SECONDS = 180


class InvalidRepositoryURL(ValueError):
    """The supplied URL is not a supported GitHub repository URL."""


class RepositoryCloneError(RuntimeError):
    """Git could not clone the requested repository."""


def normalize_github_repository_url(repository_url: str) -> str:
    """Validate a GitHub repository URL and return its canonical clone URL."""
    if not isinstance(repository_url, str):
        raise InvalidRepositoryURL("Enter a GitHub repository URL.")

    value = repository_url.strip()
    if not value or len(value) > 2048:
        raise InvalidRepositoryURL("Enter a valid GitHub repository URL.")

    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise InvalidRepositoryURL("Enter a valid GitHub repository URL.") from error

    if (
        parsed.scheme.casefold() != "https"
        or (parsed.hostname or "").casefold() != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise InvalidRepositoryURL(
            "Use an HTTPS URL from github.com without credentials or extra paths."
        )

    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise InvalidRepositoryURL(
            "Use a repository URL in the form https://github.com/owner/repository."
        )

    owner, repository = parts

    if repository.casefold().endswith(".git"):
        repository = repository[:-4]

    if (
        owner in {".", ".."}
        or repository in {".", ".."}
        or not _COMPONENT_PATTERN.fullmatch(owner)
        or not _COMPONENT_PATTERN.fullmatch(repository)
    ):
        raise InvalidRepositoryURL("The GitHub owner or repository name is invalid.")

    return f"https://github.com/{owner}/{repository}.git"


def _git_environment(github_token: str | None) -> dict[str, str]:
    """Build a Git environment without putting a token in the clone URL."""
    environment = os.environ.copy()
    environment["GIT_TERMINAL_PROMPT"] = "0"

    if github_token is None or not github_token.strip():
        return environment

    token = github_token.strip()
    if len(token) > 4096 or any(ord(character) < 32 for character in token):
        raise ValueError("The GitHub token format is invalid.")

    encoded_credentials = base64.b64encode(
        f"x-access-token:{token}".encode("utf-8")
    ).decode("ascii")

    # Git reads this temporary configuration from the child process environment.
    # The token is not added to the URL, command arguments, or a config file.
    environment["GIT_CONFIG_COUNT"] = "1"
    environment["GIT_CONFIG_KEY_0"] = "http.https://github.com/.extraheader"
    environment["GIT_CONFIG_VALUE_0"] = (
        f"AUTHORIZATION: basic {encoded_credentials}"
    )

    return environment


def clone_github_repository(
    repository_url: str,
    destination: str | Path,
    *,
    github_token: str | None = None,
) -> Path:
    """Clone one GitHub repository into a new destination directory."""
    clone_url = normalize_github_repository_url(repository_url)
    target = Path(destination).expanduser().resolve()

    if target.exists():
        raise ValueError("The repository destination must not already exist.")

    if not target.parent.is_dir():
        raise ValueError("The repository destination folder does not exist.")

    environment = _git_environment(github_token)

    try:
        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--",
                clone_url,
                str(target),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=_CLONE_TIMEOUT_SECONDS,
            env=environment,
        )
    except FileNotFoundError as error:
        raise RepositoryCloneError(
            "Git was not found. Install Git and try again."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise RepositoryCloneError(
            "The repository download took too long and was stopped."
        ) from error
    except OSError as error:
        raise RepositoryCloneError(
            "Git could not start the repository download."
        ) from error

    if result.returncode != 0 or not target.is_dir():
        raise RepositoryCloneError(
            "Git could not clone the repository. Check the URL and your access."
        )

    return target