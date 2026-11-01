import base64
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from devsecops_auditor.web import repository


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (
            "https://github.com/example/project",
            "https://github.com/example/project.git",
        ),
        (
            "https://github.com/example/project.git",
            "https://github.com/example/project.git",
        ),
        (
            "https://github.com/example/project/",
            "https://github.com/example/project.git",
        ),
    ],
)
def test_normalizes_github_repository_url(url: str, expected: str) -> None:
    assert repository.normalize_github_repository_url(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://github.com/example/project",
        "https://notgithub.com/example/project",
        "https://github.com/example/project/tree/main",
        "https://github.com/example/project?tab=readme",
        "https://user:password@github.com/example/project",
        "https://github.com:443/example/project",
        "https://github.com/example/../project",
    ],
)
def test_rejects_unsupported_repository_urls(url: str) -> None:
    with pytest.raises(repository.InvalidRepositoryURL):
        repository.normalize_github_repository_url(url)


def test_clone_uses_git_arguments_and_keeps_token_out_of_url_and_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "cloned-project"
    token = "example-test-token"
    captured: dict[str, object] = {}

    def fake_run(
        command: list[str],
        **kwargs: object,
    ) -> SimpleNamespace:
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        destination.mkdir()
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(repository.subprocess, "run", fake_run)

    result = repository.clone_github_repository(
        "https://github.com/example/private-project",
        destination,
        github_token=token,
    )

    command = captured["command"]
    environment = captured["environment"]

    assert result == destination.resolve()
    assert destination.is_dir()
    assert command[:6] == [
        "git",
        "clone",
        "--depth",
        "1",
        "--",
        "https://github.com/example/private-project.git",
    ]
    assert token not in " ".join(command)
    assert environment["GIT_TERMINAL_PROMPT"] == "0"
    assert environment["GIT_CONFIG_KEY_0"] == (
        "http.https://github.com/.extraheader"
    )

    encoded_header = environment["GIT_CONFIG_VALUE_0"].split("basic ", 1)[1]
    decoded_credentials = base64.b64decode(encoded_header).decode("utf-8")
    assert decoded_credentials == f"x-access-token:{token}"


def test_clone_rejects_existing_destination(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "already-exists"
    destination.mkdir()

    def unexpected_run(*args: object, **kwargs: object) -> None:
        pytest.fail("Git should not run when the destination already exists")

    monkeypatch.setattr(repository.subprocess, "run", unexpected_run)

    with pytest.raises(ValueError, match="must not already exist"):
        repository.clone_github_repository(
            "https://github.com/example/project",
            destination,
        )


def test_clone_rejects_missing_destination_parent(tmp_path: Path) -> None:
    destination = tmp_path / "missing-parent" / "project"

    with pytest.raises(ValueError, match="folder does not exist"):
        repository.clone_github_repository(
            "https://github.com/example/project",
            destination,
        )


def test_clone_reports_git_failure_without_echoing_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "cloned-project"
    token = "example-test-token"

    def failed_run(*args: object, **kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            returncode=128,
            stdout="",
            stderr=f"failure details containing {token}",
        )

    monkeypatch.setattr(repository.subprocess, "run", failed_run)

    with pytest.raises(repository.RepositoryCloneError) as error:
        repository.clone_github_repository(
            "https://github.com/example/private-project",
            destination,
            github_token=token,
        )

    assert token not in str(error.value)


def test_clone_reports_when_git_is_not_installed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_git(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError

    monkeypatch.setattr(repository.subprocess, "run", missing_git)

    with pytest.raises(repository.RepositoryCloneError, match="Git was not found"):
        repository.clone_github_repository(
            "https://github.com/example/project",
            tmp_path / "cloned-project",
        )


def test_clone_stops_after_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out(*args: object, **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(cmd="git clone", timeout=180)

    monkeypatch.setattr(repository.subprocess, "run", timed_out)

    with pytest.raises(repository.RepositoryCloneError, match="took too long"):
        repository.clone_github_repository(
            "https://github.com/example/project",
            tmp_path / "cloned-project",
        )


def test_clone_rejects_token_with_control_characters(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_run(*args: object, **kwargs: object) -> None:
        pytest.fail("Git should not run with an invalid token")

    monkeypatch.setattr(repository.subprocess, "run", unexpected_run)

    with pytest.raises(ValueError, match="token format is invalid"):
        repository.clone_github_repository(
            "https://github.com/example/private-project",
            tmp_path / "cloned-project",
            github_token="bad\ntoken",
        )