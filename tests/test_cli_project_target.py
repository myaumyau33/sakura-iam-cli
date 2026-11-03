"""Project targets are needed for creation, independently of authentication."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import common


@pytest.mark.parametrize(
    ("command", "api_function", "extra_args"),
    [
        ("sp", "create_service_principal", []),
        ("api-key", "create_project_api_key", ["--iam-role", "resource-viewer"]),
    ],
)
@pytest.mark.parametrize(
    ("profile_project", "explicit_project", "expected_project"),
    [(None, "20", "20"), ("10", None, "10"), ("10", "20", "20"), (None, None, None)],
)
def test_creation_resolves_project_target(
    monkeypatch,
    command,
    api_function,
    extra_args,
    profile_project,
    explicit_project,
    expected_project,
):
    profile = core.Profile(
        "https://example.test/", profile_project, "sp", "kid", Path("key")
    )
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    calls = []
    monkeypatch.setattr(
        core, api_function, lambda *args: calls.append(args) or {"id": 123}
    )
    args = [command, "create", "--name", "worker", *extra_args]
    if explicit_project:
        args += ["--project-id", explicit_project]

    result = CliRunner().invoke(cli.app, args)

    if expected_project is None:
        assert result.exit_code == 1
        assert "specify --project-id" in result.stderr
        assert calls == []
    else:
        assert result.exit_code == 0, result.output
        assert len(calls) == 1
        assert calls[0][:3] == (profile, "token", expected_project)
