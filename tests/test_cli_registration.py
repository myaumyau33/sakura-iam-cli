"""Check that splitting command modules preserves CLI registration and help."""

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from sakura_iam_cli.cli import app

EXPECTED_COMMANDS = {
    "config": ["add", "edit", "init", "list", "use"],
    "api-key": ["auth-status", "create", "delete", "get", "list", "raw-url", "update"],
    "auth": [
        "conditions",
        "context",
        "password-policy",
        "update-conditions",
        "update-password-policy",
    ],
    "folder": ["create", "delete", "get", "list", "move", "update"],
    "group": ["create", "delete", "get", "list", "members", "set-members", "update"],
    "iam-policy": ["add", "delete", "get", "update"],
    "iam-role": ["get", "list"],
    "id-policy": ["get", "update"],
    "id-role": ["get", "list"],
    "organization": ["get", "update"],
    "project": ["create", "delete", "get", "list", "move", "update"],
    "provisioning": ["create", "delete", "get", "list", "regenerate-token", "update"],
    "raw-url": [],
    "resource": ["ls", "mkdir", "mv", "tree"],
    "service-policy": ["disable", "enable", "list", "status", "templates", "update"],
    "sp": ["check-permissions", "create", "delete", "get", "list", "token", "update"],
    "sp-key": ["create", "delete", "disable", "enable", "list", "upload-key"],
    "user": [
        "clear-trusted-devices",
        "create",
        "deactivate-otp",
        "delete",
        "delete-security-key",
        "delete-trusted-device",
        "get",
        "get-security-key",
        "list",
        "register-email",
        "security-keys",
        "trusted-devices",
        "unregister-email",
        "update",
    ],
}


def test_registered_commands():
    command = get_command(app)
    assert set(command.commands) == set(EXPECTED_COMMANDS)
    for name, children in EXPECTED_COMMANDS.items():
        actual = command.commands[name]
        assert sorted(getattr(actual, "commands", {})) == children


HELP_PATHS = (
    [()]
    + [(group,) for group in EXPECTED_COMMANDS]
    + [
        (group, child)
        for group, children in EXPECTED_COMMANDS.items()
        for child in children
    ]
)


@pytest.mark.parametrize("path", HELP_PATHS, ids=lambda path: " ".join(path) or "root")
def test_command_help_loads_without_authentication(path, monkeypatch):
    from sakura_iam_cli.commands import common

    def unexpected_authentication(*args):
        pytest.fail("help must not authenticate")

    monkeypatch.setattr(common, "authenticated", unexpected_authentication)
    result = CliRunner().invoke(app, [*path, "--help"])
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.stdout
