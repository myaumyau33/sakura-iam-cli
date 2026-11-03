from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_group_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(cli.app, ["group", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_group_set_members_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(
        cli.app,
        [
            "group",
            "set-members",
            "1",
            "--user-id",
            "100",
            "--user-id",
            "200",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert "would_replace_members" in result.stdout


def test_group_set_members_requires_users_or_clear():
    result = runner.invoke(cli.app, ["group", "set-members", "1"])
    assert result.exit_code == 1
    assert "--clear" in result.stderr


def test_user_create_reads_password_file_without_printing_password(
    tmp_path: Path, monkeypatch
):
    password_file = tmp_path / "password"
    password_file.write_text("Secret123\n")
    profile = Profile("https://example.test/", "10", "sp", "kid", tmp_path / "auth.pem")
    received = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "create_user",
        lambda *args: received.append(args) or {"id": 123, "name": "User"},
    )
    result = runner.invoke(
        cli.app,
        [
            "user",
            "create",
            "--name",
            "User",
            "--code",
            "user-code",
            "--password-file",
            str(password_file),
        ],
    )
    assert result.exit_code == 0
    assert received[0][4] == "Secret123"
    assert "Secret123" not in result.stdout


def test_user_destructive_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    for arguments in (
        ["user", "delete", "1", "--dry-run"],
        ["user", "deactivate-otp", "1", "--dry-run"],
        ["user", "clear-trusted-devices", "1", "--dry-run"],
        ["user", "delete-security-key", "1", "2", "--dry-run"],
    ):
        result = runner.invoke(cli.app, arguments)
        assert result.exit_code == 0
        assert "would_" in result.stdout
