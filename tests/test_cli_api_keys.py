import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_api_key_create_saves_secret_with_private_permissions(
    tmp_path: Path, monkeypatch
):
    profile = Profile("https://example.test/", "10", "sp", "kid", tmp_path / "auth.pem")
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "create_project_api_key",
        lambda *_: {
            "id": 123,
            "access_token": "token",
            "access_token_secret": "secret",
        },
    )
    output = tmp_path / "credentials.json"
    result = runner.invoke(
        cli.app,
        [
            "api-key",
            "create",
            "--name",
            "automation",
            "--iam-role",
            "admin",
            "--output",
            str(output),
        ],
    )
    assert result.exit_code == 0
    assert json.loads(output.read_text())["access_token_secret"] == "secret"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_api_key_single_server_options_must_be_paired():
    result = runner.invoke(
        cli.app,
        [
            "api-key",
            "create",
            "--name",
            "single",
            "--iam-role",
            "viewer",
            "--server-resource-id",
            "server-1",
        ],
    )
    assert result.exit_code == 1
    assert "must be specified together" in result.stderr


def test_api_key_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(cli.app, ["api-key", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_api_key_auth_status_reads_created_credentials(tmp_path: Path, monkeypatch):
    credentials = tmp_path / "api-key.json"
    credentials.write_text(
        json.dumps({"access_token": "access", "access_token_secret": "secret"})
    )
    credentials.chmod(0o600)
    calls = []
    monkeypatch.setattr(
        core,
        "get_cloud_auth_status",
        lambda *args, **kwargs: calls.append((args, kwargs))
        or {"is_ok": True, "Account": {"ID": "123"}},
    )

    result = runner.invoke(
        cli.app, ["api-key", "auth-status", str(credentials), "--zone", "tk1a"]
    )

    assert result.exit_code == 0
    assert calls == [(("access", "secret"), {"zone": "tk1a"})]
    assert json.loads(result.stdout)["Account"]["ID"] == "123"


def test_api_key_auth_status_rejects_open_credentials_file(tmp_path: Path, monkeypatch):
    credentials = tmp_path / "api-key.json"
    credentials.write_text(
        json.dumps({"access_token": "access", "access_token_secret": "secret"})
    )
    credentials.chmod(0o644)
    monkeypatch.setattr(
        core,
        "get_cloud_auth_status",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("requested")),
    )

    result = runner.invoke(cli.app, ["api-key", "auth-status", str(credentials)])

    assert result.exit_code == 1
    assert "permissions are too open" in result.stderr
