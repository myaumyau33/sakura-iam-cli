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


def test_provisioning_create_saves_secret_with_restricted_permissions(
    tmp_path: Path, monkeypatch
):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "create_scim_configuration",
        lambda *args: {
            "id": "config-1",
            "name": args[-1],
            "base_url": "https://example.test/scim/config-1/v2/",
            "secret_token": "secret",
        },
    )
    output = tmp_path / "provisioning.json"

    result = runner.invoke(
        cli.app,
        [
            "provisioning",
            "create",
            "--name",
            "Microsoft Entra ID",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(output.read_text())["secret_token"] == "secret"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "secret" not in result.stdout


def test_provisioning_commands(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    calls = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "list_scim_configurations",
        lambda *args, **kwargs: calls.append(("list", args, kwargs)) or {"items": []},
    )
    monkeypatch.setattr(
        core,
        "read_scim_configuration",
        lambda *args: calls.append(("get", args)) or {"id": args[-1]},
    )
    monkeypatch.setattr(
        core,
        "update_scim_configuration",
        lambda *args: calls.append(("update", args)) or {"id": args[-2]},
    )

    listed = runner.invoke(
        cli.app, ["provisioning", "list", "--page", "2", "--per-page", "25"]
    )
    fetched = runner.invoke(cli.app, ["provisioning", "get", "config-1"])
    updated = runner.invoke(
        cli.app,
        ["provisioning", "update", "config-1", "--name", "Renamed"],
    )

    assert listed.exit_code == fetched.exit_code == updated.exit_code == 0
    assert calls[0] == ("list", (profile, "token"), {"page": 2, "per_page": 25})
    assert calls[1] == ("get", (profile, "token", "config-1"))
    assert calls[2] == ("update", (profile, "token", "config-1", "Renamed"))


def test_provisioning_destructive_dry_runs_do_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )

    deleted = runner.invoke(
        cli.app, ["provisioning", "delete", "config-1", "--dry-run"]
    )
    regenerated = runner.invoke(
        cli.app,
        ["provisioning", "regenerate-token", "config-1", "--dry-run"],
    )

    assert deleted.exit_code == regenerated.exit_code == 0
    assert "would_delete" in deleted.stdout
    assert "would_regenerate_token" in regenerated.stdout


def test_provisioning_regenerate_token_saves_secret(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "regenerate_scim_configuration_token",
        lambda *args: {"secret_token": "new-secret"},
    )
    output = tmp_path / "new-token.json"

    result = runner.invoke(
        cli.app,
        [
            "provisioning",
            "regenerate-token",
            "config-1",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(output.read_text()) == {"secret_token": "new-secret"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "new-secret" not in result.stdout
