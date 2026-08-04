import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli
from sakura_iam_cli.core import Profile


runner = CliRunner()


def test_delete_dry_run_does_not_authenticate_or_modify_record(tmp_path: Path, monkeypatch):
    record_path = tmp_path / "sp-key-001.public.json"
    original = {
        "id": 123,
        "target_service_principal_id": "target-sp",
        "status": "uploaded",
    }
    record_path.write_text(json.dumps(original))
    monkeypatch.setattr(
        cli, "load_profile", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    result = runner.invoke(
        cli.app,
        ["sp-key", "delete", "--key-dir", str(tmp_path), "--dry-run"],
    )
    assert result.exit_code == 0
    assert "would_delete" in result.stdout
    assert json.loads(record_path.read_text()) == original


def test_delete_uses_recorded_id_and_marks_record_deleted(tmp_path: Path, monkeypatch):
    record_path = tmp_path / "sp-key-001.public.json"
    record_path.write_text(
        json.dumps(
            {
                "id": 123,
                "kid": "kid",
                "target_service_principal_id": "target-sp",
                "status": "uploaded",
            }
        )
    )
    profile = Profile("https://example.test/", "p", "sp", "auth-kid", tmp_path / "auth.pem")
    deleted = []
    monkeypatch.setattr(cli, "load_profile", lambda *_: profile)
    monkeypatch.setattr(cli, "issue_access_token", lambda _: "token")
    monkeypatch.setattr(
        cli,
        "delete_service_principal_key",
        lambda actual_profile, token, sp_id, key_id: deleted.append(
            (actual_profile, token, sp_id, key_id)
        ),
    )

    result = runner.invoke(
        cli.app, ["sp-key", "delete", "--key-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert deleted == [(profile, "token", "target-sp", "123")]
    assert json.loads(record_path.read_text())["status"] == "deleted"


def test_disable_uses_recorded_target_and_updates_status(tmp_path: Path, monkeypatch):
    record_path = tmp_path / "sp-key-001.public.json"
    record_path.write_text(json.dumps({
        "id": 123,
        "target_service_principal_id": "target-sp",
        "status": "enabled",
    }))
    profile = Profile("https://example.test/", "p", "auth-sp", "kid", tmp_path / "auth.pem")
    changed = []
    monkeypatch.setattr(cli, "load_profile", lambda *_: profile)
    monkeypatch.setattr(cli, "issue_access_token", lambda _: "token")
    monkeypatch.setattr(
        cli,
        "change_service_principal_key_state",
        lambda actual_profile, token, sp_id, key_id, action: changed.append(
            (actual_profile, token, sp_id, key_id, action)
        ) or {"id": 123, "status": "disabled"},
    )

    result = runner.invoke(
        cli.app, ["sp-key", "disable", "--key-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert changed == [(profile, "token", "target-sp", "123", "disable")]
    assert json.loads(record_path.read_text())["status"] == "disabled"


def test_service_principal_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["sp", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_api_key_create_saves_secret_with_private_permissions(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", tmp_path / "auth.pem")
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "create_project_api_key",
        lambda *_: {"id": 123, "access_token": "token", "access_token_secret": "secret"},
    )
    output = tmp_path / "credentials.json"
    result = runner.invoke(
        cli.app,
        [
            "api-key", "create", "--name", "automation", "--iam-role", "admin",
            "--output", str(output),
        ],
    )
    assert result.exit_code == 0
    assert json.loads(output.read_text())["access_token_secret"] == "secret"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_api_key_single_server_options_must_be_paired():
    result = runner.invoke(
        cli.app,
        [
            "api-key", "create", "--name", "single", "--iam-role", "viewer",
            "--server-resource-id", "server-1",
        ],
    )
    assert result.exit_code == 1
    assert "must be specified together" in result.stderr


def test_api_key_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["api-key", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_project_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["project", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_project_move_dry_run_to_root_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(
        cli.app,
        ["project", "move", "--project-id", "1", "--project-id", "2", "--to-root", "--dry-run"],
    )
    assert result.exit_code == 0
    assert '"parent_folder_id": null' in result.stdout
    assert "would_move" in result.stdout


def test_project_move_requires_exactly_one_destination():
    result = runner.invoke(cli.app, ["project", "move", "--project-id", "1"])
    assert result.exit_code == 1
    assert "exactly one" in result.stderr


def test_folder_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["folder", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_folder_move_dry_run_to_root_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(
        cli.app,
        ["folder", "move", "--folder-id", "1", "--folder-id", "2", "--to-root", "--dry-run"],
    )
    assert result.exit_code == 0
    assert '"parent_id": null' in result.stdout
    assert "would_move" in result.stdout


def test_folder_move_requires_exactly_one_destination():
    result = runner.invoke(cli.app, ["folder", "move", "--folder-id", "1"])
    assert result.exit_code == 1
    assert "exactly one" in result.stderr


def test_group_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["group", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_group_set_members_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(
        cli.app,
        ["group", "set-members", "1", "--user-id", "100", "--user-id", "200", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "would_replace_members" in result.stdout


def test_group_set_members_requires_users_or_clear():
    result = runner.invoke(cli.app, ["group", "set-members", "1"])
    assert result.exit_code == 1
    assert "--clear" in result.stderr


def test_user_create_reads_password_file_without_printing_password(tmp_path: Path, monkeypatch):
    password_file = tmp_path / "password"
    password_file.write_text("Secret123\n")
    profile = Profile("https://example.test/", "10", "sp", "kid", tmp_path / "auth.pem")
    received = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "create_user",
        lambda *args: received.append(args) or {"id": 123, "name": "User"},
    )
    result = runner.invoke(
        cli.app,
        [
            "user", "create", "--name", "User", "--code", "user-code",
            "--password-file", str(password_file),
        ],
    )
    assert result.exit_code == 0
    assert received[0][4] == "Secret123"
    assert "Secret123" not in result.stdout


def test_user_destructive_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
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
