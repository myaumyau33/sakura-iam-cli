import json
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
