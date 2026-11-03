import json

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import common

runner = CliRunner()


def test_sp_permission_report_defaults_to_authenticated_sp(permission_api):
    result = runner.invoke(cli.app, ["sp", "check-permissions", "--json"])
    assert result.exit_code == 0, result.output
    report = json.loads(result.stdout)
    assert report["service_principal_id"] == "100"
    assert report["status"] == "complete"
    assert report["id"]["checks"] == [
        {
            "role": "identity-admin",
            "status": "present",
            "sources": ["organization-id-policy"],
        }
    ]
    assert "token" not in result.stdout


@pytest.mark.parametrize(
    "args, code, status",
    [
        (["--iam-role", "owner", "--id-role", "identity-admin"], 0, "present"),
        (["--iam-role", "not-found"], 1, "missing"),
    ],
)
def test_sp_permission_requirements_set_exit_status(permission_api, args, code, status):
    result = runner.invoke(cli.app, ["sp", "check-permissions", "--json", *args])
    assert result.exit_code == code, result.output
    assert json.loads(result.stdout)["status"] == status


def test_sp_permission_unreadable_id_policy_is_unknown(permission_api):
    permission_api[1]["organization-id-policy"] = core.CliError("HTTP 403: denied")
    result = runner.invoke(
        cli.app, ["sp", "check-permissions", "--id-role", "identity-admin", "--json"]
    )
    assert result.exit_code == 2
    report = json.loads(result.stdout)
    assert report["status"] == "unknown"
    assert report["id"]["checks"][0]["status"] == "unknown"
    assert report["iam"]["complete"] is True


def test_sp_permission_table_reports_inheritance_and_id_roles(permission_api):
    result = runner.invoke(
        cli.app,
        [
            "sp",
            "check-permissions",
            "--iam-role",
            "owner",
            "--id-role",
            "identity-admin",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "SP: 100" in result.stdout
    assert (
        "確認するIAMポリシー: プロジェクト 10 → フォルダ 2 → フォルダ 1 → 組織"
        in result.stdout
    )
    assert "上位階層" not in result.stdout
    assert "identity-admin" in result.stdout
    assert "owner" in result.stdout
    assert "organization-id-policy" in result.stdout
    assert "結果:" not in result.stdout
    assert "保証しません" not in result.stdout


def test_sp_permission_table_explains_unknown_not_missing(permission_api):
    permission_api[1]["organization-id-policy"] = core.CliError("HTTP 403: denied")
    result = runner.invoke(
        cli.app, ["sp", "check-permissions", "--id-role", "identity-admin"]
    )
    assert result.exit_code == 2
    assert "判定不能" in result.stdout
    assert "未割当" not in result.stdout
    assert "HTTP 403" in result.stdout
    assert "結果:" not in result.stdout
    assert "保証しません" not in result.stdout


def test_sp_permission_checks_another_sp_using_selected_profile(
    permission_api, monkeypatch
):
    seen = []
    profile = permission_api[0]

    def authenticate(ctx):
        seen.append(ctx.obj)
        return profile, "token"

    monkeypatch.setattr(common, "authenticated", authenticate)
    result = runner.invoke(
        cli.app,
        [
            "--settings",
            "admin.json",
            "--profile",
            "admin",
            "sp",
            "check-permissions",
            "200",
            "--iam-role",
            "owner",
            "--project-id",
            "20",
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen[0].profile_name == "admin"
    assert str(seen[0].settings) == "admin.json"
    report = json.loads(result.stdout)
    assert report["service_principal_id"] == "200"
    assert report["target"] == {"type": "project", "id": "20"}


def test_sp_permission_rejects_conflicting_targets_before_authentication(monkeypatch):
    def authenticate(*args):
        pytest.fail("must not authenticate with conflicting targets")

    monkeypatch.setattr(common, "authenticated", authenticate)
    result = runner.invoke(
        cli.app, ["sp", "check-permissions", "--project-id", "10", "--organization"]
    )
    assert result.exit_code == 1
    assert "at most one" in result.stderr


def test_sp_permission_catches_authentication_errors(monkeypatch):
    def authenticate(*args):
        raise core.CliError("authentication failed")

    monkeypatch.setattr(common, "authenticated", authenticate)
    result = runner.invoke(cli.app, ["sp", "check-permissions"])
    assert result.exit_code == 1
    assert "authentication failed" in result.stderr
