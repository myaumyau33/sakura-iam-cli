import json
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_organization_update_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )

    result = runner.invoke(
        cli.app, ["organization", "update", "--name", "New Organization", "--dry-run"]
    )

    assert result.exit_code == 0
    assert "would_update" in result.stdout


def test_service_policy_state_dry_runs_do_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    for action in ("enable", "disable"):
        result = runner.invoke(cli.app, ["service-policy", action, "--dry-run"])
        assert result.exit_code == 0
        assert f"would_{action}" in result.stdout


def test_service_policy_update_normalizes_list_response(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "service-policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "code": "cloud-restrict-zone",
                        "name": "ゾーン制限",
                        "spec": {
                            "contents": [
                                {
                                    "allow_all": False,
                                    "deny_all": False,
                                    "values": {"allowed_values": ["is:iaas"]},
                                }
                            ]
                        },
                        "is_active": True,
                        "is_dry_run": False,
                    }
                ]
            }
        )
    )
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "update_organization_service_policy_rules",
        lambda *args: received.append(args) or {"rules": args[-1]},
    )

    result = runner.invoke(cli.app, ["service-policy", "update", str(policy_file)])

    assert result.exit_code == 0
    assert received[0][2][0]["code"] == "cloud-restrict-zone"
    assert "name" not in received[0][2][0]


def test_service_policy_update_rejects_invalid_rules(tmp_path: Path):
    policy_file = tmp_path / "service-policy.json"
    policy_file.write_text('{"rules": [{"code": "rule", "is_active": true}]}')

    result = runner.invoke(
        cli.app, ["service-policy", "update", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "is_dry_run" in result.stderr
