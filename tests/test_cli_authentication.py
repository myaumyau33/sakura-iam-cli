import json
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_password_policy_update_validates_and_dry_runs(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "password-policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "min_length": 12,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_symbols": False,
            }
        )
    )
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )

    result = runner.invoke(
        cli.app, ["auth", "update-password-policy", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "would_update" in result.stdout


def test_password_policy_rejects_out_of_range_length(tmp_path: Path):
    policy_file = tmp_path / "password-policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "min_length": 7,
                "require_uppercase": False,
                "require_lowercase": False,
                "require_symbols": False,
            }
        )
    )

    result = runner.invoke(
        cli.app, ["auth", "update-password-policy", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "8 through 64" in result.stderr


def test_auth_conditions_update_validates_and_updates(tmp_path: Path, monkeypatch):
    conditions_file = tmp_path / "conditions.json"
    conditions = {
        "ip_restriction": {
            "mode": "allow_list",
            "source_network": ["192.0.2.0/24"],
        },
        "require_two_factor_auth": {"enabled": True},
        "datetime_restriction": {
            "after": "2026-08-01T00:00:00+09:00",
            "before": None,
        },
    }
    conditions_file.write_text(json.dumps(conditions))
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "update_auth_conditions",
        lambda *args: received.append(args) or args[-1],
    )

    result = runner.invoke(cli.app, ["auth", "update-conditions", str(conditions_file)])

    assert result.exit_code == 0
    assert received == [(profile, "token", conditions)]


def test_auth_conditions_reject_invalid_network(tmp_path: Path):
    conditions_file = tmp_path / "conditions.json"
    conditions_file.write_text(
        json.dumps(
            {
                "ip_restriction": {
                    "mode": "allow_list",
                    "source_network": ["not-a-cidr"],
                },
                "require_two_factor_auth": {"enabled": False},
                "datetime_restriction": {"after": None, "before": None},
            }
        )
    )

    result = runner.invoke(
        cli.app, ["auth", "update-conditions", str(conditions_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "IPv4 CIDR" in result.stderr
