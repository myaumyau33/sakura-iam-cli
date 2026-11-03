import json
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_id_role_commands(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    calls = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "list_id_roles",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {"items": []},
    )
    monkeypatch.setattr(
        core,
        "read_id_role",
        lambda *args: calls.append((args, {})) or {"id": args[-1]},
    )

    listed = runner.invoke(
        cli.app, ["id-role", "list", "--page", "2", "--per-page", "25"]
    )
    fetched = runner.invoke(cli.app, ["id-role", "get", "identity-admin"])

    assert listed.exit_code == 0
    assert fetched.exit_code == 0
    assert calls[0] == ((profile, "token"), {"page": 2, "per_page": 25})
    assert calls[1] == ((profile, "token", "identity-admin"), {})


def test_id_policy_update_validates_and_updates(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "bindings": [
                    {
                        "role": {"type": "preset", "id": "identity-admin"},
                        "principals": [{"type": "user", "id": 100}],
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
        "update_organization_id_policy",
        lambda *args: received.append(args) or {"bindings": args[-1]},
    )

    result = runner.invoke(cli.app, ["id-policy", "update", str(policy_file)])

    assert result.exit_code == 0
    assert received == [
        (
            profile,
            "token",
            [
                {
                    "role": {"type": "preset", "id": "identity-admin"},
                    "principals": [{"type": "user", "id": 100}],
                }
            ],
        )
    ]


def test_id_policy_update_dry_run_does_not_authenticate(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text('{"bindings": []}')
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )

    result = runner.invoke(
        cli.app, ["id-policy", "update", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "would_update" in result.stdout


def test_id_policy_rejects_invalid_document(tmp_path: Path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(
        '{"bindings": [{"role": {"type": "custom", "id": "admin"}}]}'
    )

    result = runner.invoke(
        cli.app, ["id-policy", "update", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "role" in result.stderr
