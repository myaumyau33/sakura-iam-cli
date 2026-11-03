import json
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_iam_policy_requires_exactly_one_target():
    missing = runner.invoke(cli.app, ["iam-policy", "get"])
    duplicate = runner.invoke(
        cli.app,
        ["iam-policy", "get", "--organization", "--project-id", "10"],
    )

    assert missing.exit_code == 1
    assert duplicate.exit_code == 1
    assert "exactly one" in missing.stderr
    assert "exactly one" in duplicate.stderr


def test_iam_policy_update_dry_run_does_not_authenticate(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "iam-policy.json"
    policy_file.write_text(
        json.dumps(
            {
                "bindings": [
                    {
                        "role": {"type": "preset", "id": "owner"},
                        "principals": [{"type": "group", "id": 100}],
                    }
                ]
            }
        )
    )
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )

    result = runner.invoke(
        cli.app,
        [
            "iam-policy",
            "update",
            str(policy_file),
            "--folder-id",
            "20",
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert output["status"] == "would_update"
    assert output["target"] == {"type": "folder", "id": "20"}


def test_iam_policy_get_dispatches_project(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "read_project_iam_policy",
        lambda *args: received.append(args) or {"bindings": []},
    )

    result = runner.invoke(cli.app, ["iam-policy", "get", "--project-id", "30"])

    assert result.exit_code == 0
    assert received == [(profile, "token", "30")]
