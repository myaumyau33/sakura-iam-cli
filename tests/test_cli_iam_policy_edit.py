import json
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
    prompts,
)
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_iam_policy_add_interactively_selects_principals_and_roles(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter(
        [
            ["service-principal", "user"],
            [20],
            [10],
            ["owner", "viewer"],
        ]
    )
    updated = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core,
        "read_organization_iam_policy",
        lambda *_: {
            "bindings": [
                {
                    "role": {"type": "preset", "id": "owner"},
                    "principals": [{"type": "user", "id": 10}],
                }
            ]
        },
    )
    monkeypatch.setattr(
        core,
        "list_service_principals",
        lambda *args, **kwargs: {"count": 1, "items": [{"id": 20, "name": "Worker"}]},
    )
    monkeypatch.setattr(
        core,
        "list_users",
        lambda *args, **kwargs: {
            "count": 1,
            "items": [{"id": 10, "name": "User", "code": "user"}],
        },
    )
    monkeypatch.setattr(
        core,
        "list_iam_roles",
        lambda *args, **kwargs: {
            "count": 2,
            "items": [
                {
                    "id": "owner",
                    "name": "Owner",
                    "category": "iam",
                    "lowest_grantable_resource": "project",
                },
                {
                    "id": "viewer",
                    "name": "Viewer",
                    "category": "cloud",
                    "lowest_grantable_resource": "project",
                },
            ],
        },
    )
    monkeypatch.setattr(prompts, "interactive_checkbox", lambda *_: next(selections))
    monkeypatch.setattr(prompts, "interactive_confirm", lambda *_: True)
    monkeypatch.setattr(
        core,
        "update_organization_iam_policy",
        lambda *args: updated.append(args) or {"bindings": args[-1]},
    )

    result = runner.invoke(cli.app, ["iam-policy", "add", "--organization"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "updated"
    assert len(updated) == 1
    owner, viewer = updated[0][-1]
    assert owner["principals"] == [
        {"type": "user", "id": 10},
        {"type": "service-principal", "id": 20},
    ]
    assert viewer["principals"] == [
        {"type": "service-principal", "id": 20},
        {"type": "user", "id": 10},
    ]


def test_iam_policy_add_dry_run_does_not_update(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter([["user"], [10], ["viewer"]])
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(core, "read_project_iam_policy", lambda *_: {"bindings": []})
    monkeypatch.setattr(
        core,
        "list_users",
        lambda *args, **kwargs: {"count": 1, "items": [{"id": 10, "name": "User"}]},
    )
    monkeypatch.setattr(
        core,
        "list_iam_roles",
        lambda *args, **kwargs: {
            "count": 1,
            "items": [
                {
                    "id": "viewer",
                    "name": "Viewer",
                    "category": "cloud",
                    "lowest_grantable_resource": "project",
                }
            ],
        },
    )
    monkeypatch.setattr(prompts, "interactive_checkbox", lambda *_: next(selections))
    monkeypatch.setattr(
        prompts,
        "interactive_confirm",
        lambda *_: (_ for _ in ()).throw(AssertionError("confirmed")),
    )
    monkeypatch.setattr(
        core,
        "update_project_iam_policy",
        lambda *_: (_ for _ in ()).throw(AssertionError("updated")),
    )

    result = runner.invoke(
        cli.app, ["iam-policy", "add", "--project-id", "30", "--dry-run"]
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "would_update"


def test_iam_policy_delete_dry_run_removes_selected_assignment(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter([["user"], [10], ["viewer"]])
    bindings = [
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": [
                {"type": "user", "id": 10},
                {"type": "service-principal", "id": 20},
            ],
        },
        {
            "role": {"type": "preset", "id": "editor"},
            "principals": [{"type": "user", "id": 10}],
        },
    ]
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        core, "read_project_iam_policy", lambda *_: {"bindings": bindings}
    )
    monkeypatch.setattr(
        core,
        "list_users",
        lambda *args, **kwargs: {
            "count": 2,
            "items": [
                {"id": 10, "name": "Assigned", "code": "assigned"},
                {"id": 99, "name": "Unassigned", "code": "unassigned"},
            ],
        },
    )
    monkeypatch.setattr(
        core,
        "list_iam_roles",
        lambda *args, **kwargs: {
            "count": 2,
            "items": [
                {"id": "viewer", "name": "Viewer", "category": "cloud"},
                {"id": "editor", "name": "Editor", "category": "cloud"},
            ],
        },
    )
    seen_choices = []

    def select(_message, choices):
        seen_choices.append(choices)
        return next(selections)

    monkeypatch.setattr(prompts, "interactive_checkbox", select)
    monkeypatch.setattr(
        prompts,
        "interactive_confirm",
        lambda *_: (_ for _ in ()).throw(AssertionError("confirmed")),
    )
    monkeypatch.setattr(
        core,
        "update_project_iam_policy",
        lambda *_: (_ for _ in ()).throw(AssertionError("updated")),
    )

    result = runner.invoke(
        cli.app, ["iam-policy", "delete", "--project-id", "30", "--dry-run"]
    )

    assert result.exit_code == 0
    assert [choice.value for choice in seen_choices[1]] == [10]
    output = json.loads(result.stdout)
    assert output["bindings"][0]["principals"] == [
        {"type": "service-principal", "id": 20}
    ]
    assert output["bindings"][1] == bindings[1]
