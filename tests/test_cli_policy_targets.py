from pathlib import Path

from sakura_iam_cli import core
from sakura_iam_cli.commands import (
    policy_targets,
    prompts,
)
from sakura_iam_cli.core import Profile


def test_interactive_iam_policy_target_selects_organization(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(prompts, "interactive_select", lambda *_: "organization")
    monkeypatch.setattr(
        core, "read_organization", lambda *_: {"id": 1, "name": "Organization"}
    )

    assert policy_targets.select_iam_policy_target(profile, "token") == (
        "organization",
        None,
    )


def test_interactive_iam_policy_target_selects_folder(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter(["folder", "20"])
    monkeypatch.setattr(prompts, "interactive_select", lambda *_: next(selections))
    monkeypatch.setattr(
        core,
        "list_folders",
        lambda *args, **kwargs: {
            "count": 1,
            "items": [{"id": 20, "name": "Production"}],
        },
    )

    assert policy_targets.select_iam_policy_target(profile, "token") == ("folder", "20")


def test_interactive_iam_policy_target_selects_project(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter(["project", "30"])
    monkeypatch.setattr(prompts, "interactive_select", lambda *_: next(selections))
    monkeypatch.setattr(
        core,
        "list_projects",
        lambda *args, **kwargs: {
            "count": 1,
            "items": [{"id": 30, "name": "Application", "code": "app"}],
        },
    )

    assert policy_targets.select_iam_policy_target(profile, "token") == (
        "project",
        "30",
    )
