from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import (
    common,
    resources,
)
from sakura_iam_cli.core import Profile
from sakura_iam_cli.resources import ResourceTree

runner = CliRunner()


def test_resource_mv_dry_run_resolves_paths_without_mutation(monkeypatch):
    tree = ResourceTree(
        [{"id": 1, "name": "Production", "parent_id": None}],
        [{"id": 10, "name": "App", "code": "app", "parent_folder_id": None}],
    )
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(resources, "load_resource_tree", lambda *_: tree)
    monkeypatch.setattr(
        core, "move_projects", lambda *_: (_ for _ in ()).throw(AssertionError("moved"))
    )
    result = runner.invoke(
        cli.app, ["resource", "mv", "/app", "/Production", "--dry-run"]
    )
    assert result.exit_code == 0
    assert "would_move" in result.stdout
    assert '"id": "10"' in result.stdout


def test_resource_mkdir_parents_creates_each_missing_folder(monkeypatch):
    tree = ResourceTree([{"id": 1, "name": "Production", "parent_id": None}], [])
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    created = []
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(resources, "load_resource_tree", lambda *_: tree)

    def fake_create(_profile, _token, name, description, parent_id):
        created.append((name, description, parent_id))
        return {"id": len(created) + 1, "name": name, "parent_id": parent_id}

    monkeypatch.setattr(core, "create_folder", fake_create)
    result = runner.invoke(
        cli.app,
        [
            "resource",
            "mkdir",
            "/Production/App/Logs",
            "--parents",
            "--description",
            "log folder",
        ],
    )
    assert result.exit_code == 0
    assert created == [("App", "", "1"), ("Logs", "log folder", "2")]


def test_resource_mkdir_dry_run_does_not_create(monkeypatch):
    tree = ResourceTree([], [])
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(resources, "load_resource_tree", lambda *_: tree)
    monkeypatch.setattr(
        core,
        "create_folder",
        lambda *_: (_ for _ in ()).throw(AssertionError("created")),
    )
    result = runner.invoke(
        cli.app, ["resource", "mkdir", "/One/Two", "-p", "--dry-run"]
    )
    assert result.exit_code == 0
    assert "would_create" in result.stdout
