import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core
from sakura_iam_cli.commands import common, resources
from sakura_iam_cli.resources import ResourceTree

runner = CliRunner()


@pytest.fixture
def authenticated(monkeypatch):
    calls = []
    profile = core.Profile("https://example.test/", None, "sp", "kid", Path("key"))

    def authenticate(ctx):
        calls.append(ctx.obj)
        return profile, "token"

    monkeypatch.setattr(common, "authenticated", authenticate)
    return calls


@pytest.fixture
def tree(monkeypatch, authenticated):
    value = ResourceTree(
        [
            {"id": 1, "name": "Production", "parent_id": None},
            {"id": 2, "name": "Batch", "parent_id": 1},
            {"id": 3, "name": "Logs", "parent_id": 2},
            {"id": 4, "name": "Empty", "parent_id": None},
        ],
        [
            {"id": 9, "name": "Root", "code": "root", "parent_folder_id": None},
            {"id": 10, "name": "App", "code": "app", "parent_folder_id": 1},
            {"id": 11, "name": "Job", "code": "job", "parent_folder_id": 2},
            {"id": 12, "name": "Archive", "code": "archive", "parent_folder_id": 3},
        ],
    )
    monkeypatch.setattr(resources, "load_resource_tree", lambda *_: value)
    return value


def test_resource_tree_prints_full_hierarchy(tree):
    result = runner.invoke(cli.app, ["resource", "tree"])
    assert result.exit_code == 0, result.output
    assert result.stdout == (
        "/\n"
        "├── Empty/ (folder:4)\n"
        "├── Production/ (folder:1)\n"
        "│   ├── Batch/ (folder:2)\n"
        "│   │   ├── Logs/ (folder:3)\n"
        "│   │   │   └── Archive [archive] (project:12)\n"
        "│   │   └── Job [job] (project:11)\n"
        "│   └── App [app] (project:10)\n"
        "└── Root [root] (project:9)\n"
    )


@pytest.mark.parametrize("path", ["/Production", "folder:1"])
def test_resource_tree_selects_subtree(tree, path):
    result = runner.invoke(cli.app, ["resource", "tree", path])
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith("Production/ (folder:1)\n")
    assert "Job [job]" in result.stdout
    assert "Empty" not in result.stdout
    assert "Root [root]" not in result.stdout


def test_resource_tree_depth_limits_display(tree):
    result = runner.invoke(cli.app, ["resource", "tree", "/Production", "-L", "1"])
    assert result.exit_code == 0, result.output
    assert "Batch/" in result.stdout
    assert "App [app]" in result.stdout
    assert "Logs/" not in result.stdout
    assert "Job [job]" not in result.stdout


def test_resource_tree_nested_json(tree):
    result = runner.invoke(cli.app, ["resource", "tree", "/Production", "--json"])
    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["path"] == "/Production"
    batch, app = document["items"]
    assert batch["type"] == "folder"
    assert batch["id"] == "2"
    logs, job = batch["children"]
    assert logs["children"][0] == {
        "type": "project",
        "id": "12",
        "name": "Archive",
        "code": "archive",
    }
    assert job == {"type": "project", "id": "11", "name": "Job", "code": "job"}
    assert app["id"] == "10"


def test_resource_tree_json_respects_depth(tree):
    result = runner.invoke(cli.app, ["resource", "tree", "--depth", "1", "--json"])
    assert result.exit_code == 0, result.output
    items = json.loads(result.stdout)["items"]
    assert [item["name"] for item in items] == ["Empty", "Production", "Root"]
    assert items[0]["children"] == items[1]["children"] == []


def test_resource_tree_empty_folder(tree):
    result = runner.invoke(cli.app, ["resource", "tree", "/Empty"])
    assert result.exit_code == 0
    assert result.stdout == "Empty/ (folder:4)\n"


@pytest.mark.parametrize("path", ["/Missing", "folder:99", "Production"])
def test_resource_tree_invalid_path(tree, path):
    result = runner.invoke(cli.app, ["resource", "tree", path])
    assert result.exit_code == 1
    assert "error:" in result.stderr
    assert result.stdout == ""


def test_resource_tree_requires_positive_depth(authenticated):
    result = runner.invoke(cli.app, ["resource", "tree", "--depth", "0"])
    assert result.exit_code == 2
    assert authenticated == []


def test_resource_tree_treats_resource_names_as_plain_text(tree):
    tree.add_folder({"id": 5, "name": "[red]literal[/red]", "parent_id": None})
    result = runner.invoke(cli.app, ["resource", "tree"])
    assert result.exit_code == 0
    assert "[red]literal[/red]/ (folder:5)" in result.stdout


def test_resource_tree_detects_cycle(monkeypatch, authenticated):
    cycle = ResourceTree(
        [
            {"id": 1, "name": "A", "parent_id": 2},
            {"id": 2, "name": "B", "parent_id": 1},
        ],
        [],
    )
    monkeypatch.setattr(resources, "load_resource_tree", lambda *_: cycle)
    result = runner.invoke(cli.app, ["resource", "tree", "folder:1"])
    assert result.exit_code == 1
    assert "cycle detected" in result.stderr
    assert result.stdout == ""


def test_resource_tree_loads_all_pages(monkeypatch, authenticated):
    calls = []

    def folders(profile, token, *, page, per_page):
        calls.append(("folders", page))
        return {
            "items": [
                {
                    "id": page,
                    "name": f"Folder{page}",
                    "parent_id": None if page == 1 else 1,
                }
            ],
            "count": 2,
        }

    def projects(profile, token, *, page, per_page):
        calls.append(("projects", page))
        return {
            "items": [
                {
                    "id": page + 10,
                    "name": f"Project{page}",
                    "code": f"p{page}",
                    "parent_folder_id": page,
                }
            ],
            "count": 2,
        }

    monkeypatch.setattr(core, "list_folders", folders)
    monkeypatch.setattr(core, "list_projects", projects)
    result = runner.invoke(cli.app, ["resource", "tree"])
    assert result.exit_code == 0, result.output
    assert calls == [("folders", 1), ("folders", 2), ("projects", 1), ("projects", 2)]
    assert "Project2 [p2] (project:12)" in result.stdout
