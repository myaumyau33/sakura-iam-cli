import pytest

from sakura_iam_cli.core import CliError
from sakura_iam_cli.resources import ResourceTree


@pytest.fixture
def tree() -> ResourceTree:
    return ResourceTree(
        [
            {"id": 1, "name": "Production", "parent_id": None},
            {"id": 2, "name": "Development", "parent_id": None},
            {"id": 3, "name": "Batch", "parent_id": 2},
        ],
        [
            {
                "id": 10,
                "name": "Automation Project",
                "code": "automation-project",
                "parent_folder_id": 2,
            },
            {
                "id": 11,
                "name": "Production",
                "code": "production-project",
                "parent_folder_id": None,
            },
        ],
    )


def test_resolve_paths_and_ids(tree: ResourceTree):
    assert tree.resolve_folder("/Development/Batch").id == "3"
    assert tree.resolve_folder("folder:1").name == "Production"
    assert tree.resolve_resource("/Development/automation-project").id == "10"
    assert tree.resolve_resource("/Development/Automation Project").id == "10"
    assert tree.resolve_resource("project:11").name == "Production"


def test_ambiguous_folder_and_project_name_requires_id(tree: ResourceTree):
    with pytest.raises(CliError, match="ambiguous"):
        tree.resolve_resource("/Production")


def test_paths_must_be_absolute(tree: ResourceTree):
    with pytest.raises(CliError, match="absolute"):
        tree.resolve_resource("Development/Batch")


def test_folder_cannot_move_into_descendant(tree: ResourceTree):
    source = tree.resolve_resource("folder:2")
    destination = tree.resolve_folder("folder:3")
    with pytest.raises(CliError, match="descendant"):
        tree.ensure_valid_move([source], destination)


def test_plan_mkdir(tree: ResourceTree):
    assert tree.plan_mkdir("/Development/New", False) == ("2", ["New"])
    assert tree.plan_mkdir("/Development/New/Logs", True) == ("2", ["New", "Logs"])
    assert tree.plan_mkdir("/Development", True) == ("2", [])
    with pytest.raises(CliError, match="--parents"):
        tree.plan_mkdir("/Missing/Child", False)
    with pytest.raises(CliError, match="already exists"):
        tree.plan_mkdir("/Development", False)
