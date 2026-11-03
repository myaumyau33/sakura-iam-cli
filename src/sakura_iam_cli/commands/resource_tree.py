"""Recursive folder and project listing."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text
from rich.tree import Tree

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, resources
from sakura_iam_cli.resources import ResourceTree


def nested_resources(
    tree: ResourceTree, folder_id: str | None, depth: int | None
) -> list[dict]:
    items: list[dict] = []
    pending = [(folder_id, items, 0)]
    visited = {folder_id}
    while pending:
        parent_id, children, level = pending.pop()
        for resource in tree.children(parent_id):
            node = {
                "type": resource.kind,
                "id": resource.id,
                "name": resource.name,
                "code": resource.code,
            }
            children.append(node)
            if resource.kind == "folder":
                node["children"] = []
                if depth is None or level + 1 < depth:
                    if resource.id in visited:
                        raise core.CliError(
                            f"cycle detected in folder hierarchy: folder:{resource.id}"
                        )
                    visited.add(resource.id)
                    pending.append((resource.id, node["children"], level + 1))
    return items


def tree_label(node: dict) -> Text:
    if node["type"] == "folder":
        return Text(f"{node['name']}/ (folder:{node['id']})")
    code = f" [{node['code']}]" if node["code"] else ""
    return Text(f"{node['name']}{code} (project:{node['id']})")


def print_tree(label: Text, items: list[dict]) -> None:
    root = Tree(label)
    pending = [(root, items)]
    while pending:
        parent, children = pending.pop()
        for child in children:
            branch = parent.add(tree_label(child))
            if child["type"] == "folder":
                pending.append((branch, child["children"]))
    Console().print(root)


@apps.resource_app.command("tree")
def resource_tree(
    ctx: typer.Context,
    path: Annotated[
        str, typer.Argument(help="Absolute folder path or folder:ID.")
    ] = "/",
    depth: Annotated[
        int | None,
        typer.Option(
            "--depth",
            "-L",
            min=1,
            help="Maximum number of levels below the starting folder.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print a nested JSON hierarchy instead of a tree."),
    ] = False,
) -> None:
    """Show folders and projects recursively below a path."""
    try:
        profile, token = common.authenticated(ctx)
        tree = resources.load_resource_tree(profile, token)
        folder = tree.resolve_folder(path)
        items = nested_resources(tree, None if folder is None else folder.id, depth)
        if json_output:
            common.print_json({"path": path, "items": items})
        else:
            label = (
                Text("/")
                if folder is None
                else tree_label(
                    {"type": "folder", "id": folder.id, "name": folder.name}
                )
            )
            print_tree(label, items)
    except core.CliError as exc:
        common.fail(exc)
