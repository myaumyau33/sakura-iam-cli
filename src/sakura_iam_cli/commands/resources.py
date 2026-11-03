from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common
from sakura_iam_cli.resources import Resource, ResourceTree


def load_resource_tree(profile: core.Profile, token: str) -> ResourceTree:
    folders = common.collect_pages(
        lambda page: core.list_folders(profile, token, page=page, per_page=100)
    )
    projects = common.collect_pages(
        lambda page: core.list_projects(profile, token, page=page, per_page=100)
    )
    return ResourceTree(folders, projects)


def resource_label(resource: Resource) -> str:
    return (
        resource.code if resource.kind == "project" and resource.code else resource.name
    )


@apps.resource_app.command("ls")
def resource_ls(
    ctx: typer.Context,
    path: Annotated[
        str, typer.Argument(help="Absolute folder path or folder:ID.")
    ] = "/",
    json_output: Annotated[
        bool, typer.Option("--json", help="Print JSON instead of a table.")
    ] = False,
) -> None:
    """List the folders and projects immediately below a path."""
    try:
        profile, token = common.authenticated(ctx)
        tree = load_resource_tree(profile, token)
        folder = tree.resolve_folder(path)
        children = tree.children(None if folder is None else folder.id)
    except core.CliError as exc:
        common.fail(exc)
    rows = [
        {
            "type": item.kind,
            "id": item.id,
            "name": item.name,
            "code": item.code,
        }
        for item in children
    ]
    if json_output:
        common.print_json({"path": path, "items": rows})
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("TYPE")
    table.add_column("ID")
    table.add_column("NAME")
    table.add_column("CODE")
    for row in rows:
        table.add_row(row["type"], row["id"], row["name"], row["code"] or "")
    Console().print(table)


@apps.resource_app.command("mv")
def resource_mv(
    ctx: typer.Context,
    references: Annotated[
        list[str],
        typer.Argument(
            help="One or more source paths followed by a destination folder path."
        ),
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Move folders and projects using absolute paths or kind:ID references."""
    try:
        if len(references) < 2:
            raise core.CliError("mv requires at least one source and one destination")
        profile, token = common.authenticated(ctx)
        tree = load_resource_tree(profile, token)
        sources = [tree.resolve_resource(reference) for reference in references[:-1]]
        if len({(item.kind, item.id) for item in sources}) != len(sources):
            raise core.CliError("the same source was specified more than once")
        destination = tree.resolve_folder(references[-1])
        tree.ensure_valid_move(sources, destination)
        destination_id = None if destination is None else destination.id
        result = {
            "sources": [
                {"type": item.kind, "id": item.id, "name": item.name, "code": item.code}
                for item in sources
            ],
            "destination": {
                "type": "root" if destination is None else "folder",
                "id": destination_id,
                "name": "/" if destination is None else destination.name,
            },
            "status": "would_move" if dry_run else "moved",
        }
        if dry_run:
            result["dry_run"] = True
            common.print_json(result)
            return
        project_ids = [item.id for item in sources if item.kind == "project"]
        folder_ids = [item.id for item in sources if item.kind == "folder"]
        if project_ids:
            core.move_projects(profile, token, project_ids, destination_id)
        if folder_ids:
            core.move_folders(profile, token, folder_ids, destination_id)
        common.print_json(result)
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.resource_app.command("mkdir")
def resource_mkdir(
    ctx: typer.Context,
    path: Annotated[str, typer.Argument(help="Absolute path of the folder to create.")],
    parents: Annotated[
        bool,
        typer.Option(
            "--parents",
            "-p",
            help="Create missing parent folders and ignore an existing target.",
        ),
    ] = False,
    description: Annotated[
        str, typer.Option("--description", help="Description for the final folder.")
    ] = "",
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Create a folder by path, optionally including missing parents."""
    try:
        profile, token = common.authenticated(ctx)
        tree = load_resource_tree(profile, token)
        parent_id, missing_names = tree.plan_mkdir(path, parents)
        if not missing_names:
            common.print_json({"path": path, "created": [], "status": "already_exists"})
            return
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "path": path,
                    "parent_id": parent_id,
                    "folders": missing_names,
                    "status": "would_create",
                }
            )
            return
        created = []
        current_parent_id = parent_id
        for index, name in enumerate(missing_names):
            response = core.create_folder(
                profile,
                token,
                name,
                description if index == len(missing_names) - 1 else "",
                current_parent_id,
            )
            response.setdefault("name", name)
            response.setdefault("parent_id", current_parent_id)
            folder = tree.add_folder(response)
            current_parent_id = folder.id
            created.append(
                {"id": folder.id, "name": folder.name, "parent_id": folder.parent_id}
            )
        common.print_json({"path": path, "created": created, "status": "created"})
    except (core.CliError, ValueError, KeyError) as exc:
        common.fail(core.CliError(str(exc)))
