from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, options


@apps.project_app.command("list")
def list_project_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[
        options.ProjectOrdering | None, typer.Option("--ordering")
    ] = None,
    iam_roles: Annotated[
        list[str] | None,
        typer.Option("--iam-role", help="Filter by an IAM role; may be repeated."),
    ] = None,
    parent_folder_id: Annotated[str | None, typer.Option("--parent-folder-id")] = None,
) -> None:
    """List projects."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_projects(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
                iam_roles=iam_roles,
                parent_folder_id=parent_folder_id,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.project_app.command("create")
def create_project_resource(
    ctx: typer.Context,
    code: Annotated[str, typer.Option("--code", max=64)],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    parent_folder_id: Annotated[str | None, typer.Option("--parent-folder-id")] = None,
) -> None:
    """Create a project."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.create_project(
                profile, token, code, name, description, parent_folder_id
            )
        )
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.project_app.command("get")
def get_project_resource(
    ctx: typer.Context,
    project_id: Annotated[str, typer.Argument(help="Project ID.")],
) -> None:
    """Get a project."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_project(profile, token, project_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.project_app.command("update")
def update_project_resource(
    ctx: typer.Context,
    project_id: Annotated[str, typer.Argument(help="Project ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Update a project."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_project(profile, token, project_id, name, description)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.project_app.command("delete")
def delete_project_resource(
    ctx: typer.Context,
    project_id: Annotated[str, typer.Argument(help="Project ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a project."""
    if dry_run:
        common.print_json(
            {"dry_run": True, "project_id": project_id, "status": "would_delete"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_project(profile, token, project_id)
        common.print_json({"project_id": project_id, "status": "deleted"})
    except core.CliError as exc:
        common.fail(exc)


@apps.project_app.command("move")
def move_project_resources(
    ctx: typer.Context,
    project_ids: Annotated[
        list[str], typer.Option("--project-id", help="Project ID; may be repeated.")
    ],
    parent_folder_id: Annotated[
        str | None, typer.Option("--parent-folder-id", help="Destination folder ID.")
    ] = None,
    to_root: Annotated[
        bool, typer.Option("--to-root", help="Move projects out of a folder.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Move one or more projects to a folder or the root."""
    try:
        if (parent_folder_id is None) == (not to_root):
            raise core.CliError(
                "specify exactly one of --parent-folder-id or --to-root"
            )
        target = None if to_root else parent_folder_id
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "project_ids": project_ids,
                    "parent_folder_id": target,
                    "status": "would_move",
                }
            )
            return
        profile, token = common.authenticated(ctx)
        core.move_projects(profile, token, project_ids, target)
        common.print_json(
            {"project_ids": project_ids, "parent_folder_id": target, "status": "moved"}
        )
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
