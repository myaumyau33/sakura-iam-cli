from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common


@apps.folder_app.command("list")
def list_folder_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    folder_name: Annotated[str | None, typer.Option("--folder-name")] = None,
    parent_id: Annotated[str | None, typer.Option("--parent-id")] = None,
) -> None:
    """List folders."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_folders(
                profile,
                token,
                page=page,
                per_page=per_page,
                folder_name=folder_name,
                parent_id=parent_id,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.folder_app.command("create")
def create_folder_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    parent_id: Annotated[str | None, typer.Option("--parent-id")] = None,
) -> None:
    """Create a folder."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.create_folder(profile, token, name, description, parent_id)
        )
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.folder_app.command("get")
def get_folder_resource(
    ctx: typer.Context,
    folder_id: Annotated[str, typer.Argument(help="Folder ID.")],
) -> None:
    """Get a folder."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_folder(profile, token, folder_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.folder_app.command("update")
def update_folder_resource(
    ctx: typer.Context,
    folder_id: Annotated[str, typer.Argument(help="Folder ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Update a folder."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_folder(profile, token, folder_id, name, description)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.folder_app.command("delete")
def delete_folder_resource(
    ctx: typer.Context,
    folder_id: Annotated[str, typer.Argument(help="Folder ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete an empty folder."""
    if dry_run:
        common.print_json(
            {"dry_run": True, "folder_id": folder_id, "status": "would_delete"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_folder(profile, token, folder_id)
        common.print_json({"folder_id": folder_id, "status": "deleted"})
    except core.CliError as exc:
        common.fail(exc)


@apps.folder_app.command("move")
def move_folder_resources(
    ctx: typer.Context,
    folder_ids: Annotated[
        list[str], typer.Option("--folder-id", help="Folder ID; may be repeated.")
    ],
    parent_id: Annotated[
        str | None, typer.Option("--parent-id", help="Destination parent folder ID.")
    ] = None,
    to_root: Annotated[
        bool, typer.Option("--to-root", help="Move folders to the root.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Move one or more folders to another folder or the root."""
    try:
        if (parent_id is None) == (not to_root):
            raise core.CliError("specify exactly one of --parent-id or --to-root")
        target = None if to_root else parent_id
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "folder_ids": folder_ids,
                    "parent_id": target,
                    "status": "would_move",
                }
            )
            return
        profile, token = common.authenticated(ctx)
        core.move_folders(profile, token, folder_ids, target)
        common.print_json(
            {"folder_ids": folder_ids, "parent_id": target, "status": "moved"}
        )
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
