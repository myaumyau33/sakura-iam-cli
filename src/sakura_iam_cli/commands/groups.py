from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, options


@apps.group_app.command("list")
def list_group_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[
        options.GroupOrdering | None, typer.Option("--ordering")
    ] = None,
    user_id: Annotated[
        str | None, typer.Option("--user-id", help="Filter by a member user ID.")
    ] = None,
) -> None:
    """List groups."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_groups(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
                user_id=user_id,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.group_app.command("create")
def create_group_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Create a group."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.create_group(profile, token, name, description))
    except core.CliError as exc:
        common.fail(exc)


@apps.group_app.command("get")
def get_group_resource(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
) -> None:
    """Get a group."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_group(profile, token, group_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.group_app.command("update")
def update_group_resource(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Update a group."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_group(profile, token, group_id, name, description)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.group_app.command("delete")
def delete_group_resource(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a group."""
    if dry_run:
        common.print_json(
            {"dry_run": True, "group_id": group_id, "status": "would_delete"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_group(profile, token, group_id)
        common.print_json({"group_id": group_id, "status": "deleted"})
    except core.CliError as exc:
        common.fail(exc)


@apps.group_app.command("members")
def list_group_members(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
) -> None:
    """List a group's user memberships."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.list_group_memberships(profile, token, group_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.group_app.command("set-members")
def set_group_members(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
    user_ids: Annotated[
        list[str] | None,
        typer.Option("--user-id", help="Complete member list; may be repeated."),
    ] = None,
    clear: Annotated[
        bool, typer.Option("--clear", help="Remove every user from the group.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace all user memberships in a group."""
    try:
        if clear and user_ids:
            raise core.CliError("--clear cannot be combined with --user-id")
        if not clear and not user_ids:
            raise core.CliError("specify at least one --user-id, or use --clear")
        members = [] if clear else user_ids or []
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "group_id": group_id,
                    "user_ids": members,
                    "status": "would_replace_members",
                }
            )
            return
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_group_memberships(profile, token, group_id, members)
        )
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
