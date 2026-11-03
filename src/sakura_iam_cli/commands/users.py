from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, options


@apps.user_app.command("list")
def list_user_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[options.UserOrdering | None, typer.Option("--ordering")] = None,
) -> None:
    """List users."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_users(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("create")
def create_user_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    code: Annotated[str, typer.Option("--code")],
    description: Annotated[str, typer.Option("--description")] = "",
    email: Annotated[str | None, typer.Option("--email")] = None,
    password_file: Annotated[
        Path | None,
        typer.Option("--password-file", help="Read the password from a file."),
    ] = None,
) -> None:
    """Create a user; prompts for a password unless --password-file is used."""
    try:
        password = common.read_password(password_file, required=True)
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.create_user(
                profile, token, name, code, password or "", description, email
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("get")
def get_user_resource(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
) -> None:
    """Get a user."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_user(profile, token, user_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("update")
def update_user_resource(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    password_file: Annotated[
        Path | None,
        typer.Option("--password-file", help="Also replace the password from a file."),
    ] = None,
) -> None:
    """Update a user and optionally replace the password."""
    try:
        password = common.read_password(password_file, required=False)
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_user(profile, token, user_id, name, description, password)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("delete")
def delete_user_resource(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a user."""
    if dry_run:
        common.print_json(
            {"dry_run": True, "user_id": user_id, "status": "would_delete"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_user(profile, token, user_id)
        common.print_json({"user_id": user_id, "status": "deleted"})
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("register-email")
def register_email(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    email: Annotated[str, typer.Option("--email")],
) -> None:
    """Register an email address for a user."""
    try:
        profile, token = common.authenticated(ctx)
        core.register_user_email(profile, token, user_id, email)
        common.print_json({"user_id": user_id, "email": email, "status": "registered"})
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("unregister-email")
def unregister_email(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Unregister a user's email address."""
    if dry_run:
        common.print_json(
            {"dry_run": True, "user_id": user_id, "status": "would_unregister_email"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.unregister_user_email(profile, token, user_id)
        common.print_json({"user_id": user_id, "status": "email_unregistered"})
    except core.CliError as exc:
        common.fail(exc)
