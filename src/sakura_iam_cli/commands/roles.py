from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common


@apps.iam_role_app.command("list")
def list_roles(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List IAM roles."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_iam_roles(profile, token, page=page, per_page=per_page)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.iam_role_app.command("get")
def get_role(
    ctx: typer.Context,
    iam_role_id: Annotated[str, typer.Argument(help="IAM role ID.")],
) -> None:
    """Get an IAM role."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_iam_role(profile, token, iam_role_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.id_role_app.command("list")
def list_identity_roles(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List ID roles."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_id_roles(profile, token, page=page, per_page=per_page)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.id_role_app.command("get")
def get_identity_role(
    ctx: typer.Context,
    id_role_id: Annotated[str, typer.Argument(help="ID role ID.")],
) -> None:
    """Get an ID role."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_id_role(profile, token, id_role_id))
    except core.CliError as exc:
        common.fail(exc)
