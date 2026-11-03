from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common


@apps.organization_app.command("get")
def get_organization(ctx: typer.Context) -> None:
    """Get the organization."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_organization(profile, token))
    except core.CliError as exc:
        common.fail(exc)


@apps.organization_app.command("update")
def update_organization_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name", help="New organization name.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Update the organization name."""
    if dry_run:
        common.print_json({"dry_run": True, "status": "would_update", "name": name})
        return
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.update_organization(profile, token, name))
    except core.CliError as exc:
        common.fail(exc)
