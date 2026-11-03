from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, policy_files


@apps.id_policy_app.command("get")
def get_id_policy(ctx: typer.Context) -> None:
    """Get the organization ID policy."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_organization_id_policy(profile, token))
    except core.CliError as exc:
        common.fail(exc)


@apps.id_policy_app.command("update")
def update_id_policy(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the complete bindings array.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the organization ID policy with a JSON document."""
    try:
        bindings = policy_files.load_id_policy(policy_file)
        if dry_run:
            common.print_json(
                {"dry_run": True, "status": "would_update", "bindings": bindings}
            )
            return
        profile, token = common.authenticated(ctx)
        common.print_json(core.update_organization_id_policy(profile, token, bindings))
    except core.CliError as exc:
        common.fail(exc)
