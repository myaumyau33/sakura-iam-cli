from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, policy_files


@apps.auth_app.command("context")
def get_auth_context(ctx: typer.Context) -> None:
    """Get the current credential's authentication context."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_auth_context(profile, token))
    except core.CliError as exc:
        common.fail(exc)


@apps.auth_app.command("password-policy")
def get_password_policy(ctx: typer.Context) -> None:
    """Get the organization password policy."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_password_policy(profile, token))
    except core.CliError as exc:
        common.fail(exc)


@apps.auth_app.command("update-password-policy")
def update_password_policy_command(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the complete password policy.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the organization password policy."""
    try:
        policy = policy_files.load_password_policy(policy_file)
        if dry_run:
            common.print_json({"dry_run": True, "status": "would_update", **policy})
            return
        profile, token = common.authenticated(ctx)
        common.print_json(core.update_password_policy(profile, token, policy))
    except core.CliError as exc:
        common.fail(exc)


@apps.auth_app.command("conditions")
def get_auth_conditions(ctx: typer.Context) -> None:
    """Get the organization authentication conditions."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_auth_conditions(profile, token))
    except core.CliError as exc:
        common.fail(exc)


@apps.auth_app.command("update-conditions")
def update_auth_conditions_command(
    ctx: typer.Context,
    conditions_file: Annotated[
        Path, typer.Argument(help="JSON file containing all authentication conditions.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the organization authentication conditions."""
    try:
        conditions = policy_files.load_auth_conditions(conditions_file)
        if dry_run:
            common.print_json({"dry_run": True, "status": "would_update", **conditions})
            return
        profile, token = common.authenticated(ctx)
        common.print_json(core.update_auth_conditions(profile, token, conditions))
    except core.CliError as exc:
        common.fail(exc)
