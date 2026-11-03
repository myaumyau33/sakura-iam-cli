from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, policy_files, policy_targets


@apps.iam_policy_app.command("get")
def get_iam_policy(
    ctx: typer.Context,
    organization: Annotated[
        bool, typer.Option("--organization", help="Target the organization policy.")
    ] = False,
    folder_id: Annotated[
        str | None, typer.Option("--folder-id", help="Target a folder policy.")
    ] = None,
    project_id: Annotated[
        str | None, typer.Option("--project-id", help="Target a project policy.")
    ] = None,
) -> None:
    """Get an IAM policy at one resource level."""
    try:
        scope, resource_id = policy_targets.resolve_iam_policy_target(
            organization, folder_id, project_id
        )
        profile, token = common.authenticated(ctx)
        if scope == "organization":
            response = core.read_organization_iam_policy(profile, token)
        elif scope == "folder":
            response = core.read_folder_iam_policy(profile, token, resource_id or "")
        else:
            response = core.read_project_iam_policy(profile, token, resource_id or "")
        common.print_json(response)
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.iam_policy_app.command("update")
def update_iam_policy(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the complete bindings array.")
    ],
    organization: Annotated[
        bool, typer.Option("--organization", help="Target the organization policy.")
    ] = False,
    folder_id: Annotated[
        str | None, typer.Option("--folder-id", help="Target a folder policy.")
    ] = None,
    project_id: Annotated[
        str | None, typer.Option("--project-id", help="Target a project policy.")
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace an IAM policy at one resource level."""
    try:
        scope, resource_id = policy_targets.resolve_iam_policy_target(
            organization, folder_id, project_id
        )
        bindings = policy_files.load_role_policy(policy_file, "IAM policy")
        target = {"type": scope, "id": resource_id}
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "status": "would_update",
                    "target": target,
                    "bindings": bindings,
                }
            )
            return
        profile, token = common.authenticated(ctx)
        if scope == "organization":
            response = core.update_organization_iam_policy(profile, token, bindings)
        elif scope == "folder":
            response = core.update_folder_iam_policy(
                profile, token, resource_id or "", bindings
            )
        else:
            response = core.update_project_iam_policy(
                profile, token, resource_id or "", bindings
            )
        common.print_json(response)
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
