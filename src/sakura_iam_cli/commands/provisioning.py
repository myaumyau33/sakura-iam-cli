from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common


@apps.provisioning_app.command("list")
def list_provisioning_configurations(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List SCIM user provisioning configurations."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_scim_configurations(profile, token, page=page, per_page=per_page)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.provisioning_app.command("create")
def create_provisioning_configuration(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Save the response containing the secret token as mode 0600.",
        ),
    ] = None,
) -> None:
    """Create user provisioning. The secret token is returned only at creation."""
    try:
        profile, token = common.authenticated(ctx)
        response = core.create_scim_configuration(profile, token, name)
        if output is None:
            common.print_json(response)
        else:
            common.write_sensitive_json(output, response)
            common.print_json({"id": response.get("id"), "saved_to": str(output)})
    except core.CliError as exc:
        common.fail(exc)


@apps.provisioning_app.command("get")
def get_provisioning_configuration(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
) -> None:
    """Get one user provisioning configuration without its secret token."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.read_scim_configuration(profile, token, configuration_id)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.provisioning_app.command("update")
def update_provisioning_configuration(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
    name: Annotated[str, typer.Option("--name")],
) -> None:
    """Rename a user provisioning configuration."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_scim_configuration(profile, token, configuration_id, name)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.provisioning_app.command("delete")
def delete_provisioning_configuration(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a user provisioning configuration."""
    if dry_run:
        common.print_json(
            {
                "dry_run": True,
                "id": configuration_id,
                "status": "would_delete",
            }
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_scim_configuration(profile, token, configuration_id)
        common.print_json({"id": configuration_id, "status": "deleted"})
    except core.CliError as exc:
        common.fail(exc)


@apps.provisioning_app.command("regenerate-token")
def regenerate_provisioning_token(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            help="Save the new secret token as mode 0600.",
        ),
    ] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the secret token, immediately invalidating the previous token."""
    if dry_run:
        common.print_json(
            {
                "dry_run": True,
                "id": configuration_id,
                "status": "would_regenerate_token",
            }
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        response = core.regenerate_scim_configuration_token(
            profile, token, configuration_id
        )
        if output is None:
            common.print_json(response)
        else:
            common.write_sensitive_json(output, response)
            common.print_json({"id": configuration_id, "saved_to": str(output)})
    except core.CliError as exc:
        common.fail(exc)
