from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, options


@apps.sp_app.command("list")
def list_principals(
    ctx: typer.Context,
    project_id: Annotated[str | None, typer.Option("--project-id")] = None,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[
        options.ServicePrincipalOrdering | None, typer.Option("--ordering")
    ] = None,
) -> None:
    """List service principals."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_service_principals(
                profile,
                token,
                page=page,
                per_page=per_page,
                project_id=project_id,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.sp_app.command("create")
def create_principal(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    project_id: Annotated[
        str | None,
        typer.Option(
            "--project-id", help="Target project; required unless set in the profile."
        ),
    ] = None,
) -> None:
    """Create a service principal."""
    try:
        profile, token = common.authenticated(ctx)
        target_project_id = project_id or profile.project_id
        if not target_project_id:
            raise core.CliError("specify --project-id to select the target project")
        common.print_json(
            core.create_service_principal(
                profile, token, target_project_id, name, description
            )
        )
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.sp_app.command("get")
def get_principal(
    ctx: typer.Context,
    service_principal_id: Annotated[str, typer.Argument(help="Service principal ID.")],
) -> None:
    """Get a service principal."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.read_service_principal(profile, token, service_principal_id)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.sp_app.command("update")
def update_principal(
    ctx: typer.Context,
    service_principal_id: Annotated[str, typer.Argument(help="Service principal ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str | None, typer.Option("--description")] = None,
) -> None:
    """Update a service principal."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_service_principal(
                profile, token, service_principal_id, name, description
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.sp_app.command("delete")
def delete_principal(
    ctx: typer.Context,
    service_principal_id: Annotated[str, typer.Argument(help="Service principal ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a service principal."""
    if dry_run:
        common.print_json(
            {
                "dry_run": True,
                "service_principal_id": service_principal_id,
                "status": "would_delete",
            }
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_service_principal(profile, token, service_principal_id)
        common.print_json(
            {"service_principal_id": service_principal_id, "status": "deleted"}
        )
    except core.CliError as exc:
        common.fail(exc)
