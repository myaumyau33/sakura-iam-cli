from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, key_files, options


def validate_single_server_options(
    server_resource_id: str | None, zone_id: str | None
) -> None:
    if (server_resource_id is None) != (zone_id is None):
        raise core.CliError(
            "--server-resource-id and --zone-id must be specified together"
        )


@apps.api_key_app.command("list")
def list_api_keys(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[
        options.ApiKeyOrdering | None, typer.Option("--ordering")
    ] = None,
) -> None:
    """List project API keys."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_project_api_keys(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.api_key_app.command("auth-status")
def api_key_auth_status(
    credentials_file: Annotated[
        Path,
        typer.Argument(
            help="Mode-0600 JSON file created by 'api-key create --output'."
        ),
    ],
    zone: Annotated[
        options.CloudApiZone, typer.Option("--zone", help="Cloud API zone endpoint.")
    ] = options.CloudApiZone.is1a,
) -> None:
    """Get the Cloud API v1.1 authentication status of a project API key."""
    try:
        access_token, access_token_secret = key_files.load_api_key_credentials(
            credentials_file
        )
        common.print_json(
            core.get_cloud_auth_status(
                access_token, access_token_secret, zone=zone.value
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.api_key_app.command("create")
def create_api_key(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    iam_roles: Annotated[
        list[str], typer.Option("--iam-role", help="Repeat for each IAM role.")
    ],
    description: Annotated[str, typer.Option("--description")] = "",
    project_id: Annotated[
        str | None,
        typer.Option(
            "--project-id", help="Target project; required unless set in the profile."
        ),
    ] = None,
    server_resource_id: Annotated[
        str | None, typer.Option("--server-resource-id")
    ] = None,
    zone_id: Annotated[str | None, typer.Option("--zone-id")] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", help="Save the response containing the secret as mode 0600."
        ),
    ] = None,
) -> None:
    """Create a project API key. The secret is returned only at creation."""
    try:
        validate_single_server_options(server_resource_id, zone_id)
        profile, token = common.authenticated(ctx)
        target_project_id = project_id or profile.project_id
        if not target_project_id:
            raise core.CliError("specify --project-id to select the target project")
        response = core.create_project_api_key(
            profile,
            token,
            target_project_id,
            name,
            description,
            iam_roles,
            server_resource_id,
            zone_id,
        )
        if output is None:
            common.print_json(response)
        else:
            common.write_sensitive_json(output, response)
            common.print_json({"id": response.get("id"), "saved_to": str(output)})
    except (core.CliError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.api_key_app.command("get")
def get_api_key(
    ctx: typer.Context,
    api_key_id: Annotated[str, typer.Argument(help="Project API key ID.")],
) -> None:
    """Get a project API key (the secret is not returned)."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_project_api_key(profile, token, api_key_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.api_key_app.command("update")
def update_api_key(
    ctx: typer.Context,
    api_key_id: Annotated[str, typer.Argument(help="Project API key ID.")],
    name: Annotated[str, typer.Option("--name")],
    iam_roles: Annotated[
        list[str], typer.Option("--iam-role", help="Repeat for each IAM role.")
    ],
    description: Annotated[str, typer.Option("--description")] = "",
    server_resource_id: Annotated[
        str | None, typer.Option("--server-resource-id")
    ] = None,
    zone_id: Annotated[str | None, typer.Option("--zone-id")] = None,
) -> None:
    """Update a project API key."""
    try:
        validate_single_server_options(server_resource_id, zone_id)
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_project_api_key(
                profile,
                token,
                api_key_id,
                name,
                description,
                iam_roles,
                server_resource_id,
                zone_id,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.api_key_app.command("delete")
def delete_api_key(
    ctx: typer.Context,
    api_key_id: Annotated[str, typer.Argument(help="Project API key ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a project API key."""
    if dry_run:
        common.print_json({"dry_run": True, "id": api_key_id, "status": "would_delete"})
        return
    try:
        profile, token = common.authenticated(ctx)
        core.delete_project_api_key(profile, token, api_key_id)
        common.print_json({"id": api_key_id, "status": "deleted"})
    except core.CliError as exc:
        common.fail(exc)
