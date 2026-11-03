"""Manage SAML SSO profiles using service principal authentication."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.api.sso import SSO_PROFILE_FIELDS
from sakura_iam_cli.commands import apps, common

IdArgument = Annotated[int, typer.Argument(min=1, help="SSO profile ID.")]
NameOption = Annotated[str | None, typer.Option("--name")]
DescriptionOption = Annotated[str | None, typer.Option("--description")]
EntityOption = Annotated[
    str | None, typer.Option("--idp-entity-id", help="IdP entity ID.")
]
LoginOption = Annotated[
    str | None, typer.Option("--idp-login-url", help="IdP SAML login URL.")
]
LogoutOption = Annotated[
    str | None,
    typer.Option("--idp-logout-url", help="IdP logout URL; an empty string clears it."),
]
CertificateOption = Annotated[
    str | None, typer.Option("--idp-certificate", help="IdP X.509 certificate as text.")
]
CertificateFileOption = Annotated[
    Path | None,
    typer.Option(
        "--idp-certificate-file",
        help="Read the IdP X.509 certificate from a UTF-8 file.",
    ),
]
DryRunOption = Annotated[
    bool,
    typer.Option(
        "--dry-run",
        help="Show the requested changes without authentication or API calls.",
    ),
]


def requested_fields(
    name,
    description,
    idp_entity_id,
    idp_login_url,
    idp_logout_url,
    idp_certificate,
    idp_certificate_file,
) -> dict[str, str]:
    if idp_certificate is not None and idp_certificate_file is not None:
        raise core.CliError(
            "--idp-certificate and --idp-certificate-file cannot be combined"
        )
    if idp_certificate_file is not None:
        idp_certificate = idp_certificate_file.read_text(encoding="utf-8")
    values = (
        name,
        description,
        idp_entity_id,
        idp_login_url,
        idp_logout_url,
        idp_certificate,
    )
    return {
        field: value
        for field, value in zip(SSO_PROFILE_FIELDS, values)
        if value is not None
    }


@apps.sso_app.command("list")
def list_profiles(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List SSO profiles and their assignment status."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_sso_profiles(profile, token, page=page, per_page=per_page)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.sso_app.command("get")
def get_profile(ctx: typer.Context, sso_profile_id: IdArgument) -> None:
    """Get SSO settings, including the SP entity ID and ACS URL."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.read_sso_profile(profile, token, str(sso_profile_id)))
    except core.CliError as exc:
        common.fail(exc)


@apps.sso_app.command("create")
def create_profile(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: DescriptionOption = None,
    idp_entity_id: EntityOption = None,
    idp_login_url: LoginOption = None,
    idp_logout_url: LogoutOption = None,
    idp_certificate: CertificateOption = None,
    idp_certificate_file: CertificateFileOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Create an SSO profile. IdP settings may be supplied later using update."""
    try:
        fields = dict.fromkeys(SSO_PROFILE_FIELDS, "")
        fields.update(
            requested_fields(
                name,
                description,
                idp_entity_id,
                idp_login_url,
                idp_logout_url,
                idp_certificate,
                idp_certificate_file,
            )
        )
        if dry_run:
            common.print_json({"dry_run": True, "status": "would_create", **fields})
            return
        profile, token = common.authenticated(ctx)
        common.print_json(core.create_sso_profile(profile, token, **fields))
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.sso_app.command("update")
def update_profile(
    ctx: typer.Context,
    sso_profile_id: IdArgument,
    name: NameOption = None,
    description: DescriptionOption = None,
    idp_entity_id: EntityOption = None,
    idp_login_url: LoginOption = None,
    idp_logout_url: LogoutOption = None,
    idp_certificate: CertificateOption = None,
    idp_certificate_file: CertificateFileOption = None,
    dry_run: DryRunOption = False,
) -> None:
    """Update specified settings while keeping all other settings unchanged."""
    try:
        changes = requested_fields(
            name,
            description,
            idp_entity_id,
            idp_login_url,
            idp_logout_url,
            idp_certificate,
            idp_certificate_file,
        )
        if not changes:
            raise core.CliError("specify at least one setting to update")
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "id": sso_profile_id,
                    "changes": changes,
                    "status": "would_update",
                }
            )
            return
        profile, token = common.authenticated(ctx)
        current = core.read_sso_profile(profile, token, str(sso_profile_id))
        if not isinstance(current, dict):
            raise core.CliError("SSO profile response must be an object")
        fields = {
            field: changes.get(field, current.get(field))
            for field in SSO_PROFILE_FIELDS
        }
        if not all(isinstance(value, str) for value in fields.values()):
            raise core.CliError(
                "SSO profile response is missing valid settings; refusing to replace unspecified values"
            )
        common.print_json(
            core.update_sso_profile(profile, token, str(sso_profile_id), **fields)
        )
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.sso_app.command(
    "assign", help="Enable this SSO profile for all cloud users in the account."
)
@apps.sso_app.command("unassign", help="Disable this SSO profile's assignment.")
@apps.sso_app.command(
    "delete",
    help="Delete an SSO profile; an assigned profile must first be unassigned.",
)
def change_profile(
    ctx: typer.Context, sso_profile_id: IdArgument, dry_run: DryRunOption = False
) -> None:
    action = ctx.info_name
    if dry_run:
        common.print_json(
            {"dry_run": True, "id": sso_profile_id, "status": f"would_{action}"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        operation = {
            "assign": core.assign_sso_profile,
            "unassign": core.unassign_sso_profile,
            "delete": core.delete_sso_profile,
        }[action]
        response = operation(profile, token, str(sso_profile_id))
        common.print_json(
            {"id": sso_profile_id, "status": "deleted"}
            if action == "delete"
            else response
        )
    except core.CliError as exc:
        common.fail(exc)
