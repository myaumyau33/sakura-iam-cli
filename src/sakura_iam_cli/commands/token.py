from __future__ import annotations

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common


@apps.sp_app.command("token")
def token(ctx: typer.Context) -> None:
    """Issue and print an access token for the configured service principal."""
    try:
        profile, access_token = common.authenticated(ctx)
        common.print_json(
            {
                "service_principal_id": profile.service_principal_id,
                "access_token": access_token,
            }
        )
    except core.CliError as exc:
        common.fail(exc)
