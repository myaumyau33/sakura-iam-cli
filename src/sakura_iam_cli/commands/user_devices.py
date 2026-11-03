from __future__ import annotations

from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common


def run_user_destructive_action(
    ctx: typer.Context,
    user_id: str,
    status: str,
    dry_run: bool,
    action,
) -> None:
    if dry_run:
        common.print_json(
            {"dry_run": True, "user_id": user_id, "status": f"would_{status}"}
        )
        return
    try:
        profile, token = common.authenticated(ctx)
        action(profile, token)
        common.print_json({"user_id": user_id, "status": status})
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("deactivate-otp")
def deactivate_otp(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Deactivate OTP authentication for a user."""
    run_user_destructive_action(
        ctx,
        user_id,
        "otp_deactivated",
        dry_run,
        lambda profile, token: core.deactivate_user_otp(profile, token, user_id),
    )


@apps.user_app.command("trusted-devices")
def trusted_devices(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
) -> None:
    """List a user's trusted devices."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.list_trusted_devices(profile, token, user_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("delete-trusted-device")
def remove_trusted_device(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    trusted_device_id: Annotated[str, typer.Argument(help="Trusted device ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete one trusted device."""
    run_user_destructive_action(
        ctx,
        user_id,
        "trusted_device_deleted",
        dry_run,
        lambda profile, token: core.delete_trusted_device(
            profile, token, user_id, trusted_device_id
        ),
    )


@apps.user_app.command("clear-trusted-devices")
def clear_user_trusted_devices(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete every trusted device for a user."""
    run_user_destructive_action(
        ctx,
        user_id,
        "trusted_devices_cleared",
        dry_run,
        lambda profile, token: core.clear_trusted_devices(profile, token, user_id),
    )


@apps.user_app.command("security-keys")
def security_keys(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
) -> None:
    """List a user's WebAuthn security keys."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.list_security_keys(profile, token, user_id))
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("get-security-key")
def get_security_key(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    security_key_id: Annotated[str, typer.Argument(help="Security key ID.")],
) -> None:
    """Get one WebAuthn security key."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.read_security_key(profile, token, user_id, security_key_id)
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.user_app.command("delete-security-key")
def remove_security_key(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    security_key_id: Annotated[str, typer.Argument(help="Security key ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete one WebAuthn security key."""
    run_user_destructive_action(
        ctx,
        user_id,
        "security_key_deleted",
        dry_run,
        lambda profile, token: core.delete_security_key(
            profile, token, user_id, security_key_id
        ),
    )
