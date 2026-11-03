from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, options, policy_files


@apps.service_policy_app.command("status")
def service_policy_status(ctx: typer.Context) -> None:
    """Get whether service policy is enabled."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(core.get_service_policy_status(profile, token))
    except core.CliError as exc:
        common.fail(exc)


def change_service_policy_state(ctx: typer.Context, action: str, dry_run: bool) -> None:
    if dry_run:
        common.print_json({"dry_run": True, "status": f"would_{action}"})
        return
    try:
        profile, token = common.authenticated(ctx)
        if action == "enable":
            core.enable_service_policy(profile, token)
        else:
            core.disable_service_policy(profile, token)
        common.print_json({"status": f"{action}d"})
    except core.CliError as exc:
        common.fail(exc)


@apps.service_policy_app.command("enable")
def enable_service_policy_command(
    ctx: typer.Context,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Enable service policy for the organization."""
    change_service_policy_state(ctx, "enable", dry_run)


@apps.service_policy_app.command("disable")
def disable_service_policy_command(
    ctx: typer.Context,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Disable service policy for the organization."""
    change_service_policy_state(ctx, "disable", dry_run)


@apps.service_policy_app.command("templates")
def list_service_policy_templates(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    code: Annotated[str | None, typer.Option("--code")] = None,
    rule_type: Annotated[
        options.ServicePolicyTemplateType | None, typer.Option("--type")
    ] = None,
) -> None:
    """List available service policy rule templates."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_service_policy_rule_templates(
                profile,
                token,
                page=page,
                per_page=per_page,
                name=name,
                code=code,
                rule_type=None if rule_type is None else rule_type.value,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.service_policy_app.command("list")
def list_service_policy_rules(
    ctx: typer.Context,
    active: Annotated[
        bool | None, typer.Option("--active/--inactive", help="Filter by active state.")
    ] = None,
    rules_dry_run: Annotated[
        bool | None,
        typer.Option(
            "--rules-dry-run/--rules-live", help="Filter by API dry-run state."
        ),
    ] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    code: Annotated[str | None, typer.Option("--code")] = None,
    rule_type: Annotated[
        options.ServicePolicyRuleType | None, typer.Option("--type")
    ] = None,
) -> None:
    """List configured organization service policy rules."""
    try:
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.list_organization_service_policy_rules(
                profile,
                token,
                is_active=active,
                is_dry_run=rules_dry_run,
                name=name,
                code=code,
                rule_type=None if rule_type is None else rule_type.value,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.service_policy_app.command("update")
def update_service_policy_rules(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the rules to update.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Update the service policy rules specified in a JSON document."""
    try:
        rules = policy_files.load_service_policy_rules(policy_file)
        if dry_run:
            common.print_json(
                {"dry_run": True, "status": "would_update", "rules": rules}
            )
            return
        profile, token = common.authenticated(ctx)
        common.print_json(
            core.update_organization_service_policy_rules(profile, token, rules)
        )
    except core.CliError as exc:
        common.fail(exc)
