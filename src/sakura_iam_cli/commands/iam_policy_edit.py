from __future__ import annotations

from typing import Annotated

import questionary
import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import (
    apps,
    common,
    policy_bindings,
    policy_targets,
    prompts,
)


@apps.iam_policy_app.command("add")
def add_iam_policy_bindings(
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
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Interactively add users or service principals to IAM role bindings."""
    try:
        profile, token = common.authenticated(ctx)
        if not organization and folder_id is None and project_id is None:
            scope, resource_id = policy_targets.select_iam_policy_target(profile, token)
        else:
            scope, resource_id = policy_targets.resolve_iam_policy_target(
                organization, folder_id, project_id
            )
        policy = policy_targets.read_iam_policy_for_target(
            profile, token, scope, resource_id
        )
        bindings = policy.get("bindings")
        if not isinstance(bindings, list):
            raise core.CliError(
                "IAM API policy response did not contain a bindings array"
            )

        principal_types = prompts.interactive_checkbox(
            "追加するプリンシパル種別を選択してください",
            [
                questionary.Choice("サービスプリンシパル", value="service-principal"),
                questionary.Choice("ユーザ", value="user"),
            ],
        )
        principals: list[dict] = []
        if "service-principal" in principal_types:
            service_principals = common.collect_pages(
                lambda page: core.list_service_principals(
                    profile, token, page=page, per_page=100
                )
            )
            selected_ids = prompts.interactive_checkbox(
                "サービスプリンシパルを選択してください",
                [
                    questionary.Choice(
                        f"{item.get('name', '(名前なし)')} ({item['id']})",
                        value=int(item["id"]),
                    )
                    for item in service_principals
                    if "id" in item
                ],
            )
            principals.extend(
                {"type": "service-principal", "id": principal_id}
                for principal_id in selected_ids
            )
        if "user" in principal_types:
            users = common.collect_pages(
                lambda page: core.list_users(profile, token, page=page, per_page=100)
            )
            selected_ids = prompts.interactive_checkbox(
                "ユーザを選択してください",
                [
                    questionary.Choice(
                        f"{item.get('name', '(名前なし)')} [{item.get('code', '-')}] ({item['id']})",
                        value=int(item["id"]),
                    )
                    for item in users
                    if "id" in item
                ],
            )
            principals.extend(
                {"type": "user", "id": principal_id} for principal_id in selected_ids
            )

        roles = common.collect_pages(
            lambda page: core.list_iam_roles(profile, token, page=page, per_page=100)
        )
        role_ids = prompts.interactive_checkbox(
            "割り当てるIAMロールを選択してください",
            policy_bindings.build_iam_role_choices(roles, scope, bindings, principals),
        )
        updated_bindings = policy_bindings.merge_iam_policy_bindings(
            bindings, role_ids, principals
        )
        result = {
            "target": {"type": scope, "id": resource_id},
            "principals": principals,
            "iam_roles": role_ids,
            "bindings": updated_bindings,
        }
        if dry_run:
            common.print_json({"dry_run": True, "status": "would_update", **result})
            return
        if not prompts.interactive_confirm("この内容でIAMポリシーを更新しますか？"):
            common.print_json({"status": "cancelled", **result})
            return
        response = policy_targets.update_iam_policy_for_target(
            profile, token, scope, resource_id, updated_bindings
        )
        common.print_json(
            {"status": "updated", "target": result["target"], "policy": response}
        )
    except (core.CliError, KeyError, TypeError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.iam_policy_app.command("delete")
def delete_iam_policy_bindings(
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
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Interactively remove users or service principals from IAM role bindings."""
    try:
        profile, token = common.authenticated(ctx)
        if not organization and folder_id is None and project_id is None:
            scope, resource_id = policy_targets.select_iam_policy_target(profile, token)
        else:
            scope, resource_id = policy_targets.resolve_iam_policy_target(
                organization, folder_id, project_id
            )
        policy = policy_targets.read_iam_policy_for_target(
            profile, token, scope, resource_id
        )
        bindings = policy.get("bindings")
        if not isinstance(bindings, list):
            raise core.CliError(
                "IAM API policy response did not contain a bindings array"
            )
        assigned_principals = {
            (principal.get("type"), principal.get("id"))
            for binding in bindings
            if isinstance(binding, dict)
            for principal in binding.get("principals", [])
            if isinstance(principal, dict)
        }
        type_choices = []
        if any(
            principal_type == "service-principal"
            for principal_type, _ in assigned_principals
        ):
            type_choices.append(
                questionary.Choice("サービスプリンシパル", value="service-principal")
            )
        if any(principal_type == "user" for principal_type, _ in assigned_principals):
            type_choices.append(questionary.Choice("ユーザ", value="user"))
        principal_types = prompts.interactive_checkbox(
            "削除するプリンシパル種別を選択してください", type_choices
        )

        principals: list[dict] = []
        if "service-principal" in principal_types:
            service_principals = common.collect_pages(
                lambda page: core.list_service_principals(
                    profile, token, page=page, per_page=100
                )
            )
            selected_ids = prompts.interactive_checkbox(
                "サービスプリンシパルを選択してください",
                [
                    questionary.Choice(
                        f"{item.get('name', '(名前なし)')} ({item['id']})",
                        value=int(item["id"]),
                    )
                    for item in service_principals
                    if "id" in item
                    and ("service-principal", int(item["id"])) in assigned_principals
                ],
            )
            principals.extend(
                {"type": "service-principal", "id": principal_id}
                for principal_id in selected_ids
            )
        if "user" in principal_types:
            users = common.collect_pages(
                lambda page: core.list_users(profile, token, page=page, per_page=100)
            )
            selected_ids = prompts.interactive_checkbox(
                "ユーザを選択してください",
                [
                    questionary.Choice(
                        f"{item.get('name', '(名前なし)')} [{item.get('code', '-')}] ({item['id']})",
                        value=int(item["id"]),
                    )
                    for item in users
                    if "id" in item and ("user", int(item["id"])) in assigned_principals
                ],
            )
            principals.extend(
                {"type": "user", "id": principal_id} for principal_id in selected_ids
            )

        roles = common.collect_pages(
            lambda page: core.list_iam_roles(profile, token, page=page, per_page=100)
        )
        role_ids = prompts.interactive_checkbox(
            "削除するIAMロールを選択してください",
            policy_bindings.build_iam_role_removal_choices(roles, bindings, principals),
        )
        updated_bindings = policy_bindings.remove_iam_policy_bindings(
            bindings, role_ids, principals
        )
        result = {
            "target": {"type": scope, "id": resource_id},
            "principals": principals,
            "iam_roles": role_ids,
            "bindings": updated_bindings,
        }
        if dry_run:
            common.print_json({"dry_run": True, "status": "would_update", **result})
            return
        if not prompts.interactive_confirm("選択したIAMロール割り当てを削除しますか？"):
            common.print_json({"status": "cancelled", **result})
            return
        response = policy_targets.update_iam_policy_for_target(
            profile, token, scope, resource_id, updated_bindings
        )
        common.print_json(
            {"status": "updated", "target": result["target"], "policy": response}
        )
    except (core.CliError, KeyError, TypeError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
