from __future__ import annotations

import questionary
import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import common, prompts


def resolve_iam_policy_target(
    organization: bool, folder_id: str | None, project_id: str | None
) -> tuple[str, str | None]:
    targets = [organization, folder_id is not None, project_id is not None]
    if sum(targets) != 1:
        raise core.CliError(
            "specify exactly one of --organization, --folder-id, or --project-id"
        )
    if organization:
        return "organization", None
    scope, resource_id = (
        ("folder", folder_id) if folder_id is not None else ("project", project_id)
    )
    try:
        numeric_id = int(resource_id)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise core.CliError(f"{scope} ID must be an integer") from exc
    if numeric_id <= 0:
        raise core.CliError(f"{scope} ID must be a positive integer")
    return scope, str(numeric_id)


def select_iam_policy_target(
    profile: core.Profile, token: str
) -> tuple[str, str | None]:
    scope = prompts.interactive_select(
        "IAMポリシーの対象階層を選択してください",
        [
            questionary.Choice("組織", value="organization"),
            questionary.Choice("フォルダ", value="folder"),
            questionary.Choice("プロジェクト", value="project"),
        ],
    )
    if scope == "organization":
        organization = core.read_organization(profile, token)
        name = organization.get("name", "組織")
        organization_id = organization.get("id")
        typer.echo(f"対象: {name} ({organization_id})")
        return "organization", None
    if scope == "folder":
        folders = common.collect_pages(
            lambda page: core.list_folders(profile, token, page=page, per_page=100)
        )
        folder_id = prompts.interactive_select(
            "フォルダを選択してください",
            [
                questionary.Choice(
                    f"{item.get('name', '(名前なし)')} ({item['id']})",
                    value=str(item["id"]),
                )
                for item in folders
                if "id" in item
            ],
        )
        return "folder", folder_id
    projects = common.collect_pages(
        lambda page: core.list_projects(profile, token, page=page, per_page=100)
    )
    project_id = prompts.interactive_select(
        "プロジェクトを選択してください",
        [
            questionary.Choice(
                f"{item.get('name', '(名前なし)')} [{item.get('code', '-')}] ({item['id']})",
                value=str(item["id"]),
            )
            for item in projects
            if "id" in item
        ],
    )
    return "project", project_id


def read_iam_policy_for_target(
    profile: core.Profile, token: str, scope: str, resource_id: str | None
) -> dict:
    if scope == "organization":
        return core.read_organization_iam_policy(profile, token)
    if scope == "folder":
        return core.read_folder_iam_policy(profile, token, resource_id or "")
    return core.read_project_iam_policy(profile, token, resource_id or "")


def update_iam_policy_for_target(
    profile: core.Profile,
    token: str,
    scope: str,
    resource_id: str | None,
    bindings: list[dict],
) -> dict:
    if scope == "organization":
        return core.update_organization_iam_policy(profile, token, bindings)
    if scope == "folder":
        return core.update_folder_iam_policy(
            profile, token, resource_id or "", bindings
        )
    return core.update_project_iam_policy(profile, token, resource_id or "", bindings)
