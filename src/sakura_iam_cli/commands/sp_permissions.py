"""Read-only diagnosis of service principal IAM and ID role assignments."""

from __future__ import annotations

from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common
from sakura_iam_cli.permission_audit import PermissionAudit

_STATUS = {
    "present": "あり",
    "missing": "未割当",
    "unknown": "判定不能",
    "complete": "調査完了",
}


def print_report(report: dict) -> None:
    console = Console()
    console.print(Text(f"SP: {report['service_principal_id']}"))
    target = report["target"]
    locations = []
    if target["type"] == "unknown":
        locations.append("プロジェクト未特定")
    for policy in report["iam"]["policies"]:
        source = policy["source"].split("/")
        if source[0] == "projects":
            locations.append(f"プロジェクト {source[1]}")
        elif source[0] == "folders":
            locations.append(f"フォルダ {source[1]}")
        else:
            locations.append("組織")
    console.print(Text(f"確認するIAMポリシー: {' → '.join(locations)}"))
    policies = Table("区分", "確認元", "参照結果", "割り当てロール")
    for kind in ("iam", "id"):
        for policy in report[kind]["policies"]:
            policies.add_row(
                Text(kind.upper()),
                Text(policy["source"]),
                Text("確認済み" if policy["complete"] else "判定不能"),
                Text(
                    ", ".join(policy["roles"])
                    or ("なし" if policy["complete"] else "未確認")
                ),
            )
    console.print(policies)
    requirements = Table("区分", "指定ロール", "割り当て", "付与元")
    for kind in ("iam", "id"):
        if report[kind]["required_roles"]:
            for check in report[kind]["checks"]:
                requirements.add_row(
                    Text(kind.upper()),
                    Text(check["role"]),
                    Text(_STATUS[check["status"]]),
                    Text(", ".join(check["sources"]) or "-"),
                )
    if requirements.row_count:
        console.print(requirements)
    diagnostics = [f"{item['source']}: {item['error']}" for item in report["issues"]]
    diagnostics += [
        f"{policy['source']}: {policy['error']}"
        for kind in ("iam", "id")
        for policy in report[kind]["policies"]
        if policy["error"]
    ]
    for message in dict.fromkeys(diagnostics):
        console.print(Text(message))
    for warning in report["warnings"]:
        console.print(Text(warning))


@apps.sp_app.command("check-permissions")
def check_permissions(
    ctx: typer.Context,
    service_principal_id: Annotated[
        int | None,
        typer.Argument(min=1, help="SP to inspect; defaults to the authenticated SP."),
    ] = None,
    project_id: Annotated[
        int | None,
        typer.Option(
            "--project-id",
            min=1,
            help="IAM target project; defaults to the SP's project.",
        ),
    ] = None,
    folder_id: Annotated[
        int | None, typer.Option("--folder-id", min=1, help="IAM target folder.")
    ] = None,
    organization: Annotated[
        bool,
        typer.Option(
            "--organization", help="Check IAM assignments at the organization level."
        ),
    ] = False,
    iam_role: Annotated[
        list[str] | None,
        typer.Option(
            "--iam-role",
            help="Required IAM role ID (exact assignment); repeat as needed.",
        ),
    ] = None,
    id_role: Annotated[
        list[str] | None,
        typer.Option(
            "--id-role",
            help="Required ID role ID (exact assignment); repeat as needed.",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print the complete diagnostic report as JSON."),
    ] = False,
) -> None:
    """Inspect IAM inheritance and ID policies. Uses read-only requests."""
    try:
        if sum((project_id is not None, folder_id is not None, organization)) > 1:
            raise core.CliError(
                "specify at most one of --project-id, --folder-id, or --organization"
            )
        profile, token = common.authenticated(ctx)
        subject = (
            str(service_principal_id)
            if service_principal_id is not None
            else profile.service_principal_id
        )
        scope = (
            "project"
            if project_id is not None
            else (
                "folder"
                if folder_id is not None
                else ("organization" if organization else None)
            )
        )
        target_id = (
            str(project_id)
            if project_id is not None
            else (str(folder_id) if folder_id is not None else None)
        )
        report = PermissionAudit(profile, token, subject).run(
            scope, target_id, iam_role or [], id_role or []
        )
        if json_output:
            common.print_json(report)
        else:
            print_report(report)
    except (core.CliError, ValueError, OSError) as exc:
        common.fail(core.CliError(str(exc)))
    raise typer.Exit({"missing": 1, "unknown": 2}.get(report["status"], 0))
