from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated

import questionary
import typer
from rich.console import Console
from rich.table import Table

from .core import (
    CliError,
    Profile,
    change_service_principal_key_state,
    clear_trusted_devices,
    create_folder,
    create_group,
    create_project,
    create_project_api_key,
    create_scim_configuration,
    create_service_principal,
    create_user,
    deactivate_user_otp,
    delete_folder,
    delete_group,
    delete_project,
    delete_project_api_key,
    delete_scim_configuration,
    delete_security_key,
    delete_service_principal,
    delete_service_principal_key,
    delete_trusted_device,
    delete_user,
    disable_service_policy,
    enable_service_policy,
    generate_key_pairs,
    get_service_policy_status,
    issue_access_token,
    list_folders,
    list_group_memberships,
    list_groups,
    list_iam_roles,
    list_id_roles,
    list_organization_service_policy_rules,
    list_project_api_keys,
    list_projects,
    list_scim_configurations,
    list_security_keys,
    list_service_policy_rule_templates,
    list_service_principal_keys,
    list_service_principals,
    list_trusted_devices,
    list_users,
    load_profile,
    move_folders,
    move_projects,
    read_auth_conditions,
    read_auth_context,
    read_folder,
    read_folder_iam_policy,
    read_group,
    read_iam_role,
    read_id_role,
    read_organization,
    read_organization_iam_policy,
    read_organization_id_policy,
    read_password_policy,
    read_project,
    read_project_api_key,
    read_project_iam_policy,
    read_scim_configuration,
    read_security_key,
    read_service_principal,
    read_user,
    regenerate_scim_configuration_token,
    register_user_email,
    unregister_user_email,
    update_auth_conditions,
    update_folder,
    update_folder_iam_policy,
    update_group,
    update_group_memberships,
    update_organization,
    update_organization_iam_policy,
    update_organization_id_policy,
    update_organization_service_policy_rules,
    update_password_policy,
    update_project,
    update_project_api_key,
    update_project_iam_policy,
    update_scim_configuration,
    update_service_principal,
    update_user,
    upload_public_key,
)
from .resources import Resource, ResourceTree

app = typer.Typer(help="A CLI wrapper for the Sakura Cloud IAM API.", no_args_is_help=True)
sp_key_app = typer.Typer(help="Manage service principal keys.", no_args_is_help=True)
sp_app = typer.Typer(help="Manage service principals.", no_args_is_help=True)
api_key_app = typer.Typer(help="Manage project API keys.", no_args_is_help=True)
iam_role_app = typer.Typer(help="Inspect IAM roles.", no_args_is_help=True)
iam_policy_app = typer.Typer(help="Manage IAM policies at each resource level.", no_args_is_help=True)
id_role_app = typer.Typer(help="Inspect ID roles.", no_args_is_help=True)
id_policy_app = typer.Typer(help="Manage the organization ID policy.", no_args_is_help=True)
organization_app = typer.Typer(help="Manage the organization.", no_args_is_help=True)
service_policy_app = typer.Typer(help="Manage service policy rules.", no_args_is_help=True)
auth_app = typer.Typer(help="Manage organization authentication settings.", no_args_is_help=True)
project_app = typer.Typer(help="Manage projects.", no_args_is_help=True)
folder_app = typer.Typer(help="Manage folders.", no_args_is_help=True)
group_app = typer.Typer(help="Manage groups and memberships.", no_args_is_help=True)
user_app = typer.Typer(help="Manage users and user authentication devices.", no_args_is_help=True)
provisioning_app = typer.Typer(help="Manage SCIM user provisioning.", no_args_is_help=True)
resource_app = typer.Typer(help="Browse and move folders and projects by path.", no_args_is_help=True)
app.add_typer(sp_key_app, name="sp-key")
app.add_typer(sp_app, name="sp")
app.add_typer(api_key_app, name="api-key")
app.add_typer(iam_role_app, name="iam-role")
app.add_typer(iam_policy_app, name="iam-policy")
app.add_typer(id_role_app, name="id-role")
app.add_typer(id_policy_app, name="id-policy")
app.add_typer(organization_app, name="organization")
app.add_typer(service_policy_app, name="service-policy")
app.add_typer(auth_app, name="auth")
app.add_typer(project_app, name="project")
app.add_typer(folder_app, name="folder")
app.add_typer(group_app, name="group")
app.add_typer(user_app, name="user")
app.add_typer(provisioning_app, name="provisioning")
app.add_typer(resource_app, name="resource")

SettingsOption = Annotated[
    Path, typer.Option("--settings", help="Path to the settings JSON file.")
]
ProfileOption = Annotated[
    str | None, typer.Option("--profile", help="Profile name from the settings file.")
]


@dataclass(frozen=True)
class AppContext:
    settings: Path
    profile_name: str | None


class ServicePrincipalOrdering(str, Enum):
    name = "name"
    name_desc = "-name"


class ServicePrincipalKeyOrdering(str, Enum):
    created_at = "created_at"
    created_at_desc = "-created_at"
    key_expires_at = "key_expires_at"
    key_expires_at_desc = "-key_expires_at"


class ApiKeyOrdering(str, Enum):
    name = "name"
    name_desc = "-name"


class ProjectOrdering(str, Enum):
    code = "code"
    code_desc = "-code"


class GroupOrdering(str, Enum):
    name = "name"
    name_desc = "-name"


class UserOrdering(str, Enum):
    code = "code"
    code_desc = "-code"


class ServicePolicyRuleType(str, Enum):
    bool = "bool"
    list = "list"


class ServicePolicyTemplateType(str, Enum):
    boolean = "boolean"
    list = "list"


@app.callback()
def configure(
    ctx: typer.Context,
    settings: SettingsOption = Path("settings.json"),
    profile_name: ProfileOption = None,
) -> None:
    """Configure the Sakura Cloud IAM API client."""
    ctx.obj = AppContext(settings=settings, profile_name=profile_name)


def print_json(value: object) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, indent=2))


def write_sensitive_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise CliError(f"refusing to overwrite existing output file: {path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as output_file:
        json.dump(value, output_file, ensure_ascii=False, indent=2)
        output_file.write("\n")


def fail(error: CliError) -> None:
    typer.echo(f"error: {error}", err=True)
    raise typer.Exit(1)


def load_key_records(key_dir: Path) -> list[tuple[Path, dict]]:
    metadata_paths = sorted(key_dir.glob("*.public.json"))
    if not metadata_paths:
        raise CliError(f"no *.public.json upload records found in {key_dir}")
    records = []
    for path in metadata_paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CliError(f"invalid upload record {path}: {exc}") from exc
        if "id" not in record:
            raise CliError(f"upload record does not contain key id: {path}")
        if "target_service_principal_id" not in record:
            raise CliError(f"upload record does not contain target service principal id: {path}")
        records.append((path, record))
    return records


def authenticated(ctx: typer.Context) -> tuple[Profile, str]:
    config: AppContext = ctx.obj
    profile = load_profile(config.settings, config.profile_name)
    return profile, issue_access_token(profile)


def load_resource_tree(profile: Profile, token: str) -> ResourceTree:
    def collect(fetch) -> list[dict]:
        page = 1
        items: list[dict] = []
        while True:
            response = fetch(page)
            batch = response.get("items", [])
            if not isinstance(batch, list):
                raise CliError("IAM API list response did not contain an items array")
            items.extend(batch)
            count = response.get("count")
            if response.get("next") or (isinstance(count, int) and len(items) < count):
                page += 1
                continue
            break
        return items

    folders = collect(lambda page: list_folders(profile, token, page=page, per_page=100))
    projects = collect(lambda page: list_projects(profile, token, page=page, per_page=100))
    return ResourceTree(folders, projects)


def resource_label(resource: Resource) -> str:
    return resource.code if resource.kind == "project" and resource.code else resource.name


@resource_app.command("ls")
def resource_ls(
    ctx: typer.Context,
    path: Annotated[str, typer.Argument(help="Absolute folder path or folder:ID.")] = "/",
    json_output: Annotated[bool, typer.Option("--json", help="Print JSON instead of a table.")] = False,
) -> None:
    """List the folders and projects immediately below a path."""
    try:
        profile, token = authenticated(ctx)
        tree = load_resource_tree(profile, token)
        folder = tree.resolve_folder(path)
        children = tree.children(None if folder is None else folder.id)
    except CliError as exc:
        fail(exc)
    rows = [
        {
            "type": item.kind,
            "id": item.id,
            "name": item.name,
            "code": item.code,
        }
        for item in children
    ]
    if json_output:
        print_json({"path": path, "items": rows})
        return
    table = Table(show_header=True, header_style="bold")
    table.add_column("TYPE")
    table.add_column("ID")
    table.add_column("NAME")
    table.add_column("CODE")
    for row in rows:
        table.add_row(row["type"], row["id"], row["name"], row["code"] or "")
    Console().print(table)


@resource_app.command("mv")
def resource_mv(
    ctx: typer.Context,
    references: Annotated[
        list[str],
        typer.Argument(help="One or more source paths followed by a destination folder path."),
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Move folders and projects using absolute paths or kind:ID references."""
    try:
        if len(references) < 2:
            raise CliError("mv requires at least one source and one destination")
        profile, token = authenticated(ctx)
        tree = load_resource_tree(profile, token)
        sources = [tree.resolve_resource(reference) for reference in references[:-1]]
        if len({(item.kind, item.id) for item in sources}) != len(sources):
            raise CliError("the same source was specified more than once")
        destination = tree.resolve_folder(references[-1])
        tree.ensure_valid_move(sources, destination)
        destination_id = None if destination is None else destination.id
        result = {
            "sources": [
                {"type": item.kind, "id": item.id, "name": item.name, "code": item.code}
                for item in sources
            ],
            "destination": {
                "type": "root" if destination is None else "folder",
                "id": destination_id,
                "name": "/" if destination is None else destination.name,
            },
            "status": "would_move" if dry_run else "moved",
        }
        if dry_run:
            result["dry_run"] = True
            print_json(result)
            return
        project_ids = [item.id for item in sources if item.kind == "project"]
        folder_ids = [item.id for item in sources if item.kind == "folder"]
        if project_ids:
            move_projects(profile, token, project_ids, destination_id)
        if folder_ids:
            move_folders(profile, token, folder_ids, destination_id)
        print_json(result)
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@resource_app.command("mkdir")
def resource_mkdir(
    ctx: typer.Context,
    path: Annotated[str, typer.Argument(help="Absolute path of the folder to create.")],
    parents: Annotated[
        bool, typer.Option("--parents", "-p", help="Create missing parent folders and ignore an existing target.")
    ] = False,
    description: Annotated[
        str, typer.Option("--description", help="Description for the final folder.")
    ] = "",
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Create a folder by path, optionally including missing parents."""
    try:
        profile, token = authenticated(ctx)
        tree = load_resource_tree(profile, token)
        parent_id, missing_names = tree.plan_mkdir(path, parents)
        if not missing_names:
            print_json({"path": path, "created": [], "status": "already_exists"})
            return
        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "path": path,
                    "parent_id": parent_id,
                    "folders": missing_names,
                    "status": "would_create",
                }
            )
            return
        created = []
        current_parent_id = parent_id
        for index, name in enumerate(missing_names):
            response = create_folder(
                profile,
                token,
                name,
                description if index == len(missing_names) - 1 else "",
                current_parent_id,
            )
            response.setdefault("name", name)
            response.setdefault("parent_id", current_parent_id)
            folder = tree.add_folder(response)
            current_parent_id = folder.id
            created.append({"id": folder.id, "name": folder.name, "parent_id": folder.parent_id})
        print_json({"path": path, "created": created, "status": "created"})
    except (CliError, ValueError, KeyError) as exc:
        fail(CliError(str(exc)))


def validate_single_server_options(
    server_resource_id: str | None, zone_id: str | None
) -> None:
    if (server_resource_id is None) != (zone_id is None):
        raise CliError("--server-resource-id and --zone-id must be specified together")


@api_key_app.command("list")
def list_api_keys(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[ApiKeyOrdering | None, typer.Option("--ordering")] = None,
) -> None:
    """List project API keys."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_project_api_keys(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except CliError as exc:
        fail(exc)


@iam_role_app.command("list")
def list_roles(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List IAM roles."""
    try:
        profile, token = authenticated(ctx)
        print_json(list_iam_roles(profile, token, page=page, per_page=per_page))
    except CliError as exc:
        fail(exc)


@iam_role_app.command("get")
def get_role(
    ctx: typer.Context,
    iam_role_id: Annotated[str, typer.Argument(help="IAM role ID.")],
) -> None:
    """Get an IAM role."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_iam_role(profile, token, iam_role_id))
    except CliError as exc:
        fail(exc)


@id_role_app.command("list")
def list_identity_roles(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List ID roles."""
    try:
        profile, token = authenticated(ctx)
        print_json(list_id_roles(profile, token, page=page, per_page=per_page))
    except CliError as exc:
        fail(exc)


@id_role_app.command("get")
def get_identity_role(
    ctx: typer.Context,
    id_role_id: Annotated[str, typer.Argument(help="ID role ID.")],
) -> None:
    """Get an ID role."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_id_role(profile, token, id_role_id))
    except CliError as exc:
        fail(exc)


def load_role_policy(path: Path, label: str) -> list[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError(f"{label} file not found: {path}") from exc
    except OSError as exc:
        raise CliError(f"could not read {label} file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid {label} JSON in {path}: {exc}") from exc

    if not isinstance(document, dict) or set(document) != {"bindings"}:
        raise CliError(f"{label} must be a JSON object containing only 'bindings'")
    bindings = document["bindings"]
    if not isinstance(bindings, list):
        raise CliError(f"{label} 'bindings' must be an array")
    for binding_index, binding in enumerate(bindings):
        location = f"bindings[{binding_index}]"
        if not isinstance(binding, dict) or set(binding) != {"role", "principals"}:
            raise CliError(f"{location} must contain only 'role' and 'principals'")
        role = binding["role"]
        if (
            not isinstance(role, dict)
            or set(role) != {"type", "id"}
            or role.get("type") != "preset"
            or not isinstance(role.get("id"), str)
            or not role["id"]
        ):
            raise CliError(f"{location}.role must contain type 'preset' and a non-empty string id")
        principals = binding["principals"]
        if not isinstance(principals, list):
            raise CliError(f"{location}.principals must be an array")
        for principal_index, principal in enumerate(principals):
            principal_location = f"{location}.principals[{principal_index}]"
            if (
                not isinstance(principal, dict)
                or set(principal) != {"type", "id"}
                or not isinstance(principal.get("type"), str)
                or not principal["type"]
                or not isinstance(principal.get("id"), int)
                or isinstance(principal["id"], bool)
            ):
                raise CliError(
                    f"{principal_location} must contain a non-empty string type and an integer id"
                )
    return bindings


def load_id_policy(path: Path) -> list[dict]:
    return load_role_policy(path, "ID policy")


@id_policy_app.command("get")
def get_id_policy(ctx: typer.Context) -> None:
    """Get the organization ID policy."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_organization_id_policy(profile, token))
    except CliError as exc:
        fail(exc)


@id_policy_app.command("update")
def update_id_policy(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the complete bindings array.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the organization ID policy with a JSON document."""
    try:
        bindings = load_id_policy(policy_file)
        if dry_run:
            print_json({"dry_run": True, "status": "would_update", "bindings": bindings})
            return
        profile, token = authenticated(ctx)
        print_json(update_organization_id_policy(profile, token, bindings))
    except CliError as exc:
        fail(exc)


def resolve_iam_policy_target(
    organization: bool, folder_id: str | None, project_id: str | None
) -> tuple[str, str | None]:
    targets = [organization, folder_id is not None, project_id is not None]
    if sum(targets) != 1:
        raise CliError(
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
        raise CliError(f"{scope} ID must be an integer") from exc
    if numeric_id <= 0:
        raise CliError(f"{scope} ID must be a positive integer")
    return scope, str(numeric_id)


@iam_policy_app.command("get")
def get_iam_policy(
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
) -> None:
    """Get an IAM policy at one resource level."""
    try:
        scope, resource_id = resolve_iam_policy_target(
            organization, folder_id, project_id
        )
        profile, token = authenticated(ctx)
        if scope == "organization":
            response = read_organization_iam_policy(profile, token)
        elif scope == "folder":
            response = read_folder_iam_policy(profile, token, resource_id or "")
        else:
            response = read_project_iam_policy(profile, token, resource_id or "")
        print_json(response)
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@iam_policy_app.command("update")
def update_iam_policy(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the complete bindings array.")
    ],
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
    """Replace an IAM policy at one resource level."""
    try:
        scope, resource_id = resolve_iam_policy_target(
            organization, folder_id, project_id
        )
        bindings = load_role_policy(policy_file, "IAM policy")
        target = {"type": scope, "id": resource_id}
        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "status": "would_update",
                    "target": target,
                    "bindings": bindings,
                }
            )
            return
        profile, token = authenticated(ctx)
        if scope == "organization":
            response = update_organization_iam_policy(profile, token, bindings)
        elif scope == "folder":
            response = update_folder_iam_policy(
                profile, token, resource_id or "", bindings
            )
        else:
            response = update_project_iam_policy(
                profile, token, resource_id or "", bindings
            )
        print_json(response)
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


def collect_pages(fetch) -> list[dict]:
    page = 1
    items: list[dict] = []
    while True:
        response = fetch(page)
        batch = response.get("items", [])
        if not isinstance(batch, list):
            raise CliError("IAM API list response did not contain an items array")
        items.extend(batch)
        count = response.get("count")
        if response.get("next") or (isinstance(count, int) and len(items) < count):
            page += 1
            continue
        return items


def interactive_checkbox(message: str, choices: list[questionary.Choice]) -> list:
    if not choices:
        raise CliError(f"no choices are available for: {message}")
    selected = questionary.checkbox(
        message,
        choices=choices,
        instruction="(Spaceで選択、Enterで確定)",
        validate=lambda values: bool(values) or "1つ以上選択してください",
    ).ask()
    if selected is None:
        raise CliError("interactive selection cancelled")
    return selected


def interactive_select(message: str, choices: list[questionary.Choice]):
    if not choices:
        raise CliError(f"no choices are available for: {message}")
    selected = questionary.select(
        message,
        choices=choices,
        instruction="(上下キーで移動、Enterで確定)",
    ).ask()
    if selected is None:
        raise CliError("interactive selection cancelled")
    return selected


def interactive_confirm(message: str) -> bool:
    answer = questionary.confirm(message, default=False).ask()
    if answer is None:
        raise CliError("interactive selection cancelled")
    return answer


def select_iam_policy_target(
    profile: Profile, token: str
) -> tuple[str, str | None]:
    scope = interactive_select(
        "IAMポリシーの対象階層を選択してください",
        [
            questionary.Choice("組織", value="organization"),
            questionary.Choice("フォルダ", value="folder"),
            questionary.Choice("プロジェクト", value="project"),
        ],
    )
    if scope == "organization":
        organization = read_organization(profile, token)
        name = organization.get("name", "組織")
        organization_id = organization.get("id")
        typer.echo(f"対象: {name} ({organization_id})")
        return "organization", None
    if scope == "folder":
        folders = collect_pages(
            lambda page: list_folders(profile, token, page=page, per_page=100)
        )
        folder_id = interactive_select(
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
    projects = collect_pages(
        lambda page: list_projects(profile, token, page=page, per_page=100)
    )
    project_id = interactive_select(
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


def role_is_grantable_at(role: dict, scope: str) -> bool:
    levels = {"organization": 0, "folder": 1, "project": 2}
    lowest = role.get("lowest_grantable_resource")
    return isinstance(lowest, str) and lowest in levels and levels[scope] <= levels[lowest]


def build_iam_role_choices(
    roles: list[dict], scope: str, bindings: list[dict], principals: list[dict]
) -> list[questionary.Choice]:
    selected_principals = {
        (principal["type"], principal["id"]) for principal in principals
    }
    assignment_counts: dict[str, int] = {}
    for binding in bindings:
        role = binding.get("role")
        binding_principals = binding.get("principals")
        if not isinstance(role, dict) or not isinstance(binding_principals, list):
            continue
        role_id = role.get("id")
        if not isinstance(role_id, str):
            continue
        assigned = {
            (principal.get("type"), principal.get("id"))
            for principal in binding_principals
            if isinstance(principal, dict)
        }
        assignment_counts[role_id] = len(selected_principals & assigned)

    choices = []
    for role in roles:
        if "id" not in role or not role_is_grantable_at(role, scope):
            continue
        role_id = str(role["id"])
        assigned_count = assignment_counts.get(role_id, 0)
        fully_assigned = bool(selected_principals) and assigned_count == len(
            selected_principals
        )
        partial_label = " [一部割当済み]" if 0 < assigned_count < len(selected_principals) else ""
        choices.append(
            questionary.Choice(
                f"[{role.get('category', '-')}] "
                f"{role.get('name', role_id)} ({role_id}){partial_label}",
                value=role_id,
                checked=fully_assigned,
            )
        )
    return choices


def merge_iam_policy_bindings(
    bindings: list[dict], role_ids: list[str], principals: list[dict]
) -> list[dict]:
    merged = [
        {
            "role": dict(binding["role"]),
            "principals": [dict(principal) for principal in binding["principals"]],
        }
        for binding in bindings
    ]
    by_role = {binding["role"]["id"]: binding for binding in merged}
    for role_id in role_ids:
        binding = by_role.get(role_id)
        if binding is None:
            binding = {
                "role": {"type": "preset", "id": role_id},
                "principals": [],
            }
            merged.append(binding)
            by_role[role_id] = binding
        existing = {
            (principal["type"], principal["id"])
            for principal in binding["principals"]
        }
        for principal in principals:
            key = (principal["type"], principal["id"])
            if key not in existing:
                binding["principals"].append(dict(principal))
                existing.add(key)
    return merged


def build_iam_role_removal_choices(
    roles: list[dict], bindings: list[dict], principals: list[dict]
) -> list[questionary.Choice]:
    selected_principals = {
        (principal["type"], principal["id"]) for principal in principals
    }
    role_assignments: dict[str, set[tuple[object, object]]] = {}
    for binding in bindings:
        role = binding.get("role")
        binding_principals = binding.get("principals")
        if not isinstance(role, dict) or not isinstance(binding_principals, list):
            continue
        role_id = role.get("id")
        if not isinstance(role_id, str):
            continue
        role_assignments[role_id] = {
            (principal.get("type"), principal.get("id"))
            for principal in binding_principals
            if isinstance(principal, dict)
        }
    roles_by_id = {
        str(role["id"]): role for role in roles if isinstance(role, dict) and "id" in role
    }
    choices = []
    for role_id, assigned in role_assignments.items():
        assigned_count = len(selected_principals & assigned)
        if assigned_count == 0:
            continue
        role = roles_by_id.get(role_id, {"id": role_id})
        partial_label = (
            " [一部のみ割当済み]"
            if assigned_count < len(selected_principals)
            else " [全対象に割当済み]"
        )
        choices.append(
            questionary.Choice(
                f"[{role.get('category', '-')}] "
                f"{role.get('name', role_id)} ({role_id}){partial_label}",
                value=role_id,
            )
        )
    return choices


def remove_iam_policy_bindings(
    bindings: list[dict], role_ids: list[str], principals: list[dict]
) -> list[dict]:
    removals = {(principal["type"], principal["id"]) for principal in principals}
    selected_roles = set(role_ids)
    updated = []
    for binding in bindings:
        role = dict(binding["role"])
        binding_principals = [dict(principal) for principal in binding["principals"]]
        if role["id"] in selected_roles:
            binding_principals = [
                principal
                for principal in binding_principals
                if (principal["type"], principal["id"]) not in removals
            ]
        if binding_principals:
            updated.append({"role": role, "principals": binding_principals})
    return updated


def read_iam_policy_for_target(
    profile: Profile, token: str, scope: str, resource_id: str | None
) -> dict:
    if scope == "organization":
        return read_organization_iam_policy(profile, token)
    if scope == "folder":
        return read_folder_iam_policy(profile, token, resource_id or "")
    return read_project_iam_policy(profile, token, resource_id or "")


def update_iam_policy_for_target(
    profile: Profile,
    token: str,
    scope: str,
    resource_id: str | None,
    bindings: list[dict],
) -> dict:
    if scope == "organization":
        return update_organization_iam_policy(profile, token, bindings)
    if scope == "folder":
        return update_folder_iam_policy(profile, token, resource_id or "", bindings)
    return update_project_iam_policy(profile, token, resource_id or "", bindings)


@iam_policy_app.command("add")
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
        profile, token = authenticated(ctx)
        if not organization and folder_id is None and project_id is None:
            scope, resource_id = select_iam_policy_target(profile, token)
        else:
            scope, resource_id = resolve_iam_policy_target(
                organization, folder_id, project_id
            )
        policy = read_iam_policy_for_target(profile, token, scope, resource_id)
        bindings = policy.get("bindings")
        if not isinstance(bindings, list):
            raise CliError("IAM API policy response did not contain a bindings array")

        principal_types = interactive_checkbox(
            "追加するプリンシパル種別を選択してください",
            [
                questionary.Choice("サービスプリンシパル", value="service-principal"),
                questionary.Choice("ユーザ", value="user"),
            ],
        )
        principals: list[dict] = []
        if "service-principal" in principal_types:
            service_principals = collect_pages(
                lambda page: list_service_principals(
                    profile, token, page=page, per_page=100
                )
            )
            selected_ids = interactive_checkbox(
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
            users = collect_pages(
                lambda page: list_users(profile, token, page=page, per_page=100)
            )
            selected_ids = interactive_checkbox(
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
                {"type": "user", "id": principal_id}
                for principal_id in selected_ids
            )

        roles = collect_pages(
            lambda page: list_iam_roles(profile, token, page=page, per_page=100)
        )
        role_ids = interactive_checkbox(
            "割り当てるIAMロールを選択してください",
            build_iam_role_choices(roles, scope, bindings, principals),
        )
        updated_bindings = merge_iam_policy_bindings(bindings, role_ids, principals)
        result = {
            "target": {"type": scope, "id": resource_id},
            "principals": principals,
            "iam_roles": role_ids,
            "bindings": updated_bindings,
        }
        if dry_run:
            print_json({"dry_run": True, "status": "would_update", **result})
            return
        if not interactive_confirm("この内容でIAMポリシーを更新しますか？"):
            print_json({"status": "cancelled", **result})
            return
        response = update_iam_policy_for_target(
            profile, token, scope, resource_id, updated_bindings
        )
        print_json({"status": "updated", "target": result["target"], "policy": response})
    except (CliError, KeyError, TypeError, ValueError) as exc:
        fail(CliError(str(exc)))


@iam_policy_app.command("delete")
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
        profile, token = authenticated(ctx)
        if not organization and folder_id is None and project_id is None:
            scope, resource_id = select_iam_policy_target(profile, token)
        else:
            scope, resource_id = resolve_iam_policy_target(
                organization, folder_id, project_id
            )
        policy = read_iam_policy_for_target(profile, token, scope, resource_id)
        bindings = policy.get("bindings")
        if not isinstance(bindings, list):
            raise CliError("IAM API policy response did not contain a bindings array")
        assigned_principals = {
            (principal.get("type"), principal.get("id"))
            for binding in bindings
            if isinstance(binding, dict)
            for principal in binding.get("principals", [])
            if isinstance(principal, dict)
        }
        type_choices = []
        if any(principal_type == "service-principal" for principal_type, _ in assigned_principals):
            type_choices.append(
                questionary.Choice("サービスプリンシパル", value="service-principal")
            )
        if any(principal_type == "user" for principal_type, _ in assigned_principals):
            type_choices.append(questionary.Choice("ユーザ", value="user"))
        principal_types = interactive_checkbox(
            "削除するプリンシパル種別を選択してください", type_choices
        )

        principals: list[dict] = []
        if "service-principal" in principal_types:
            service_principals = collect_pages(
                lambda page: list_service_principals(
                    profile, token, page=page, per_page=100
                )
            )
            selected_ids = interactive_checkbox(
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
            users = collect_pages(
                lambda page: list_users(profile, token, page=page, per_page=100)
            )
            selected_ids = interactive_checkbox(
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
                {"type": "user", "id": principal_id}
                for principal_id in selected_ids
            )

        roles = collect_pages(
            lambda page: list_iam_roles(profile, token, page=page, per_page=100)
        )
        role_ids = interactive_checkbox(
            "削除するIAMロールを選択してください",
            build_iam_role_removal_choices(roles, bindings, principals),
        )
        updated_bindings = remove_iam_policy_bindings(bindings, role_ids, principals)
        result = {
            "target": {"type": scope, "id": resource_id},
            "principals": principals,
            "iam_roles": role_ids,
            "bindings": updated_bindings,
        }
        if dry_run:
            print_json({"dry_run": True, "status": "would_update", **result})
            return
        if not interactive_confirm("選択したIAMロール割り当てを削除しますか？"):
            print_json({"status": "cancelled", **result})
            return
        response = update_iam_policy_for_target(
            profile, token, scope, resource_id, updated_bindings
        )
        print_json({"status": "updated", "target": result["target"], "policy": response})
    except (CliError, KeyError, TypeError, ValueError) as exc:
        fail(CliError(str(exc)))


@organization_app.command("get")
def get_organization(ctx: typer.Context) -> None:
    """Get the organization."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_organization(profile, token))
    except CliError as exc:
        fail(exc)


@organization_app.command("update")
def update_organization_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name", help="New organization name.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Update the organization name."""
    if dry_run:
        print_json({"dry_run": True, "status": "would_update", "name": name})
        return
    try:
        profile, token = authenticated(ctx)
        print_json(update_organization(profile, token, name))
    except CliError as exc:
        fail(exc)


@service_policy_app.command("status")
def service_policy_status(ctx: typer.Context) -> None:
    """Get whether service policy is enabled."""
    try:
        profile, token = authenticated(ctx)
        print_json(get_service_policy_status(profile, token))
    except CliError as exc:
        fail(exc)


def change_service_policy_state(ctx: typer.Context, action: str, dry_run: bool) -> None:
    if dry_run:
        print_json({"dry_run": True, "status": f"would_{action}"})
        return
    try:
        profile, token = authenticated(ctx)
        if action == "enable":
            enable_service_policy(profile, token)
        else:
            disable_service_policy(profile, token)
        print_json({"status": f"{action}d"})
    except CliError as exc:
        fail(exc)


@service_policy_app.command("enable")
def enable_service_policy_command(
    ctx: typer.Context,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Enable service policy for the organization."""
    change_service_policy_state(ctx, "enable", dry_run)


@service_policy_app.command("disable")
def disable_service_policy_command(
    ctx: typer.Context,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Disable service policy for the organization."""
    change_service_policy_state(ctx, "disable", dry_run)


@service_policy_app.command("templates")
def list_service_policy_templates(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    code: Annotated[str | None, typer.Option("--code")] = None,
    rule_type: Annotated[
        ServicePolicyTemplateType | None, typer.Option("--type")
    ] = None,
) -> None:
    """List available service policy rule templates."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_service_policy_rule_templates(
                profile,
                token,
                page=page,
                per_page=per_page,
                name=name,
                code=code,
                rule_type=None if rule_type is None else rule_type.value,
            )
        )
    except CliError as exc:
        fail(exc)


@service_policy_app.command("list")
def list_service_policy_rules(
    ctx: typer.Context,
    active: Annotated[
        bool | None, typer.Option("--active/--inactive", help="Filter by active state.")
    ] = None,
    rules_dry_run: Annotated[
        bool | None,
        typer.Option("--rules-dry-run/--rules-live", help="Filter by API dry-run state."),
    ] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    code: Annotated[str | None, typer.Option("--code")] = None,
    rule_type: Annotated[ServicePolicyRuleType | None, typer.Option("--type")] = None,
) -> None:
    """List configured organization service policy rules."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_organization_service_policy_rules(
                profile,
                token,
                is_active=active,
                is_dry_run=rules_dry_run,
                name=name,
                code=code,
                rule_type=None if rule_type is None else rule_type.value,
            )
        )
    except CliError as exc:
        fail(exc)


def validate_rule_spec(spec: object, location: str) -> None:
    if not isinstance(spec, dict) or not set(spec) <= {"contents"}:
        raise CliError(f"{location} may contain only a 'contents' array")
    if "contents" not in spec:
        return
    contents = spec["contents"]
    if not isinstance(contents, list):
        raise CliError(f"{location}.contents must be an array")
    for index, content in enumerate(contents):
        content_location = f"{location}.contents[{index}]"
        allowed_keys = {"values", "allow_all", "deny_all", "enforce"}
        if not isinstance(content, dict) or not set(content) <= allowed_keys:
            raise CliError(f"{content_location} contains unsupported fields")
        for key in ("allow_all", "deny_all", "enforce"):
            if key in content and not isinstance(content[key], bool):
                raise CliError(f"{content_location}.{key} must be a boolean")
        if "values" not in content:
            continue
        values = content["values"]
        if not isinstance(values, dict) or not set(values) <= {
            "allowed_values", "denied_values"
        }:
            raise CliError(f"{content_location}.values contains unsupported fields")
        for key, items in values.items():
            if not isinstance(items, list) or not all(
                isinstance(item, str) for item in items
            ):
                raise CliError(f"{content_location}.values.{key} must be an array of strings")


def load_service_policy_rules(path: Path) -> list[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError(f"service policy file not found: {path}") from exc
    except OSError as exc:
        raise CliError(f"could not read service policy file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid service policy JSON in {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"rules"}:
        raise CliError("service policy must be a JSON object containing only 'rules'")
    rules = document["rules"]
    if not isinstance(rules, list):
        raise CliError("service policy 'rules' must be an array")
    normalized = []
    for index, rule in enumerate(rules):
        location = f"rules[{index}]"
        allowed_keys = {"code", "spec", "dry_run_spec", "is_active", "is_dry_run", "name"}
        if not isinstance(rule, dict) or not set(rule) <= allowed_keys:
            raise CliError(f"{location} contains unsupported fields")
        if not isinstance(rule.get("code"), str) or not rule["code"]:
            raise CliError(f"{location}.code must be a non-empty string")
        for key in ("is_active", "is_dry_run"):
            if not isinstance(rule.get(key), bool):
                raise CliError(f"{location}.{key} must be a boolean")
        if "spec" not in rule and "dry_run_spec" not in rule:
            raise CliError(f"{location} must contain 'spec' or 'dry_run_spec'")
        for key in ("spec", "dry_run_spec"):
            if key in rule:
                validate_rule_spec(rule[key], f"{location}.{key}")
        normalized.append({key: value for key, value in rule.items() if key != "name"})
    return normalized


@service_policy_app.command("update")
def update_service_policy_rules(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the rules to update.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Update the service policy rules specified in a JSON document."""
    try:
        rules = load_service_policy_rules(policy_file)
        if dry_run:
            print_json({"dry_run": True, "status": "would_update", "rules": rules})
            return
        profile, token = authenticated(ctx)
        print_json(update_organization_service_policy_rules(profile, token, rules))
    except CliError as exc:
        fail(exc)


def load_json_object(path: Path, label: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError(f"{label} file not found: {path}") from exc
    except OSError as exc:
        raise CliError(f"could not read {label} file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid {label} JSON in {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise CliError(f"{label} must be a JSON object")
    return document


def load_password_policy(path: Path) -> dict:
    policy = load_json_object(path, "password policy")
    required = {
        "min_length",
        "require_uppercase",
        "require_lowercase",
        "require_symbols",
    }
    if set(policy) != required:
        raise CliError(
            "password policy must contain only min_length, require_uppercase, "
            "require_lowercase, and require_symbols"
        )
    min_length = policy["min_length"]
    if (
        not isinstance(min_length, int)
        or isinstance(min_length, bool)
        or not 8 <= min_length <= 64
    ):
        raise CliError("password policy min_length must be an integer from 8 through 64")
    for key in required - {"min_length"}:
        if not isinstance(policy[key], bool):
            raise CliError(f"password policy {key} must be a boolean")
    return policy


def validate_datetime(value: object, location: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise CliError(f"{location} must be an ISO 8601 date-time string or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CliError(f"{location} must be an ISO 8601 date-time string or null") from exc
    if parsed.tzinfo is None:
        raise CliError(f"{location} must include a UTC offset")


def load_auth_conditions(path: Path) -> dict:
    conditions = load_json_object(path, "authentication conditions")
    required = {"ip_restriction", "require_two_factor_auth", "datetime_restriction"}
    if set(conditions) != required:
        raise CliError(
            "authentication conditions must contain only ip_restriction, "
            "require_two_factor_auth, and datetime_restriction"
        )

    restriction = conditions["ip_restriction"]
    if not isinstance(restriction, dict) or restriction.get("mode") not in {
        "allow_all", "allow_list"
    }:
        raise CliError("ip_restriction.mode must be 'allow_all' or 'allow_list'")
    if restriction["mode"] == "allow_all":
        if set(restriction) != {"mode"}:
            raise CliError("allow_all ip_restriction may contain only 'mode'")
    else:
        if set(restriction) != {"mode", "source_network"}:
            raise CliError("allow_list ip_restriction requires only mode and source_network")
        networks = restriction["source_network"]
        if not isinstance(networks, list) or not networks:
            raise CliError("ip_restriction.source_network must be a non-empty array")
        for index, network in enumerate(networks):
            if not isinstance(network, str):
                raise CliError(f"ip_restriction.source_network[{index}] must be an IPv4 CIDR")
            try:
                parsed_network = ipaddress.ip_network(network, strict=False)
            except ValueError as exc:
                raise CliError(
                    f"ip_restriction.source_network[{index}] must be an IPv4 CIDR"
                ) from exc
            if parsed_network.version != 4 or "/" not in network:
                raise CliError(f"ip_restriction.source_network[{index}] must be an IPv4 CIDR")

    two_factor = conditions["require_two_factor_auth"]
    if (
        not isinstance(two_factor, dict)
        or set(two_factor) != {"enabled"}
        or not isinstance(two_factor["enabled"], bool)
    ):
        raise CliError("require_two_factor_auth must contain only a boolean enabled field")

    datetime_restriction = conditions["datetime_restriction"]
    if not isinstance(datetime_restriction, dict) or set(datetime_restriction) != {
        "after", "before"
    }:
        raise CliError("datetime_restriction must contain only after and before")
    validate_datetime(datetime_restriction["after"], "datetime_restriction.after")
    validate_datetime(datetime_restriction["before"], "datetime_restriction.before")
    return conditions


@auth_app.command("context")
def get_auth_context(ctx: typer.Context) -> None:
    """Get the current credential's authentication context."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_auth_context(profile, token))
    except CliError as exc:
        fail(exc)


@auth_app.command("password-policy")
def get_password_policy(ctx: typer.Context) -> None:
    """Get the organization password policy."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_password_policy(profile, token))
    except CliError as exc:
        fail(exc)


@auth_app.command("update-password-policy")
def update_password_policy_command(
    ctx: typer.Context,
    policy_file: Annotated[
        Path, typer.Argument(help="JSON file containing the complete password policy.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the organization password policy."""
    try:
        policy = load_password_policy(policy_file)
        if dry_run:
            print_json({"dry_run": True, "status": "would_update", **policy})
            return
        profile, token = authenticated(ctx)
        print_json(update_password_policy(profile, token, policy))
    except CliError as exc:
        fail(exc)


@auth_app.command("conditions")
def get_auth_conditions(ctx: typer.Context) -> None:
    """Get the organization authentication conditions."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_auth_conditions(profile, token))
    except CliError as exc:
        fail(exc)


@auth_app.command("update-conditions")
def update_auth_conditions_command(
    ctx: typer.Context,
    conditions_file: Annotated[
        Path, typer.Argument(help="JSON file containing all authentication conditions.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace the organization authentication conditions."""
    try:
        conditions = load_auth_conditions(conditions_file)
        if dry_run:
            print_json({"dry_run": True, "status": "would_update", **conditions})
            return
        profile, token = authenticated(ctx)
        print_json(update_auth_conditions(profile, token, conditions))
    except CliError as exc:
        fail(exc)


@project_app.command("list")
def list_project_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[ProjectOrdering | None, typer.Option("--ordering")] = None,
    iam_roles: Annotated[
        list[str] | None,
        typer.Option("--iam-role", help="Filter by an IAM role; may be repeated."),
    ] = None,
    parent_folder_id: Annotated[str | None, typer.Option("--parent-folder-id")] = None,
) -> None:
    """List projects."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_projects(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
                iam_roles=iam_roles,
                parent_folder_id=parent_folder_id,
            )
        )
    except CliError as exc:
        fail(exc)


@project_app.command("create")
def create_project_resource(
    ctx: typer.Context,
    code: Annotated[str, typer.Option("--code", max=64)],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    parent_folder_id: Annotated[str | None, typer.Option("--parent-folder-id")] = None,
) -> None:
    """Create a project."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            create_project(
                profile, token, code, name, description, parent_folder_id
            )
        )
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@project_app.command("get")
def get_project_resource(
    ctx: typer.Context,
    project_id: Annotated[str, typer.Argument(help="Project ID.")],
) -> None:
    """Get a project."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_project(profile, token, project_id))
    except CliError as exc:
        fail(exc)


@project_app.command("update")
def update_project_resource(
    ctx: typer.Context,
    project_id: Annotated[str, typer.Argument(help="Project ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Update a project."""
    try:
        profile, token = authenticated(ctx)
        print_json(update_project(profile, token, project_id, name, description))
    except CliError as exc:
        fail(exc)


@project_app.command("delete")
def delete_project_resource(
    ctx: typer.Context,
    project_id: Annotated[str, typer.Argument(help="Project ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a project."""
    if dry_run:
        print_json({"dry_run": True, "project_id": project_id, "status": "would_delete"})
        return
    try:
        profile, token = authenticated(ctx)
        delete_project(profile, token, project_id)
        print_json({"project_id": project_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@project_app.command("move")
def move_project_resources(
    ctx: typer.Context,
    project_ids: Annotated[
        list[str], typer.Option("--project-id", help="Project ID; may be repeated.")
    ],
    parent_folder_id: Annotated[
        str | None, typer.Option("--parent-folder-id", help="Destination folder ID.")
    ] = None,
    to_root: Annotated[
        bool, typer.Option("--to-root", help="Move projects out of a folder.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Move one or more projects to a folder or the root."""
    try:
        if (parent_folder_id is None) == (not to_root):
            raise CliError("specify exactly one of --parent-folder-id or --to-root")
        target = None if to_root else parent_folder_id
        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "project_ids": project_ids,
                    "parent_folder_id": target,
                    "status": "would_move",
                }
            )
            return
        profile, token = authenticated(ctx)
        move_projects(profile, token, project_ids, target)
        print_json(
            {"project_ids": project_ids, "parent_folder_id": target, "status": "moved"}
        )
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@folder_app.command("list")
def list_folder_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    folder_name: Annotated[str | None, typer.Option("--folder-name")] = None,
    parent_id: Annotated[str | None, typer.Option("--parent-id")] = None,
) -> None:
    """List folders."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_folders(
                profile,
                token,
                page=page,
                per_page=per_page,
                folder_name=folder_name,
                parent_id=parent_id,
            )
        )
    except CliError as exc:
        fail(exc)


@folder_app.command("create")
def create_folder_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    parent_id: Annotated[str | None, typer.Option("--parent-id")] = None,
) -> None:
    """Create a folder."""
    try:
        profile, token = authenticated(ctx)
        print_json(create_folder(profile, token, name, description, parent_id))
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@folder_app.command("get")
def get_folder_resource(
    ctx: typer.Context,
    folder_id: Annotated[str, typer.Argument(help="Folder ID.")],
) -> None:
    """Get a folder."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_folder(profile, token, folder_id))
    except CliError as exc:
        fail(exc)


@folder_app.command("update")
def update_folder_resource(
    ctx: typer.Context,
    folder_id: Annotated[str, typer.Argument(help="Folder ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Update a folder."""
    try:
        profile, token = authenticated(ctx)
        print_json(update_folder(profile, token, folder_id, name, description))
    except CliError as exc:
        fail(exc)


@folder_app.command("delete")
def delete_folder_resource(
    ctx: typer.Context,
    folder_id: Annotated[str, typer.Argument(help="Folder ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete an empty folder."""
    if dry_run:
        print_json({"dry_run": True, "folder_id": folder_id, "status": "would_delete"})
        return
    try:
        profile, token = authenticated(ctx)
        delete_folder(profile, token, folder_id)
        print_json({"folder_id": folder_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@folder_app.command("move")
def move_folder_resources(
    ctx: typer.Context,
    folder_ids: Annotated[
        list[str], typer.Option("--folder-id", help="Folder ID; may be repeated.")
    ],
    parent_id: Annotated[
        str | None, typer.Option("--parent-id", help="Destination parent folder ID.")
    ] = None,
    to_root: Annotated[
        bool, typer.Option("--to-root", help="Move folders to the root.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Move one or more folders to another folder or the root."""
    try:
        if (parent_id is None) == (not to_root):
            raise CliError("specify exactly one of --parent-id or --to-root")
        target = None if to_root else parent_id
        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "folder_ids": folder_ids,
                    "parent_id": target,
                    "status": "would_move",
                }
            )
            return
        profile, token = authenticated(ctx)
        move_folders(profile, token, folder_ids, target)
        print_json({"folder_ids": folder_ids, "parent_id": target, "status": "moved"})
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@group_app.command("list")
def list_group_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[GroupOrdering | None, typer.Option("--ordering")] = None,
    user_id: Annotated[
        str | None, typer.Option("--user-id", help="Filter by a member user ID.")
    ] = None,
) -> None:
    """List groups."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_groups(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
                user_id=user_id,
            )
        )
    except CliError as exc:
        fail(exc)


@group_app.command("create")
def create_group_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Create a group."""
    try:
        profile, token = authenticated(ctx)
        print_json(create_group(profile, token, name, description))
    except CliError as exc:
        fail(exc)


@group_app.command("get")
def get_group_resource(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
) -> None:
    """Get a group."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_group(profile, token, group_id))
    except CliError as exc:
        fail(exc)


@group_app.command("update")
def update_group_resource(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
) -> None:
    """Update a group."""
    try:
        profile, token = authenticated(ctx)
        print_json(update_group(profile, token, group_id, name, description))
    except CliError as exc:
        fail(exc)


@group_app.command("delete")
def delete_group_resource(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a group."""
    if dry_run:
        print_json({"dry_run": True, "group_id": group_id, "status": "would_delete"})
        return
    try:
        profile, token = authenticated(ctx)
        delete_group(profile, token, group_id)
        print_json({"group_id": group_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@group_app.command("members")
def list_group_members(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
) -> None:
    """List a group's user memberships."""
    try:
        profile, token = authenticated(ctx)
        print_json(list_group_memberships(profile, token, group_id))
    except CliError as exc:
        fail(exc)


@group_app.command("set-members")
def set_group_members(
    ctx: typer.Context,
    group_id: Annotated[str, typer.Argument(help="Group ID.")],
    user_ids: Annotated[
        list[str] | None,
        typer.Option("--user-id", help="Complete member list; may be repeated."),
    ] = None,
    clear: Annotated[
        bool, typer.Option("--clear", help="Remove every user from the group.")
    ] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Replace all user memberships in a group."""
    try:
        if clear and user_ids:
            raise CliError("--clear cannot be combined with --user-id")
        if not clear and not user_ids:
            raise CliError("specify at least one --user-id, or use --clear")
        members = [] if clear else user_ids or []
        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "group_id": group_id,
                    "user_ids": members,
                    "status": "would_replace_members",
                }
            )
            return
        profile, token = authenticated(ctx)
        print_json(update_group_memberships(profile, token, group_id, members))
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


def read_password(password_file: Path | None, *, required: bool) -> str | None:
    if password_file is None:
        if not required:
            return None
        value = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    else:
        try:
            value = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise CliError(f"could not read password file {password_file}: {exc}") from exc
    if not value:
        raise CliError("password must not be empty")
    return value


@provisioning_app.command("list")
def list_provisioning_configurations(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
) -> None:
    """List SCIM user provisioning configurations."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_scim_configurations(
                profile, token, page=page, per_page=per_page
            )
        )
    except CliError as exc:
        fail(exc)


@provisioning_app.command("create")
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
        profile, token = authenticated(ctx)
        response = create_scim_configuration(profile, token, name)
        if output is None:
            print_json(response)
        else:
            write_sensitive_json(output, response)
            print_json({"id": response.get("id"), "saved_to": str(output)})
    except CliError as exc:
        fail(exc)


@provisioning_app.command("get")
def get_provisioning_configuration(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
) -> None:
    """Get one user provisioning configuration without its secret token."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_scim_configuration(profile, token, configuration_id))
    except CliError as exc:
        fail(exc)


@provisioning_app.command("update")
def update_provisioning_configuration(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
    name: Annotated[str, typer.Option("--name")],
) -> None:
    """Rename a user provisioning configuration."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            update_scim_configuration(profile, token, configuration_id, name)
        )
    except CliError as exc:
        fail(exc)


@provisioning_app.command("delete")
def delete_provisioning_configuration(
    ctx: typer.Context,
    configuration_id: Annotated[
        str, typer.Argument(help="User provisioning configuration ID.")
    ],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a user provisioning configuration."""
    if dry_run:
        print_json(
            {
                "dry_run": True,
                "id": configuration_id,
                "status": "would_delete",
            }
        )
        return
    try:
        profile, token = authenticated(ctx)
        delete_scim_configuration(profile, token, configuration_id)
        print_json({"id": configuration_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@provisioning_app.command("regenerate-token")
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
        print_json(
            {
                "dry_run": True,
                "id": configuration_id,
                "status": "would_regenerate_token",
            }
        )
        return
    try:
        profile, token = authenticated(ctx)
        response = regenerate_scim_configuration_token(
            profile, token, configuration_id
        )
        if output is None:
            print_json(response)
        else:
            write_sensitive_json(output, response)
            print_json({"id": configuration_id, "saved_to": str(output)})
    except CliError as exc:
        fail(exc)


@user_app.command("list")
def list_user_resources(
    ctx: typer.Context,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[UserOrdering | None, typer.Option("--ordering")] = None,
) -> None:
    """List users."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_users(
                profile,
                token,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except CliError as exc:
        fail(exc)


@user_app.command("create")
def create_user_resource(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    code: Annotated[str, typer.Option("--code")],
    description: Annotated[str, typer.Option("--description")] = "",
    email: Annotated[str | None, typer.Option("--email")] = None,
    password_file: Annotated[
        Path | None, typer.Option("--password-file", help="Read the password from a file.")
    ] = None,
) -> None:
    """Create a user; prompts for a password unless --password-file is used."""
    try:
        password = read_password(password_file, required=True)
        profile, token = authenticated(ctx)
        print_json(create_user(profile, token, name, code, password or "", description, email))
    except CliError as exc:
        fail(exc)


@user_app.command("get")
def get_user_resource(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
) -> None:
    """Get a user."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_user(profile, token, user_id))
    except CliError as exc:
        fail(exc)


@user_app.command("update")
def update_user_resource(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    password_file: Annotated[
        Path | None, typer.Option("--password-file", help="Also replace the password from a file.")
    ] = None,
) -> None:
    """Update a user and optionally replace the password."""
    try:
        password = read_password(password_file, required=False)
        profile, token = authenticated(ctx)
        print_json(update_user(profile, token, user_id, name, description, password))
    except CliError as exc:
        fail(exc)


@user_app.command("delete")
def delete_user_resource(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a user."""
    if dry_run:
        print_json({"dry_run": True, "user_id": user_id, "status": "would_delete"})
        return
    try:
        profile, token = authenticated(ctx)
        delete_user(profile, token, user_id)
        print_json({"user_id": user_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@user_app.command("register-email")
def register_email(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    email: Annotated[str, typer.Option("--email")],
) -> None:
    """Register an email address for a user."""
    try:
        profile, token = authenticated(ctx)
        register_user_email(profile, token, user_id, email)
        print_json({"user_id": user_id, "email": email, "status": "registered"})
    except CliError as exc:
        fail(exc)


@user_app.command("unregister-email")
def unregister_email(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Unregister a user's email address."""
    if dry_run:
        print_json({"dry_run": True, "user_id": user_id, "status": "would_unregister_email"})
        return
    try:
        profile, token = authenticated(ctx)
        unregister_user_email(profile, token, user_id)
        print_json({"user_id": user_id, "status": "email_unregistered"})
    except CliError as exc:
        fail(exc)


def run_user_destructive_action(
    ctx: typer.Context,
    user_id: str,
    status: str,
    dry_run: bool,
    action,
) -> None:
    if dry_run:
        print_json({"dry_run": True, "user_id": user_id, "status": f"would_{status}"})
        return
    try:
        profile, token = authenticated(ctx)
        action(profile, token)
        print_json({"user_id": user_id, "status": status})
    except CliError as exc:
        fail(exc)


@user_app.command("deactivate-otp")
def deactivate_otp(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Deactivate OTP authentication for a user."""
    run_user_destructive_action(
        ctx, user_id, "otp_deactivated", dry_run,
        lambda profile, token: deactivate_user_otp(profile, token, user_id),
    )


@user_app.command("trusted-devices")
def trusted_devices(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
) -> None:
    """List a user's trusted devices."""
    try:
        profile, token = authenticated(ctx)
        print_json(list_trusted_devices(profile, token, user_id))
    except CliError as exc:
        fail(exc)


@user_app.command("delete-trusted-device")
def remove_trusted_device(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    trusted_device_id: Annotated[str, typer.Argument(help="Trusted device ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete one trusted device."""
    run_user_destructive_action(
        ctx, user_id, "trusted_device_deleted", dry_run,
        lambda profile, token: delete_trusted_device(
            profile, token, user_id, trusted_device_id
        ),
    )


@user_app.command("clear-trusted-devices")
def clear_user_trusted_devices(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete every trusted device for a user."""
    run_user_destructive_action(
        ctx, user_id, "trusted_devices_cleared", dry_run,
        lambda profile, token: clear_trusted_devices(profile, token, user_id),
    )


@user_app.command("security-keys")
def security_keys(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
) -> None:
    """List a user's WebAuthn security keys."""
    try:
        profile, token = authenticated(ctx)
        print_json(list_security_keys(profile, token, user_id))
    except CliError as exc:
        fail(exc)


@user_app.command("get-security-key")
def get_security_key(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    security_key_id: Annotated[str, typer.Argument(help="Security key ID.")],
) -> None:
    """Get one WebAuthn security key."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_security_key(profile, token, user_id, security_key_id))
    except CliError as exc:
        fail(exc)


@user_app.command("delete-security-key")
def remove_security_key(
    ctx: typer.Context,
    user_id: Annotated[str, typer.Argument(help="User ID.")],
    security_key_id: Annotated[str, typer.Argument(help="Security key ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete one WebAuthn security key."""
    run_user_destructive_action(
        ctx, user_id, "security_key_deleted", dry_run,
        lambda profile, token: delete_security_key(
            profile, token, user_id, security_key_id
        ),
    )


@api_key_app.command("create")
def create_api_key(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    iam_roles: Annotated[list[str], typer.Option("--iam-role", help="Repeat for each IAM role.")],
    description: Annotated[str, typer.Option("--description")] = "",
    project_id: Annotated[
        str | None, typer.Option("--project-id", help="Defaults to the profile project_id.")
    ] = None,
    server_resource_id: Annotated[str | None, typer.Option("--server-resource-id")] = None,
    zone_id: Annotated[str | None, typer.Option("--zone-id")] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Save the response containing the secret as mode 0600.")
    ] = None,
) -> None:
    """Create a project API key. The secret is returned only at creation."""
    try:
        validate_single_server_options(server_resource_id, zone_id)
        profile, token = authenticated(ctx)
        response = create_project_api_key(
            profile,
            token,
            project_id or profile.project_id,
            name,
            description,
            iam_roles,
            server_resource_id,
            zone_id,
        )
        if output is None:
            print_json(response)
        else:
            write_sensitive_json(output, response)
            print_json({"id": response.get("id"), "saved_to": str(output)})
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@api_key_app.command("get")
def get_api_key(
    ctx: typer.Context,
    api_key_id: Annotated[str, typer.Argument(help="Project API key ID.")],
) -> None:
    """Get a project API key (the secret is not returned)."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_project_api_key(profile, token, api_key_id))
    except CliError as exc:
        fail(exc)


@api_key_app.command("update")
def update_api_key(
    ctx: typer.Context,
    api_key_id: Annotated[str, typer.Argument(help="Project API key ID.")],
    name: Annotated[str, typer.Option("--name")],
    iam_roles: Annotated[list[str], typer.Option("--iam-role", help="Repeat for each IAM role.")],
    description: Annotated[str, typer.Option("--description")] = "",
    server_resource_id: Annotated[str | None, typer.Option("--server-resource-id")] = None,
    zone_id: Annotated[str | None, typer.Option("--zone-id")] = None,
) -> None:
    """Update a project API key."""
    try:
        validate_single_server_options(server_resource_id, zone_id)
        profile, token = authenticated(ctx)
        print_json(
            update_project_api_key(
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
    except CliError as exc:
        fail(exc)


@api_key_app.command("delete")
def delete_api_key(
    ctx: typer.Context,
    api_key_id: Annotated[str, typer.Argument(help="Project API key ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a project API key."""
    if dry_run:
        print_json({"dry_run": True, "id": api_key_id, "status": "would_delete"})
        return
    try:
        profile, token = authenticated(ctx)
        delete_project_api_key(profile, token, api_key_id)
        print_json({"id": api_key_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@sp_app.command("list")
def list_principals(
    ctx: typer.Context,
    project_id: Annotated[str | None, typer.Option("--project-id")] = None,
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[ServicePrincipalOrdering | None, typer.Option("--ordering")] = None,
) -> None:
    """List service principals."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            list_service_principals(
                profile,
                token,
                page=page,
                per_page=per_page,
                project_id=project_id,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except CliError as exc:
        fail(exc)


@sp_app.command("create")
def create_principal(
    ctx: typer.Context,
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str, typer.Option("--description")] = "",
    project_id: Annotated[
        str | None, typer.Option("--project-id", help="Defaults to the profile project_id.")
    ] = None,
) -> None:
    """Create a service principal."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            create_service_principal(
                profile, token, project_id or profile.project_id, name, description
            )
        )
    except (CliError, ValueError) as exc:
        fail(CliError(str(exc)))


@sp_app.command("get")
def get_principal(
    ctx: typer.Context,
    service_principal_id: Annotated[str, typer.Argument(help="Service principal ID.")],
) -> None:
    """Get a service principal."""
    try:
        profile, token = authenticated(ctx)
        print_json(read_service_principal(profile, token, service_principal_id))
    except CliError as exc:
        fail(exc)


@sp_app.command("update")
def update_principal(
    ctx: typer.Context,
    service_principal_id: Annotated[str, typer.Argument(help="Service principal ID.")],
    name: Annotated[str, typer.Option("--name")],
    description: Annotated[str | None, typer.Option("--description")] = None,
) -> None:
    """Update a service principal."""
    try:
        profile, token = authenticated(ctx)
        print_json(
            update_service_principal(
                profile, token, service_principal_id, name, description
            )
        )
    except CliError as exc:
        fail(exc)


@sp_app.command("delete")
def delete_principal(
    ctx: typer.Context,
    service_principal_id: Annotated[str, typer.Argument(help="Service principal ID.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
) -> None:
    """Delete a service principal."""
    if dry_run:
        print_json(
            {"dry_run": True, "service_principal_id": service_principal_id, "status": "would_delete"}
        )
        return
    try:
        profile, token = authenticated(ctx)
        delete_service_principal(profile, token, service_principal_id)
        print_json({"service_principal_id": service_principal_id, "status": "deleted"})
    except CliError as exc:
        fail(exc)


@sp_app.command("token")
def token(ctx: typer.Context) -> None:
    """Issue and print an access token for the configured service principal."""
    try:
        profile, access_token = authenticated(ctx)
        print_json({"service_principal_id": profile.service_principal_id, "access_token": access_token})
    except CliError as exc:
        fail(exc)


@sp_key_app.command("list")
def list_keys(
    ctx: typer.Context,
    service_principal_id: Annotated[
        str, typer.Option("--service-principal-id", help="Target service principal ID.")
    ],
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[ServicePrincipalKeyOrdering | None, typer.Option("--ordering")] = None,
) -> None:
    """List keys registered to a service principal."""
    try:
        profile, access_token = authenticated(ctx)
        print_json(
            list_service_principal_keys(
                profile,
                access_token,
                service_principal_id,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except CliError as exc:
        fail(exc)


@sp_key_app.command("create")
def create_keys(
    output_key_dir: Annotated[
        Path, typer.Option("--output-key-dir", help="Directory in which to create key pairs.")
    ],
    num: Annotated[int, typer.Option("--num", min=1)] = 1,
    bits: Annotated[int, typer.Option("--bits")] = 2048,
) -> None:
    """Generate local RSA key pairs."""
    try:
        keys = generate_key_pairs(output_key_dir, num, bits)
    except CliError as exc:
        fail(exc)
    print_json({"created": len(keys), "output_key_dir": str(output_key_dir)})


@sp_key_app.command("upload-key")
def upload_keys(
    ctx: typer.Context,
    service_principal_id: Annotated[
        str, typer.Option("--service-principal-id", help="Target service principal ID.")
    ],
    key_dir: Annotated[
        Path, typer.Option("--key-dir", help="Directory containing *.public.pem files.")
    ],
    continue_on_error: Annotated[
        bool, typer.Option("--continue-on-error", help="Continue after an upload failure.")
    ] = False,
) -> None:
    """Upload generated public keys to a service principal."""
    try:
        config: AppContext = ctx.obj
        profile = load_profile(config.settings, config.profile_name)
        public_keys = sorted(key_dir.glob("*.public.pem"))
        if not public_keys:
            raise CliError(f"no *.public.pem files found in {key_dir}")
        token = issue_access_token(profile)
    except CliError as exc:
        fail(exc)

    results = []
    failures = 0
    for path in public_keys:
        try:
            response = upload_public_key(profile, token, path, service_principal_id)
            result = {
                "file": path.name,
                "target_service_principal_id": service_principal_id,
                "status": "uploaded",
                **response,
            }
            path.with_suffix(".json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            results.append(result)
        except CliError as exc:
            failures += 1
            results.append({"file": path.name, "status": "failed", "error": str(exc)})
            if not continue_on_error:
                break
    print_json({"results": results})
    if failures:
        raise typer.Exit(1)


@sp_key_app.command("delete")
def delete_keys(
    ctx: typer.Context,
    key_dir: Annotated[
        Path, typer.Option("--key-dir", help="Directory containing *.public.json records.")
    ],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show keys without deleting them.")
    ] = False,
    continue_on_error: Annotated[
        bool, typer.Option("--continue-on-error", help="Continue after a deletion failure.")
    ] = False,
) -> None:
    """Delete uploaded keys recorded in a key directory."""
    try:
        records = [
            item for item in load_key_records(key_dir) if item[1].get("status") != "deleted"
        ]
        if not records:
            print_json({"deleted": 0, "message": "all recorded keys are already deleted"})
            return

        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "results": [
                        {
                            "file": path.name,
                            "service_principal_id": str(record["target_service_principal_id"]),
                            "id": str(record["id"]),
                            "status": "would_delete",
                        }
                        for path, record in records
                    ],
                }
            )
            return

        config: AppContext = ctx.obj
        profile = load_profile(config.settings, config.profile_name)
        token = issue_access_token(profile)
    except CliError as exc:
        fail(exc)

    results = []
    failures = 0
    for path, record in records:
        key_id = str(record["id"])
        target_service_principal_id = str(record["target_service_principal_id"])
        try:
            delete_service_principal_key(
                profile, token, target_service_principal_id, key_id
            )
            record["status"] = "deleted"
            path.write_text(
                json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            results.append(
                {
                    "file": path.name,
                    "service_principal_id": target_service_principal_id,
                    "id": key_id,
                    "status": "deleted",
                }
            )
        except CliError as exc:
            failures += 1
            results.append(
                {"file": path.name, "id": key_id, "status": "failed", "error": str(exc)}
            )
            if not continue_on_error:
                break
    print_json({"results": results})
    if failures:
        raise typer.Exit(1)


def change_keys_state(
    ctx: typer.Context,
    key_dir: Path,
    action: str,
    dry_run: bool,
    continue_on_error: bool,
) -> None:
    desired_status = "enabled" if action == "enable" else "disabled"
    try:
        records = [
            item
            for item in load_key_records(key_dir)
            if item[1].get("status") not in ("deleted", desired_status)
        ]
        if not records:
            print_json({"updated": 0, "message": f"all recorded keys are already {desired_status}"})
            return
        if dry_run:
            print_json(
                {
                    "dry_run": True,
                    "results": [
                        {
                            "file": path.name,
                            "service_principal_id": str(record["target_service_principal_id"]),
                            "id": str(record["id"]),
                            "status": f"would_{action}",
                        }
                        for path, record in records
                    ],
                }
            )
            return
        config: AppContext = ctx.obj
        profile = load_profile(config.settings, config.profile_name)
        token = issue_access_token(profile)
    except CliError as exc:
        fail(exc)

    results = []
    failures = 0
    for path, record in records:
        key_id = str(record["id"])
        target_id = str(record["target_service_principal_id"])
        try:
            response = change_service_principal_key_state(
                profile, token, target_id, key_id, action
            )
            record.update(response)
            record["status"] = desired_status
            record["target_service_principal_id"] = target_id
            path.write_text(
                json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )
            results.append(
                {
                    "file": path.name,
                    "service_principal_id": target_id,
                    "id": key_id,
                    "status": desired_status,
                }
            )
        except CliError as exc:
            failures += 1
            results.append(
                {"file": path.name, "id": key_id, "status": "failed", "error": str(exc)}
            )
            if not continue_on_error:
                break
    print_json({"results": results})
    if failures:
        raise typer.Exit(1)


@sp_key_app.command("enable")
def enable_keys(
    ctx: typer.Context,
    key_dir: Annotated[Path, typer.Option("--key-dir", help="Key record directory.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    continue_on_error: Annotated[bool, typer.Option("--continue-on-error")] = False,
) -> None:
    """Enable uploaded keys recorded in a key directory."""
    change_keys_state(ctx, key_dir, "enable", dry_run, continue_on_error)


@sp_key_app.command("disable")
def disable_keys(
    ctx: typer.Context,
    key_dir: Annotated[Path, typer.Option("--key-dir", help="Key record directory.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    continue_on_error: Annotated[bool, typer.Option("--continue-on-error")] = False,
) -> None:
    """Disable uploaded keys recorded in a key directory."""
    change_keys_state(ctx, key_dir, "disable", dry_run, continue_on_error)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
