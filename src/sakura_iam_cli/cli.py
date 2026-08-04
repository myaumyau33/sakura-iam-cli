from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from .core import (
    CliError,
    Profile,
    change_service_principal_key_state,
    create_project_api_key,
    create_project,
    create_folder,
    create_group,
    create_user,
    create_service_principal,
    delete_service_principal,
    delete_project_api_key,
    delete_project,
    delete_folder,
    delete_group,
    delete_user,
    delete_security_key,
    delete_trusted_device,
    deactivate_user_otp,
    clear_trusted_devices,
    delete_service_principal_key,
    generate_key_pairs,
    issue_access_token,
    list_service_principal_keys,
    list_service_principals,
    list_project_api_keys,
    list_projects,
    list_folders,
    list_groups,
    list_group_memberships,
    list_users,
    list_security_keys,
    list_trusted_devices,
    list_iam_roles,
    load_profile,
    move_projects,
    move_folders,
    read_service_principal,
    read_project_api_key,
    read_project,
    read_folder,
    read_group,
    read_user,
    read_security_key,
    register_user_email,
    unregister_user_email,
    read_iam_role,
    update_service_principal,
    update_project_api_key,
    update_project,
    update_folder,
    update_group,
    update_group_memberships,
    update_user,
    upload_public_key,
)
from .resources import Resource, ResourceTree


app = typer.Typer(help="A CLI wrapper for the Sakura Cloud IAM API.", no_args_is_help=True)
sp_key_app = typer.Typer(help="Manage service principal keys.", no_args_is_help=True)
sp_app = typer.Typer(help="Manage service principals.", no_args_is_help=True)
api_key_app = typer.Typer(help="Manage project API keys.", no_args_is_help=True)
iam_role_app = typer.Typer(help="Inspect IAM roles.", no_args_is_help=True)
project_app = typer.Typer(help="Manage projects.", no_args_is_help=True)
folder_app = typer.Typer(help="Manage folders.", no_args_is_help=True)
group_app = typer.Typer(help="Manage groups and memberships.", no_args_is_help=True)
user_app = typer.Typer(help="Manage users and user authentication devices.", no_args_is_help=True)
resource_app = typer.Typer(help="Browse and move folders and projects by path.", no_args_is_help=True)
app.add_typer(sp_key_app, name="sp-key")
app.add_typer(sp_app, name="sp")
app.add_typer(api_key_app, name="api-key")
app.add_typer(iam_role_app, name="iam-role")
app.add_typer(project_app, name="project")
app.add_typer(folder_app, name="folder")
app.add_typer(group_app, name="group")
app.add_typer(user_app, name="user")
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
