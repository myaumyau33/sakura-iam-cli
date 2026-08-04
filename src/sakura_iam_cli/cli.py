from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from .core import (
    CliError,
    Profile,
    change_service_principal_key_state,
    create_service_principal,
    delete_service_principal,
    delete_service_principal_key,
    generate_key_pairs,
    issue_access_token,
    list_service_principal_keys,
    list_service_principals,
    load_profile,
    read_service_principal,
    update_service_principal,
    upload_public_key,
)


app = typer.Typer(help="A CLI wrapper for the Sakura Cloud IAM API.", no_args_is_help=True)
sp_key_app = typer.Typer(help="Manage service principal keys.", no_args_is_help=True)
sp_app = typer.Typer(help="Manage service principals.", no_args_is_help=True)
app.add_typer(sp_key_app, name="sp-key")
app.add_typer(sp_app, name="sp")

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
