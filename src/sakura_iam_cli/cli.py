from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

import typer

from .core import (
    CliError,
    change_service_principal_key_state,
    delete_service_principal_key,
    generate_key_pairs,
    issue_access_token,
    load_profile,
    upload_public_key,
)


app = typer.Typer(help="A CLI wrapper for the Sakura Cloud IAM API.", no_args_is_help=True)
sp_key_app = typer.Typer(help="Manage service principal keys.", no_args_is_help=True)
app.add_typer(sp_key_app, name="sp-key")

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
