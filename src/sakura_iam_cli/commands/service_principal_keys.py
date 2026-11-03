from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import apps, common, key_files, options


@apps.sp_key_app.command("list")
def list_keys(
    ctx: typer.Context,
    service_principal_id: Annotated[
        str, typer.Option("--service-principal-id", help="Target service principal ID.")
    ],
    page: Annotated[int | None, typer.Option("--page", min=1)] = None,
    per_page: Annotated[int | None, typer.Option("--per-page", min=1)] = None,
    ordering: Annotated[
        options.ServicePrincipalKeyOrdering | None, typer.Option("--ordering")
    ] = None,
) -> None:
    """List keys registered to a service principal."""
    try:
        profile, access_token = common.authenticated(ctx)
        common.print_json(
            core.list_service_principal_keys(
                profile,
                access_token,
                service_principal_id,
                page=page,
                per_page=per_page,
                ordering=None if ordering is None else ordering.value,
            )
        )
    except core.CliError as exc:
        common.fail(exc)


@apps.sp_key_app.command("create")
def create_keys(
    output_key_dir: Annotated[
        Path,
        typer.Option(
            "--output-key-dir", help="Directory in which to create key pairs."
        ),
    ],
    num: Annotated[int, typer.Option("--num", min=1)] = 1,
    bits: Annotated[int, typer.Option("--bits")] = 2048,
) -> None:
    """Generate local RSA key pairs."""
    try:
        keys = core.generate_key_pairs(output_key_dir, num, bits)
    except core.CliError as exc:
        common.fail(exc)
    common.print_json({"created": len(keys), "output_key_dir": str(output_key_dir)})


@apps.sp_key_app.command("upload-key")
def upload_keys(
    ctx: typer.Context,
    service_principal_id: Annotated[
        str, typer.Option("--service-principal-id", help="Target service principal ID.")
    ],
    key_dir: Annotated[
        Path, typer.Option("--key-dir", help="Directory containing *.public.pem files.")
    ],
    continue_on_error: Annotated[
        bool,
        typer.Option("--continue-on-error", help="Continue after an upload failure."),
    ] = False,
) -> None:
    """Upload generated public keys to a service principal."""
    try:
        config: options.AppContext = ctx.obj
        profile = core.load_profile(config.settings, config.profile_name)
        public_keys = sorted(key_dir.glob("*.public.pem"))
        if not public_keys:
            raise core.CliError(f"no *.public.pem files found in {key_dir}")
        token = core.issue_access_token(profile)
    except core.CliError as exc:
        common.fail(exc)

    results = []
    failures = 0
    for path in public_keys:
        try:
            response = core.upload_public_key(
                profile, token, path, service_principal_id
            )
            result = {
                "file": path.name,
                "target_service_principal_id": service_principal_id,
                "status": "uploaded",
                **response,
            }
            path.with_suffix(".json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            results.append(result)
        except core.CliError as exc:
            failures += 1
            results.append({"file": path.name, "status": "failed", "error": str(exc)})
            if not continue_on_error:
                break
    common.print_json({"results": results})
    if failures:
        raise typer.Exit(1)


@apps.sp_key_app.command("delete")
def delete_keys(
    ctx: typer.Context,
    key_dir: Annotated[
        Path,
        typer.Option("--key-dir", help="Directory containing *.public.json records."),
    ],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show keys without deleting them.")
    ] = False,
    continue_on_error: Annotated[
        bool,
        typer.Option("--continue-on-error", help="Continue after a deletion failure."),
    ] = False,
) -> None:
    """Delete uploaded keys recorded in a key directory."""
    try:
        records = [
            item
            for item in key_files.load_key_records(key_dir)
            if item[1].get("status") != "deleted"
        ]
        if not records:
            common.print_json(
                {"deleted": 0, "message": "all recorded keys are already deleted"}
            )
            return

        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "results": [
                        {
                            "file": path.name,
                            "service_principal_id": str(
                                record["target_service_principal_id"]
                            ),
                            "id": str(record["id"]),
                            "status": "would_delete",
                        }
                        for path, record in records
                    ],
                }
            )
            return

        config: options.AppContext = ctx.obj
        profile = core.load_profile(config.settings, config.profile_name)
        token = core.issue_access_token(profile)
    except core.CliError as exc:
        common.fail(exc)

    results = []
    failures = 0
    for path, record in records:
        key_id = str(record["id"])
        target_service_principal_id = str(record["target_service_principal_id"])
        try:
            core.delete_service_principal_key(
                profile, token, target_service_principal_id, key_id
            )
            record["status"] = "deleted"
            path.write_text(
                json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            results.append(
                {
                    "file": path.name,
                    "service_principal_id": target_service_principal_id,
                    "id": key_id,
                    "status": "deleted",
                }
            )
        except core.CliError as exc:
            failures += 1
            results.append(
                {"file": path.name, "id": key_id, "status": "failed", "error": str(exc)}
            )
            if not continue_on_error:
                break
    common.print_json({"results": results})
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
            for item in key_files.load_key_records(key_dir)
            if item[1].get("status") not in ("deleted", desired_status)
        ]
        if not records:
            common.print_json(
                {
                    "updated": 0,
                    "message": f"all recorded keys are already {desired_status}",
                }
            )
            return
        if dry_run:
            common.print_json(
                {
                    "dry_run": True,
                    "results": [
                        {
                            "file": path.name,
                            "service_principal_id": str(
                                record["target_service_principal_id"]
                            ),
                            "id": str(record["id"]),
                            "status": f"would_{action}",
                        }
                        for path, record in records
                    ],
                }
            )
            return
        config: options.AppContext = ctx.obj
        profile = core.load_profile(config.settings, config.profile_name)
        token = core.issue_access_token(profile)
    except core.CliError as exc:
        common.fail(exc)

    results = []
    failures = 0
    for path, record in records:
        key_id = str(record["id"])
        target_id = str(record["target_service_principal_id"])
        try:
            response = core.change_service_principal_key_state(
                profile, token, target_id, key_id, action
            )
            record.update(response)
            record["status"] = desired_status
            record["target_service_principal_id"] = target_id
            path.write_text(
                json.dumps(record, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            results.append(
                {
                    "file": path.name,
                    "service_principal_id": target_id,
                    "id": key_id,
                    "status": desired_status,
                }
            )
        except core.CliError as exc:
            failures += 1
            results.append(
                {"file": path.name, "id": key_id, "status": "failed", "error": str(exc)}
            )
            if not continue_on_error:
                break
    common.print_json({"results": results})
    if failures:
        raise typer.Exit(1)


@apps.sp_key_app.command("enable")
def enable_keys(
    ctx: typer.Context,
    key_dir: Annotated[Path, typer.Option("--key-dir", help="Key record directory.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    continue_on_error: Annotated[bool, typer.Option("--continue-on-error")] = False,
) -> None:
    """Enable uploaded keys recorded in a key directory."""
    change_keys_state(ctx, key_dir, "enable", dry_run, continue_on_error)


@apps.sp_key_app.command("disable")
def disable_keys(
    ctx: typer.Context,
    key_dir: Annotated[Path, typer.Option("--key-dir", help="Key record directory.")],
    dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
    continue_on_error: Annotated[bool, typer.Option("--continue-on-error")] = False,
) -> None:
    """Disable uploaded keys recorded in a key directory."""
    change_keys_state(ctx, key_dir, "disable", dry_run, continue_on_error)
