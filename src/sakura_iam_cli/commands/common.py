from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from sakura_iam_cli import core
from sakura_iam_cli.commands import options


def print_json(value: object) -> None:
    typer.echo(json.dumps(value, ensure_ascii=False, indent=2))


def write_sensitive_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise core.CliError(
            f"refusing to overwrite existing output file: {path}"
        ) from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as output_file:
        json.dump(value, output_file, ensure_ascii=False, indent=2)
        output_file.write("\n")


def fail(error: core.CliError) -> None:
    typer.echo(f"error: {error}", err=True)
    raise typer.Exit(1)


def authenticated(ctx: typer.Context) -> tuple[core.Profile, str]:
    config: options.AppContext = ctx.obj
    profile = core.load_profile(config.settings, config.profile_name)
    return profile, core.issue_access_token(profile)


def collect_pages(fetch) -> list[dict]:
    page = 1
    items: list[dict] = []
    while True:
        response = fetch(page)
        batch = response.get("items", [])
        if not isinstance(batch, list):
            raise core.CliError("IAM API list response did not contain an items array")
        items.extend(batch)
        count = response.get("count")
        if response.get("next") or (isinstance(count, int) and len(items) < count):
            page += 1
            continue
        return items


def load_json_object(path: Path, label: str) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise core.CliError(f"{label} file not found: {path}") from exc
    except OSError as exc:
        raise core.CliError(f"could not read {label} file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise core.CliError(f"invalid {label} JSON in {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise core.CliError(f"{label} must be a JSON object")
    return document


def read_password(password_file: Path | None, *, required: bool) -> str | None:
    if password_file is None:
        if not required:
            return None
        value = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    else:
        try:
            value = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise core.CliError(
                f"could not read password file {password_file}: {exc}"
            ) from exc
    if not value:
        raise core.CliError("password must not be empty")
    return value
