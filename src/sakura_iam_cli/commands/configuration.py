"""Interactive setup and local profile management; no API authentication required."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from sakura_iam_cli import config, core
from sakura_iam_cli.commands import apps, common, options
from sakura_iam_cli.settings import SettingsFile, validate_profile

NameArgument = Annotated[
    str | None,
    typer.Argument(
        help="Profile name; can also be selected with the global --profile option."
    ),
]
SpOption = Annotated[
    str | None, typer.Option("--service-principal-id", help="Service principal ID.")
]
KidOption = Annotated[
    str | None, typer.Option("--kid", help="Registered service principal key ID (kid).")
]
KeyOption = Annotated[
    Path | None,
    typer.Option(
        "--private-key",
        help="Existing RSA private key; relative to the current directory.",
    ),
]
UrlOption = Annotated[
    str | None,
    typer.Option("--base-url", help="IAM API URL; '-' resets to the standard URL."),
]
ProjectOption = Annotated[
    str | None,
    typer.Option(
        "--project-id", help="Optional default project for creation; '-' clears it."
    ),
]
DefaultOption = Annotated[
    bool, typer.Option("--default", help="Make this profile the default.")
]


def update_fields(
    existing: dict, provided: dict, settings_path: Path, *, interactive: bool
) -> dict:
    result = dict(existing)
    labels = {
        "service_principal_id": "サービスプリンシパルID",
        "kid": "登録済みの鍵のkid",
        "private_key": "秘密鍵ファイルのパス",
    }
    for field, label in labels.items():
        value = provided[field]
        if value is None and (interactive or not result.get(field)):
            default = result.get(field)
            if field == "private_key" and default:
                key = Path(default).expanduser()
                default = str(key if key.is_absolute() else settings_path.parent / key)
            value = typer.prompt(
                label, default=str(default) if default is not None else None
            )
        if value is not None:
            result[field] = (
                str(Path(value).expanduser().resolve())
                if field == "private_key"
                else value
            )
    for field, label, fallback in [
        ("base_url", "IAM API URL（-で標準URLに戻す）", config.DEFAULT_BASE_URL),
        ("project_id", "既定の作成先プロジェクトID（-で未設定）", "-"),
    ]:
        value = provided[field]
        if interactive:
            value = typer.prompt(label, default=str(result.get(field) or fallback))
        if value is not None:
            result[field] = value
    return validate_profile(result, settings_path)


@apps.config_app.command("init", help="Create a settings file and its first profile.")
@apps.config_app.command(
    "add", help="Add a new profile without changing existing profiles."
)
@apps.config_app.command(
    "edit", help="Edit a profile; without options, prompt for each setting."
)
def configure_profile(
    ctx: typer.Context,
    name: NameArgument = None,
    service_principal_id: SpOption = None,
    kid: KidOption = None,
    private_key: KeyOption = None,
    base_url: UrlOption = None,
    project_id: ProjectOption = None,
    make_default: DefaultOption = False,
) -> None:
    try:
        app_context: options.AppContext = ctx.obj
        mode = ctx.info_name
        settings_path = app_context.settings.expanduser().resolve()
        if mode == "init" and settings_path.exists():
            raise core.CliError(
                "settings file already exists; use 'config add' or 'config edit'"
            )
        settings = SettingsFile.load(settings_path, missing_ok=mode != "edit")
        if mode == "add" and name is None and app_context.profile_name is None:
            name = typer.prompt("追加するプロファイル名")
        name = settings.selected_name(name or app_context.profile_name)
        if not name.strip():
            raise core.CliError("profile name must not be empty")
        profiles = settings.document["profiles"]
        if mode != "edit" and name in profiles:
            raise core.CliError(
                f"profile '{name}' already exists; use 'config edit {name}'"
            )
        if mode == "edit" and name not in profiles:
            raise core.CliError(f"profile '{name}' not found; use 'config add {name}'")
        provided = {
            "service_principal_id": service_principal_id,
            "kid": kid,
            "private_key": private_key,
            "base_url": base_url,
            "project_id": project_id,
        }
        interactive = (
            mode == "edit"
            and not make_default
            and all(value is None for value in provided.values())
        )
        profile = update_fields(
            profiles.get(name, {}), provided, settings.path, interactive=interactive
        )
        first = not profiles
        profiles[name] = profile
        if (
            first
            or make_default
            or (
                "default_profile" not in settings.document and "default" not in profiles
            )
        ):
            settings.document["default_profile"] = name
        settings.save()
        typer.echo(f"保存先: {settings.path}\nプロファイル: {name}")
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.config_app.command("list")
def list_profiles(ctx: typer.Context) -> None:
    """List local profile names and the default profile."""
    try:
        settings = SettingsFile.load(ctx.obj.settings)
        default = settings.selected_name(None)
        table = Table("プロファイル", "既定", "サービスプリンシパルID")
        for name, profile in settings.document["profiles"].items():
            table.add_row(
                Text(name),
                "*" if name == default else "",
                Text(str(profile.get("service_principal_id", ""))),
            )
        Console().print(table)
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.config_app.command("use")
def use_profile(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Profile to use by default.")],
) -> None:
    """Change the default profile without modifying its credentials."""
    try:
        settings = SettingsFile.load(ctx.obj.settings)
        if name not in settings.document["profiles"]:
            raise core.CliError(f"profile '{name}' not found")
        settings.document["default_profile"] = name
        settings.save()
        typer.echo(f"既定のプロファイル: {name}")
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
