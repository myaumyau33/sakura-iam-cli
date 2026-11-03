from __future__ import annotations

from pathlib import Path

import typer

from sakura_iam_cli.commands import apps, options

from .commands import api_keys as api_keys
from .commands import authentication as authentication
from .commands import configuration as configuration
from .commands import folders as folders
from .commands import groups as groups
from .commands import iam_policy as iam_policy
from .commands import iam_policy_edit as iam_policy_edit
from .commands import id_policy as id_policy
from .commands import organization as organization
from .commands import projects as projects
from .commands import provisioning as provisioning
from .commands import raw_url as raw_url
from .commands import resource_tree as resource_tree
from .commands import resources as resources
from .commands import roles as roles
from .commands import service_policy as service_policy
from .commands import service_principal_keys as service_principal_keys
from .commands import service_principals as service_principals
from .commands import sp_permissions as sp_permissions
from .commands import token as token
from .commands import user_devices as user_devices
from .commands import users as users

app = apps.app

apps.app.add_typer(apps.config_app, name="config")
apps.app.add_typer(apps.sp_key_app, name="sp-key")
apps.app.add_typer(apps.sp_app, name="sp")
apps.app.add_typer(apps.api_key_app, name="api-key")
apps.app.add_typer(apps.iam_role_app, name="iam-role")
apps.app.add_typer(apps.iam_policy_app, name="iam-policy")
apps.app.add_typer(apps.id_role_app, name="id-role")
apps.app.add_typer(apps.id_policy_app, name="id-policy")
apps.app.add_typer(apps.organization_app, name="organization")
apps.app.add_typer(apps.service_policy_app, name="service-policy")
apps.app.add_typer(apps.auth_app, name="auth")
apps.app.add_typer(apps.project_app, name="project")
apps.app.add_typer(apps.folder_app, name="folder")
apps.app.add_typer(apps.group_app, name="group")
apps.app.add_typer(apps.user_app, name="user")
apps.app.add_typer(apps.provisioning_app, name="provisioning")
apps.app.add_typer(apps.resource_app, name="resource")


@apps.app.callback()
def configure(
    ctx: typer.Context,
    settings: options.SettingsOption = Path("settings.json"),
    profile_name: options.ProfileOption = None,
) -> None:
    """Configure the Sakura Cloud IAM API client."""
    ctx.obj = options.AppContext(settings=settings, profile_name=profile_name)


def main() -> None:
    apps.app()


if __name__ == "__main__":
    main()
