from __future__ import annotations

import typer

app = typer.Typer(
    help="A CLI wrapper for the Sakura Cloud IAM API.", no_args_is_help=True
)
config_app = typer.Typer(
    help="Set up settings and manage local profiles.", no_args_is_help=True
)
sso_app = typer.Typer(
    help="Manage SAML SSO profiles and their assignment.", no_args_is_help=True
)
sp_key_app = typer.Typer(help="Manage service principal keys.", no_args_is_help=True)
sp_app = typer.Typer(help="Manage service principals.", no_args_is_help=True)
api_key_app = typer.Typer(help="Manage project API keys.", no_args_is_help=True)
iam_role_app = typer.Typer(help="Inspect IAM roles.", no_args_is_help=True)
iam_policy_app = typer.Typer(
    help="Manage IAM policies at each resource level.", no_args_is_help=True
)
id_role_app = typer.Typer(help="Inspect ID roles.", no_args_is_help=True)
id_policy_app = typer.Typer(
    help="Manage the organization ID policy.", no_args_is_help=True
)
organization_app = typer.Typer(help="Manage the organization.", no_args_is_help=True)
service_policy_app = typer.Typer(
    help="Manage service policy rules.", no_args_is_help=True
)
auth_app = typer.Typer(
    help="Manage organization authentication settings.", no_args_is_help=True
)
project_app = typer.Typer(help="Manage projects.", no_args_is_help=True)
folder_app = typer.Typer(help="Manage folders.", no_args_is_help=True)
group_app = typer.Typer(help="Manage groups and memberships.", no_args_is_help=True)
user_app = typer.Typer(
    help="Manage users and user authentication devices.", no_args_is_help=True
)
provisioning_app = typer.Typer(
    help="Manage SCIM user provisioning.", no_args_is_help=True
)
resource_app = typer.Typer(
    help="Browse and move folders and projects by path.", no_args_is_help=True
)
