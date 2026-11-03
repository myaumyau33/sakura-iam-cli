from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

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


class CloudApiZone(str, Enum):
    tk1a = "tk1a"
    tk1b = "tk1b"
    is1a = "is1a"
    is1b = "is1b"
    is1c = "is1c"
    tk1v = "tk1v"


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
