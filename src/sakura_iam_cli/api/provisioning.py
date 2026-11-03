from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_scim_configurations(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "scim-configurations",
        query={"page": page, "per_page": per_page},
    )


def create_scim_configuration(
    profile: config.Profile, token: str, name: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        "scim-configurations",
        json_body={"name": name},
    )


def read_scim_configuration(
    profile: config.Profile, token: str, configuration_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"scim-configurations/{urllib.parse.quote(configuration_id, safe='')}",
    )


def update_scim_configuration(
    profile: config.Profile, token: str, configuration_id: str, name: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"scim-configurations/{urllib.parse.quote(configuration_id, safe='')}",
        json_body={"name": name},
    )


def delete_scim_configuration(
    profile: config.Profile, token: str, configuration_id: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"scim-configurations/{urllib.parse.quote(configuration_id, safe='')}",
    )


def regenerate_scim_configuration_token(
    profile: config.Profile, token: str, configuration_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        "scim-configurations/"
        f"{urllib.parse.quote(configuration_id, safe='')}/regenerate-token",
    )
