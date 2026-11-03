from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_project_api_keys(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "compat/api-keys",
        query={"page": page, "per_page": per_page, "ordering": ordering},
    )


def create_project_api_key(
    profile: config.Profile,
    token: str,
    project_id: str,
    name: str,
    description: str,
    iam_roles: list[str],
    server_resource_id: str | None = None,
    zone_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "project_id": int(project_id),
        "name": name,
        "description": description,
        "iam_roles": iam_roles,
    }
    if server_resource_id is not None:
        body["server_resource_id"] = server_resource_id
    if zone_id is not None:
        body["zone_id"] = zone_id
    return transport.request_iam(
        profile, token, "POST", "compat/api-keys", json_body=body
    )


def read_project_api_key(
    profile: config.Profile, token: str, api_key_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"compat/api-keys/{urllib.parse.quote(api_key_id, safe='')}",
    )


def update_project_api_key(
    profile: config.Profile,
    token: str,
    api_key_id: str,
    name: str,
    description: str,
    iam_roles: list[str],
    server_resource_id: str | None = None,
    zone_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": name,
        "description": description,
        "iam_roles": iam_roles,
    }
    if server_resource_id is not None:
        body["server_resource_id"] = server_resource_id
    if zone_id is not None:
        body["zone_id"] = zone_id
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"compat/api-keys/{urllib.parse.quote(api_key_id, safe='')}",
        json_body=body,
    )


def delete_project_api_key(
    profile: config.Profile, token: str, api_key_id: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"compat/api-keys/{urllib.parse.quote(api_key_id, safe='')}",
    )
