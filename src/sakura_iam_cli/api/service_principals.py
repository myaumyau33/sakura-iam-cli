from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_service_principals(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    project_id: str | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "service-principals",
        query={
            "page": page,
            "per_page": per_page,
            "project_id": project_id,
            "ordering": ordering,
        },
    )


def create_service_principal(
    profile: config.Profile, token: str, project_id: str, name: str, description: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        "service-principals",
        json_body={
            "project_id": int(project_id),
            "name": name,
            "description": description,
        },
    )


def read_service_principal(
    profile: config.Profile, token: str, service_principal_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}",
    )


def update_service_principal(
    profile: config.Profile,
    token: str,
    service_principal_id: str,
    name: str,
    description: str | None,
) -> dict[str, Any]:
    body = {"name": name}
    if description is not None:
        body["description"] = description
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}",
        json_body=body,
    )


def delete_service_principal(
    profile: config.Profile, token: str, service_principal_id: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}",
    )


def list_service_principal_keys(
    profile: config.Profile,
    token: str,
    service_principal_id: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}/keys",
        query={"page": page, "per_page": per_page, "ordering": ordering},
    )
