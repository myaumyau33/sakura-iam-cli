from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_projects(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
    iam_roles: list[str] | None = None,
    parent_folder_id: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "projects",
        query={
            "page": page,
            "per_page": per_page,
            "ordering": ordering,
            "iam_role": None if not iam_roles else ",".join(iam_roles),
            "parent_folder_id": parent_folder_id,
        },
    )


def create_project(
    profile: config.Profile,
    token: str,
    code: str,
    name: str,
    description: str,
    parent_folder_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "name": name, "description": description}
    if parent_folder_id is not None:
        body["parent_folder_id"] = int(parent_folder_id)
    return transport.request_iam(profile, token, "POST", "projects", json_body=body)


def read_project(
    profile: config.Profile, token: str, project_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"projects/{urllib.parse.quote(project_id, safe='')}",
    )


def update_project(
    profile: config.Profile,
    token: str,
    project_id: str,
    name: str,
    description: str,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"projects/{urllib.parse.quote(project_id, safe='')}",
        json_body={"name": name, "description": description},
    )


def delete_project(profile: config.Profile, token: str, project_id: str) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"projects/{urllib.parse.quote(project_id, safe='')}",
    )


def move_projects(
    profile: config.Profile,
    token: str,
    project_ids: list[str],
    parent_folder_id: str | None,
) -> None:
    transport.request_iam(
        profile,
        token,
        "POST",
        "move-projects",
        json_body={
            "project_ids": [int(project_id) for project_id in project_ids],
            "parent_folder_id": None
            if parent_folder_id is None
            else int(parent_folder_id),
        },
    )
