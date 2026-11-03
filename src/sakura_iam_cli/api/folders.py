from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_folders(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    folder_name: str | None = None,
    parent_id: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "folders",
        query={
            "page": page,
            "per_page": per_page,
            "folder_name": folder_name,
            "parent_id": parent_id,
        },
    )


def create_folder(
    profile: config.Profile,
    token: str,
    name: str,
    description: str,
    parent_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"name": name, "description": description}
    if parent_id is not None:
        body["parent_id"] = int(parent_id)
    return transport.request_iam(profile, token, "POST", "folders", json_body=body)


def read_folder(profile: config.Profile, token: str, folder_id: str) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"folders/{urllib.parse.quote(folder_id, safe='')}",
    )


def update_folder(
    profile: config.Profile,
    token: str,
    folder_id: str,
    name: str,
    description: str,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"folders/{urllib.parse.quote(folder_id, safe='')}",
        json_body={"name": name, "description": description},
    )


def delete_folder(profile: config.Profile, token: str, folder_id: str) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"folders/{urllib.parse.quote(folder_id, safe='')}",
    )


def move_folders(
    profile: config.Profile,
    token: str,
    folder_ids: list[str],
    parent_id: str | None,
) -> None:
    transport.request_iam(
        profile,
        token,
        "POST",
        "move-folders",
        json_body={
            "folder_ids": [int(folder_id) for folder_id in folder_ids],
            "parent_id": None if parent_id is None else int(parent_id),
        },
    )
