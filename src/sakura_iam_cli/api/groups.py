from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_groups(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
    user_id: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "groups",
        query={
            "page": page,
            "per_page": per_page,
            "ordering": ordering,
            "compat_user_id": user_id,
        },
    )


def create_group(
    profile: config.Profile, token: str, name: str, description: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        "groups",
        json_body={"name": name, "description": description},
    )


def read_group(profile: config.Profile, token: str, group_id: str) -> dict[str, Any]:
    return transport.request_iam(
        profile, token, "GET", f"groups/{urllib.parse.quote(group_id, safe='')}"
    )


def update_group(
    profile: config.Profile, token: str, group_id: str, name: str, description: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"groups/{urllib.parse.quote(group_id, safe='')}",
        json_body={"name": name, "description": description},
    )


def delete_group(profile: config.Profile, token: str, group_id: str) -> None:
    transport.request_iam(
        profile, token, "DELETE", f"groups/{urllib.parse.quote(group_id, safe='')}"
    )


def list_group_memberships(
    profile: config.Profile, token: str, group_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"groups/{urllib.parse.quote(group_id, safe='')}/memberships",
    )


def update_group_memberships(
    profile: config.Profile, token: str, group_id: str, user_ids: list[str]
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"groups/{urllib.parse.quote(group_id, safe='')}/memberships",
        json_body={"compat_users": [{"id": int(user_id)} for user_id in user_ids]},
    )
