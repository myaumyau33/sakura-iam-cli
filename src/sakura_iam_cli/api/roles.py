from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_iam_roles(
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
        "iam-roles",
        query={"page": page, "per_page": per_page},
    )


def read_iam_role(
    profile: config.Profile, token: str, iam_role_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"iam-roles/{urllib.parse.quote(iam_role_id, safe='')}",
    )


def list_id_roles(
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
        "id-roles",
        query={"page": page, "per_page": per_page},
    )


def read_id_role(
    profile: config.Profile, token: str, id_role_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"id-roles/{urllib.parse.quote(id_role_id, safe='')}",
    )
