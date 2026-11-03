from __future__ import annotations

from typing import Any

from sakura_iam_cli import config, transport


def read_organization_id_policy(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "organization-id-policy")


def update_organization_id_policy(
    profile: config.Profile, token: str, bindings: list[dict[str, Any]]
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        "organization-id-policy",
        json_body={"bindings": bindings},
    )


def read_organization_iam_policy(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "organization-iam-policy")


def update_organization_iam_policy(
    profile: config.Profile, token: str, bindings: list[dict[str, Any]]
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        "organization-iam-policy",
        json_body={"bindings": bindings},
    )


def read_folder_iam_policy(
    profile: config.Profile, token: str, folder_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile, token, "GET", f"folders/{int(folder_id)}/iam-policy"
    )


def update_folder_iam_policy(
    profile: config.Profile,
    token: str,
    folder_id: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"folders/{int(folder_id)}/iam-policy",
        json_body={"bindings": bindings},
    )


def read_project_iam_policy(
    profile: config.Profile, token: str, project_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile, token, "GET", f"projects/{int(project_id)}/iam-policy"
    )


def update_project_iam_policy(
    profile: config.Profile,
    token: str,
    project_id: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"projects/{int(project_id)}/iam-policy",
        json_body={"bindings": bindings},
    )
