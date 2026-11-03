from __future__ import annotations

from typing import Any

from sakura_iam_cli import config, transport


def read_auth_context(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "auth/context")


def read_password_policy(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "organization-password-policy")


def update_password_policy(
    profile: config.Profile, token: str, policy: dict[str, Any]
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        "organization-password-policy",
        json_body=policy,
    )


def read_auth_conditions(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "organization-auth-conditions")


def update_auth_conditions(
    profile: config.Profile, token: str, conditions: dict[str, Any]
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        "organization-auth-conditions",
        json_body=conditions,
    )
