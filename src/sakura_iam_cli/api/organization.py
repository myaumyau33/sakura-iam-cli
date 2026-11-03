from __future__ import annotations

from typing import Any

from sakura_iam_cli import config, transport


def read_organization(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "organization")


def update_organization(
    profile: config.Profile, token: str, name: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile, token, "PUT", "organization", json_body={"name": name}
    )


def get_service_policy_status(profile: config.Profile, token: str) -> dict[str, Any]:
    return transport.request_iam(profile, token, "GET", "service-policy-status")


def enable_service_policy(profile: config.Profile, token: str) -> None:
    transport.request_iam(profile, token, "POST", "enable-service-policy")


def disable_service_policy(profile: config.Profile, token: str) -> None:
    transport.request_iam(profile, token, "POST", "disable-service-policy")
