"""SAML SSO profile operations from IAM OpenAPI 2.1.0."""

from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport

SSO_PROFILE_FIELDS = (
    "name",
    "description",
    "idp_entity_id",
    "idp_login_url",
    "idp_logout_url",
    "idp_certificate",
)


def list_sso_profiles(
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
        "sso-profiles",
        query={"page": page, "per_page": per_page},
    )


def create_sso_profile(
    profile: config.Profile,
    token: str,
    name: str,
    description: str = "",
    idp_entity_id: str = "",
    idp_login_url: str = "",
    idp_logout_url: str = "",
    idp_certificate: str = "",
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        "sso-profiles",
        json_body={
            "name": name,
            "description": description,
            "idp_entity_id": idp_entity_id,
            "idp_login_url": idp_login_url,
            "idp_logout_url": idp_logout_url,
            "idp_certificate": idp_certificate,
        },
    )


def read_sso_profile(
    profile: config.Profile, token: str, sso_profile_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"sso-profiles/{urllib.parse.quote(sso_profile_id, safe='')}",
    )


def update_sso_profile(
    profile: config.Profile,
    token: str,
    sso_profile_id: str,
    name: str,
    description: str,
    idp_entity_id: str,
    idp_login_url: str,
    idp_logout_url: str,
    idp_certificate: str,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"sso-profiles/{urllib.parse.quote(sso_profile_id, safe='')}",
        json_body={
            "name": name,
            "description": description,
            "idp_entity_id": idp_entity_id,
            "idp_login_url": idp_login_url,
            "idp_logout_url": idp_logout_url,
            "idp_certificate": idp_certificate,
        },
    )


def delete_sso_profile(
    profile: config.Profile, token: str, sso_profile_id: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"sso-profiles/{urllib.parse.quote(sso_profile_id, safe='')}",
    )


def assign_sso_profile(
    profile: config.Profile, token: str, sso_profile_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        f"sso-profiles/{urllib.parse.quote(sso_profile_id, safe='')}/assign",
    )


def unassign_sso_profile(
    profile: config.Profile, token: str, sso_profile_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "POST",
        f"sso-profiles/{urllib.parse.quote(sso_profile_id, safe='')}/unassign",
    )
