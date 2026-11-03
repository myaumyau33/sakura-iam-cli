from __future__ import annotations

import urllib.parse
from typing import Any

from sakura_iam_cli import config, transport


def list_users(
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
        "compat/users",
        query={"page": page, "per_page": per_page, "ordering": ordering},
    )


def create_user(
    profile: config.Profile,
    token: str,
    name: str,
    code: str,
    password: str,
    description: str,
    email: str | None = None,
) -> dict[str, Any]:
    body = {
        "name": name,
        "code": code,
        "password": password,
        "description": description,
    }
    if email is not None:
        body["email"] = email
    return transport.request_iam(profile, token, "POST", "compat/users", json_body=body)


def read_user(profile: config.Profile, token: str, user_id: str) -> dict[str, Any]:
    return transport.request_iam(
        profile, token, "GET", f"compat/users/{urllib.parse.quote(user_id, safe='')}"
    )


def update_user(
    profile: config.Profile,
    token: str,
    user_id: str,
    name: str,
    description: str,
    password: str | None = None,
) -> dict[str, Any]:
    body = {"name": name, "description": description}
    if password is not None:
        body["password"] = password
    return transport.request_iam(
        profile,
        token,
        "PUT",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}",
        json_body=body,
    )


def delete_user(profile: config.Profile, token: str, user_id: str) -> None:
    transport.request_iam(
        profile, token, "DELETE", f"compat/users/{urllib.parse.quote(user_id, safe='')}"
    )


def register_user_email(
    profile: config.Profile, token: str, user_id: str, email: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/register-email",
        json_body={"email": email},
    )


def unregister_user_email(profile: config.Profile, token: str, user_id: str) -> None:
    transport.request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/unregister-email",
    )


def deactivate_user_otp(profile: config.Profile, token: str, user_id: str) -> None:
    transport.request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/deactivate-otp",
    )


def list_trusted_devices(
    profile: config.Profile, token: str, user_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/trusted-devices",
    )


def delete_trusted_device(
    profile: config.Profile, token: str, user_id: str, trusted_device_id: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/trusted-devices/"
        f"{urllib.parse.quote(trusted_device_id, safe='')}",
    )


def clear_trusted_devices(profile: config.Profile, token: str, user_id: str) -> None:
    transport.request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/clear-trusted-devices",
    )


def list_security_keys(
    profile: config.Profile, token: str, user_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/security-keys",
    )


def read_security_key(
    profile: config.Profile, token: str, user_id: str, security_key_id: str
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/security-keys/"
        f"{urllib.parse.quote(security_key_id, safe='')}",
    )


def delete_security_key(
    profile: config.Profile, token: str, user_id: str, security_key_id: str
) -> None:
    transport.request_iam(
        profile,
        token,
        "DELETE",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/security-keys/"
        f"{urllib.parse.quote(security_key_id, safe='')}",
    )
