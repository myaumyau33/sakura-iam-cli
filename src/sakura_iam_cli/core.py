from __future__ import annotations

import base64
import ipaddress
import json
import os
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


DEFAULT_BASE_URL = "https://secure.sakura.ad.jp/cloud/api/iam/1.0/"
JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class CliError(Exception):
    """An error that should be shown without a traceback."""


def _is_loopback_host(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _validate_api_url(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if not parsed.hostname:
        raise CliError("API URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise CliError("API URL must not include credentials")
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
        return url
    raise CliError("API URL must use HTTPS (HTTP is allowed only for loopback hosts)")


def _validate_private_file(path: Path, label: str) -> None:
    try:
        file_stat = path.stat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(file_stat.st_mode):
        raise CliError(f"{label} is not a regular file: {path}")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise CliError(
            f"{label} permissions are too open: {path}; run chmod 600 {path}"
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


@dataclass(frozen=True)
class Profile:
    base_url: str
    project_id: str
    service_principal_id: str
    kid: str
    private_key: Path

    @property
    def token_url(self) -> str:
        return urllib.parse.urljoin(self.base_url, "service-principals/oauth2/token")


def load_profile(settings_path: Path, profile_name: str | None = None) -> Profile:
    _validate_private_file(settings_path, "settings file")
    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise CliError(f"settings file not found: {settings_path}") from exc
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid settings JSON: {exc}") from exc

    selected = profile_name or data.get("default_profile", "default")
    try:
        raw = data["profiles"][selected]
        values = {name: str(raw[name]) for name in (
            "project_id", "service_principal_id", "kid", "private_key"
        )}
    except (KeyError, TypeError) as exc:
        raise CliError(f"profile '{selected}' is missing a required setting: {exc}") from exc

    private_key = Path(values["private_key"]).expanduser()
    if not private_key.is_absolute():
        private_key = settings_path.parent / private_key
    _validate_private_file(private_key, "private key")
    return Profile(
        base_url=_validate_api_url(
            str(raw.get("base_url", DEFAULT_BASE_URL)).rstrip("/") + "/"
        ),
        project_id=values["project_id"],
        service_principal_id=values["service_principal_id"],
        kid=values["kid"],
        private_key=private_key,
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_assertion(profile: Profile, now: int | None = None) -> str:
    _validate_api_url(profile.token_url)
    _validate_private_file(profile.private_key, "private key")
    timestamp = int(time.time()) if now is None else now
    header = {"alg": "RS256", "kid": profile.kid, "typ": "JWT"}
    payload = {
        "aud": profile.token_url,
        "exp": timestamp + 300,
        "iat": timestamp,
        "iss": profile.service_principal_id,
        "sub": profile.service_principal_id,
    }
    encoded = ".".join(
        _b64url(json.dumps(part, separators=(",", ":")).encode())
        for part in (header, payload)
    )
    try:
        key = serialization.load_pem_private_key(profile.private_key.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise CliError(f"could not read RSA private key {profile.private_key}: {exc}") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise CliError(f"private key is not RSA: {profile.private_key}")
    signature = key.sign(encoded.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded}.{_b64url(signature)}"


def _request_json(request: urllib.request.Request) -> dict[str, Any]:
    _validate_api_url(request.full_url)
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        if 300 <= exc.code < 400:
            raise CliError(f"IAM API redirect refused (HTTP {exc.code})") from exc
        raise CliError(f"IAM API returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise CliError(f"could not connect to IAM API: {exc.reason}") from exc
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise CliError("IAM API returned invalid JSON") from exc


def request_iam(
    profile: Profile,
    token: str,
    method: str,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(profile.base_url, path.lstrip("/"))
    if query:
        values = {
            key: str(value).lower() if isinstance(value, bool) else value
            for key, value in query.items()
            if value is not None
        }
        if values:
            url = f"{url}?{urllib.parse.urlencode(values)}"
    data = None if json_body is None else json.dumps(json_body).encode()
    headers = {"Authorization": f"Bearer {token}"}
    if json_body is not None:
        headers["Content-Type"] = "application/json"
    return _request_json(
        urllib.request.Request(url, data=data, headers=headers, method=method)
    )


def list_service_principals(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    project_id: str | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "service-principals",
        query={"page": page, "per_page": per_page, "project_id": project_id, "ordering": ordering},
    )


def create_service_principal(
    profile: Profile, token: str, project_id: str, name: str, description: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "POST",
        "service-principals",
        json_body={"project_id": int(project_id), "name": name, "description": description},
    )


def read_service_principal(
    profile: Profile, token: str, service_principal_id: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}",
    )


def update_service_principal(
    profile: Profile,
    token: str,
    service_principal_id: str,
    name: str,
    description: str | None,
) -> dict[str, Any]:
    body = {"name": name}
    if description is not None:
        body["description"] = description
    return request_iam(
        profile,
        token,
        "PUT",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}",
        json_body=body,
    )


def delete_service_principal(
    profile: Profile, token: str, service_principal_id: str
) -> None:
    request_iam(
        profile,
        token,
        "DELETE",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}",
    )


def list_service_principal_keys(
    profile: Profile,
    token: str,
    service_principal_id: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}/keys",
        query={"page": page, "per_page": per_page, "ordering": ordering},
    )


def list_project_api_keys(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "compat/api-keys",
        query={"page": page, "per_page": per_page, "ordering": ordering},
    )


def create_project_api_key(
    profile: Profile,
    token: str,
    project_id: str,
    name: str,
    description: str,
    iam_roles: list[str],
    server_resource_id: str | None = None,
    zone_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "project_id": int(project_id),
        "name": name,
        "description": description,
        "iam_roles": iam_roles,
    }
    if server_resource_id is not None:
        body["server_resource_id"] = server_resource_id
    if zone_id is not None:
        body["zone_id"] = zone_id
    return request_iam(profile, token, "POST", "compat/api-keys", json_body=body)


def read_project_api_key(
    profile: Profile, token: str, api_key_id: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"compat/api-keys/{urllib.parse.quote(api_key_id, safe='')}",
    )


def update_project_api_key(
    profile: Profile,
    token: str,
    api_key_id: str,
    name: str,
    description: str,
    iam_roles: list[str],
    server_resource_id: str | None = None,
    zone_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": name,
        "description": description,
        "iam_roles": iam_roles,
    }
    if server_resource_id is not None:
        body["server_resource_id"] = server_resource_id
    if zone_id is not None:
        body["zone_id"] = zone_id
    return request_iam(
        profile,
        token,
        "PUT",
        f"compat/api-keys/{urllib.parse.quote(api_key_id, safe='')}",
        json_body=body,
    )


def delete_project_api_key(profile: Profile, token: str, api_key_id: str) -> None:
    request_iam(
        profile,
        token,
        "DELETE",
        f"compat/api-keys/{urllib.parse.quote(api_key_id, safe='')}",
    )


def list_iam_roles(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "iam-roles",
        query={"page": page, "per_page": per_page},
    )


def read_iam_role(profile: Profile, token: str, iam_role_id: str) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"iam-roles/{urllib.parse.quote(iam_role_id, safe='')}",
    )


def list_id_roles(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "id-roles",
        query={"page": page, "per_page": per_page},
    )


def read_id_role(profile: Profile, token: str, id_role_id: str) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"id-roles/{urllib.parse.quote(id_role_id, safe='')}",
    )


def read_organization_id_policy(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "organization-id-policy")


def update_organization_id_policy(
    profile: Profile, token: str, bindings: list[dict[str, Any]]
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        "organization-id-policy",
        json_body={"bindings": bindings},
    )


def read_organization_iam_policy(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "organization-iam-policy")


def update_organization_iam_policy(
    profile: Profile, token: str, bindings: list[dict[str, Any]]
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        "organization-iam-policy",
        json_body={"bindings": bindings},
    )


def read_folder_iam_policy(
    profile: Profile, token: str, folder_id: str
) -> dict[str, Any]:
    return request_iam(
        profile, token, "GET", f"folders/{int(folder_id)}/iam-policy"
    )


def update_folder_iam_policy(
    profile: Profile,
    token: str,
    folder_id: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        f"folders/{int(folder_id)}/iam-policy",
        json_body={"bindings": bindings},
    )


def read_project_iam_policy(
    profile: Profile, token: str, project_id: str
) -> dict[str, Any]:
    return request_iam(
        profile, token, "GET", f"projects/{int(project_id)}/iam-policy"
    )


def update_project_iam_policy(
    profile: Profile,
    token: str,
    project_id: str,
    bindings: list[dict[str, Any]],
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        f"projects/{int(project_id)}/iam-policy",
        json_body={"bindings": bindings},
    )


def read_organization(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "organization")


def update_organization(profile: Profile, token: str, name: str) -> dict[str, Any]:
    return request_iam(
        profile, token, "PUT", "organization", json_body={"name": name}
    )


def get_service_policy_status(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "service-policy-status")


def enable_service_policy(profile: Profile, token: str) -> None:
    request_iam(profile, token, "POST", "enable-service-policy")


def disable_service_policy(profile: Profile, token: str) -> None:
    request_iam(profile, token, "POST", "disable-service-policy")


def list_service_policy_rule_templates(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    name: str | None = None,
    code: str | None = None,
    rule_type: str | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "service-policy-rule-templates",
        query={
            "page": page,
            "per_page": per_page,
            "name": name,
            "code": code,
            "type": rule_type,
        },
    )


def list_organization_service_policy_rules(
    profile: Profile,
    token: str,
    *,
    is_active: bool | None = None,
    is_dry_run: bool | None = None,
    name: str | None = None,
    code: str | None = None,
    rule_type: str | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "organization-service-policy",
        query={
            "is_active": is_active,
            "is_dry_run": is_dry_run,
            "name": name,
            "code": code,
            "type": rule_type,
        },
    )


def update_organization_service_policy_rules(
    profile: Profile, token: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        "organization-service-policy",
        json_body={"rules": rules},
    )


def read_auth_context(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "auth/context")


def read_password_policy(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "organization-password-policy")


def update_password_policy(
    profile: Profile, token: str, policy: dict[str, Any]
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        "organization-password-policy",
        json_body=policy,
    )


def read_auth_conditions(profile: Profile, token: str) -> dict[str, Any]:
    return request_iam(profile, token, "GET", "organization-auth-conditions")


def update_auth_conditions(
    profile: Profile, token: str, conditions: dict[str, Any]
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        "organization-auth-conditions",
        json_body=conditions,
    )


def list_projects(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
    iam_roles: list[str] | None = None,
    parent_folder_id: str | None = None,
) -> dict[str, Any]:
    return request_iam(
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
    profile: Profile,
    token: str,
    code: str,
    name: str,
    description: str,
    parent_folder_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"code": code, "name": name, "description": description}
    if parent_folder_id is not None:
        body["parent_folder_id"] = int(parent_folder_id)
    return request_iam(profile, token, "POST", "projects", json_body=body)


def read_project(profile: Profile, token: str, project_id: str) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"projects/{urllib.parse.quote(project_id, safe='')}",
    )


def update_project(
    profile: Profile,
    token: str,
    project_id: str,
    name: str,
    description: str,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        f"projects/{urllib.parse.quote(project_id, safe='')}",
        json_body={"name": name, "description": description},
    )


def delete_project(profile: Profile, token: str, project_id: str) -> None:
    request_iam(
        profile,
        token,
        "DELETE",
        f"projects/{urllib.parse.quote(project_id, safe='')}",
    )


def move_projects(
    profile: Profile,
    token: str,
    project_ids: list[str],
    parent_folder_id: str | None,
) -> None:
    request_iam(
        profile,
        token,
        "POST",
        "move-projects",
        json_body={
            "project_ids": [int(project_id) for project_id in project_ids],
            "parent_folder_id": None if parent_folder_id is None else int(parent_folder_id),
        },
    )


def list_folders(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    folder_name: str | None = None,
    parent_id: str | None = None,
) -> dict[str, Any]:
    return request_iam(
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
    profile: Profile,
    token: str,
    name: str,
    description: str,
    parent_id: str | None = None,
) -> dict[str, Any]:
    body: dict[str, Any] = {"name": name, "description": description}
    if parent_id is not None:
        body["parent_id"] = int(parent_id)
    return request_iam(profile, token, "POST", "folders", json_body=body)


def read_folder(profile: Profile, token: str, folder_id: str) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"folders/{urllib.parse.quote(folder_id, safe='')}",
    )


def update_folder(
    profile: Profile,
    token: str,
    folder_id: str,
    name: str,
    description: str,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        f"folders/{urllib.parse.quote(folder_id, safe='')}",
        json_body={"name": name, "description": description},
    )


def delete_folder(profile: Profile, token: str, folder_id: str) -> None:
    request_iam(
        profile,
        token,
        "DELETE",
        f"folders/{urllib.parse.quote(folder_id, safe='')}",
    )


def move_folders(
    profile: Profile,
    token: str,
    folder_ids: list[str],
    parent_id: str | None,
) -> None:
    request_iam(
        profile,
        token,
        "POST",
        "move-folders",
        json_body={
            "folder_ids": [int(folder_id) for folder_id in folder_ids],
            "parent_id": None if parent_id is None else int(parent_id),
        },
    )


def list_groups(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
    user_id: str | None = None,
) -> dict[str, Any]:
    return request_iam(
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
    profile: Profile, token: str, name: str, description: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "POST",
        "groups",
        json_body={"name": name, "description": description},
    )


def read_group(profile: Profile, token: str, group_id: str) -> dict[str, Any]:
    return request_iam(
        profile, token, "GET", f"groups/{urllib.parse.quote(group_id, safe='')}"
    )


def update_group(
    profile: Profile, token: str, group_id: str, name: str, description: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        f"groups/{urllib.parse.quote(group_id, safe='')}",
        json_body={"name": name, "description": description},
    )


def delete_group(profile: Profile, token: str, group_id: str) -> None:
    request_iam(
        profile, token, "DELETE", f"groups/{urllib.parse.quote(group_id, safe='')}"
    )


def list_group_memberships(
    profile: Profile, token: str, group_id: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"groups/{urllib.parse.quote(group_id, safe='')}/memberships",
    )


def update_group_memberships(
    profile: Profile, token: str, group_id: str, user_ids: list[str]
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "PUT",
        f"groups/{urllib.parse.quote(group_id, safe='')}/memberships",
        json_body={"compat_users": [{"id": int(user_id)} for user_id in user_ids]},
    )


def list_users(
    profile: Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    ordering: str | None = None,
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        "compat/users",
        query={"page": page, "per_page": per_page, "ordering": ordering},
    )


def create_user(
    profile: Profile,
    token: str,
    name: str,
    code: str,
    password: str,
    description: str,
    email: str | None = None,
) -> dict[str, Any]:
    body = {"name": name, "code": code, "password": password, "description": description}
    if email is not None:
        body["email"] = email
    return request_iam(profile, token, "POST", "compat/users", json_body=body)


def read_user(profile: Profile, token: str, user_id: str) -> dict[str, Any]:
    return request_iam(
        profile, token, "GET", f"compat/users/{urllib.parse.quote(user_id, safe='')}"
    )


def update_user(
    profile: Profile,
    token: str,
    user_id: str,
    name: str,
    description: str,
    password: str | None = None,
) -> dict[str, Any]:
    body = {"name": name, "description": description}
    if password is not None:
        body["password"] = password
    return request_iam(
        profile,
        token,
        "PUT",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}",
        json_body=body,
    )


def delete_user(profile: Profile, token: str, user_id: str) -> None:
    request_iam(
        profile, token, "DELETE", f"compat/users/{urllib.parse.quote(user_id, safe='')}"
    )


def register_user_email(profile: Profile, token: str, user_id: str, email: str) -> None:
    request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/register-email",
        json_body={"email": email},
    )


def unregister_user_email(profile: Profile, token: str, user_id: str) -> None:
    request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/unregister-email",
    )


def deactivate_user_otp(profile: Profile, token: str, user_id: str) -> None:
    request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/deactivate-otp",
    )


def list_trusted_devices(profile: Profile, token: str, user_id: str) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/trusted-devices",
    )


def delete_trusted_device(
    profile: Profile, token: str, user_id: str, trusted_device_id: str
) -> None:
    request_iam(
        profile,
        token,
        "DELETE",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/trusted-devices/"
        f"{urllib.parse.quote(trusted_device_id, safe='')}",
    )


def clear_trusted_devices(profile: Profile, token: str, user_id: str) -> None:
    request_iam(
        profile,
        token,
        "POST",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/clear-trusted-devices",
    )


def list_security_keys(profile: Profile, token: str, user_id: str) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/security-keys",
    )


def read_security_key(
    profile: Profile, token: str, user_id: str, security_key_id: str
) -> dict[str, Any]:
    return request_iam(
        profile,
        token,
        "GET",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/security-keys/"
        f"{urllib.parse.quote(security_key_id, safe='')}",
    )


def delete_security_key(
    profile: Profile, token: str, user_id: str, security_key_id: str
) -> None:
    request_iam(
        profile,
        token,
        "DELETE",
        f"compat/users/{urllib.parse.quote(user_id, safe='')}/security-keys/"
        f"{urllib.parse.quote(security_key_id, safe='')}",
    )


def issue_access_token(profile: Profile) -> str:
    form = urllib.parse.urlencode(
        {"grant_type": JWT_GRANT_TYPE, "assertion": create_assertion(profile)}
    ).encode()
    request = urllib.request.Request(
        profile.token_url,
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    response = _request_json(request)
    try:
        return str(response["access_token"])
    except KeyError as exc:
        raise CliError("token response did not contain access_token") from exc


def generate_key_pairs(output_dir: Path, num: int, bits: int = 2048) -> list[Path]:
    if num < 1:
        raise CliError("--num must be at least 1")
    if bits not in (2048, 3072, 4096):
        raise CliError("--bits must be 2048, 3072, or 4096")
    output_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    width = max(3, len(str(num)))
    for index in range(1, num + 1):
        stem = f"sp-key-{index:0{width}d}"
        private_path = output_dir / f"{stem}.private.pem"
        public_path = output_dir / f"{stem}.public.pem"
        if private_path.exists() or public_path.exists():
            raise CliError(f"refusing to overwrite an existing key: {stem}")
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        private_bytes = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_bytes = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_path.write_bytes(private_bytes)
        os.chmod(private_path, 0o600)
        public_path.write_bytes(public_bytes)
        os.chmod(public_path, 0o644)
        created.append(public_path)
    return created


def upload_public_key(
    profile: Profile,
    token: str,
    public_key_path: Path,
    service_principal_id: str,
) -> dict[str, Any]:
    url = urllib.parse.urljoin(
        profile.base_url,
        f"service-principals/{urllib.parse.quote(service_principal_id, safe='')}/upload-key",
    )
    try:
        public_key = public_key_path.read_text(encoding="ascii")
        serialization.load_pem_public_key(public_key.encode("ascii"))
    except (OSError, ValueError) as exc:
        raise CliError(f"invalid public key {public_key_path}: {exc}") from exc
    request = urllib.request.Request(
        url,
        data=json.dumps({"public_key": public_key}).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        method="POST",
    )
    return _request_json(request)


def delete_service_principal_key(
    profile: Profile,
    token: str,
    service_principal_id: str,
    service_principal_key_id: str,
) -> None:
    url = urllib.parse.urljoin(
        profile.base_url,
        "service-principals/"
        f"{urllib.parse.quote(service_principal_id, safe='')}/keys/"
        f"{urllib.parse.quote(service_principal_key_id, safe='')}",
    )
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}"},
        method="DELETE",
    )
    _request_json(request)


def change_service_principal_key_state(
    profile: Profile,
    token: str,
    service_principal_id: str,
    service_principal_key_id: str,
    action: str,
) -> dict[str, Any]:
    if action not in ("enable", "disable"):
        raise ValueError(f"unsupported key action: {action}")
    url = urllib.parse.urljoin(
        profile.base_url,
        "service-principals/"
        f"{urllib.parse.quote(service_principal_id, safe='')}/keys/"
        f"{urllib.parse.quote(service_principal_key_id, safe='')}/{action}",
    )
    request = urllib.request.Request(
        url,
        data=b"",
        headers={"Authorization": f"Bearer {token}"},
        method="POST",
    )
    return _request_json(request)
