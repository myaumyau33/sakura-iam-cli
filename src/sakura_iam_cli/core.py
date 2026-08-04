from __future__ import annotations

import base64
import json
import os
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
    return Profile(
        base_url=str(raw.get("base_url", DEFAULT_BASE_URL)).rstrip("/") + "/",
        project_id=values["project_id"],
        service_principal_id=values["service_principal_id"],
        kid=values["kid"],
        private_key=private_key,
    )


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_assertion(profile: Profile, now: int | None = None) -> str:
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
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
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
        values = {key: value for key, value in query.items() if value is not None}
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
