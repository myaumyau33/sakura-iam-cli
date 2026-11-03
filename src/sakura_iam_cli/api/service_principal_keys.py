from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from sakura_iam_cli import config, errors, transport


def upload_public_key(
    profile: config.Profile,
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
        raise errors.CliError(f"invalid public key {public_key_path}: {exc}") from exc
    request = urllib.request.Request(
        url,
        data=json.dumps({"public_key": public_key}).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    return transport._request_json(request)


def delete_service_principal_key(
    profile: config.Profile,
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
    transport._request_json(request)


def change_service_principal_key_state(
    profile: config.Profile,
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
    return transport._request_json(request)
