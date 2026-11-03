from __future__ import annotations

import base64
import json
import time
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from sakura_iam_cli import config, errors, transport

JWT_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:jwt-bearer"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def create_assertion(profile: config.Profile, now: int | None = None) -> str:
    config._validate_api_url(profile.token_url)
    config._validate_private_file(profile.private_key, "private key")
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
        key = serialization.load_pem_private_key(
            profile.private_key.read_bytes(), password=None
        )
    except (OSError, ValueError, TypeError) as exc:
        raise errors.CliError(
            f"could not read RSA private key {profile.private_key}: {exc}"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise errors.CliError(f"private key is not RSA: {profile.private_key}")
    signature = key.sign(encoded.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{encoded}.{_b64url(signature)}"


def issue_access_token(profile: config.Profile) -> str:
    form = urllib.parse.urlencode(
        {"grant_type": JWT_GRANT_TYPE, "assertion": create_assertion(profile)}
    ).encode()
    request = urllib.request.Request(
        profile.token_url,
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    response = transport._request_json(request)
    try:
        return str(response["access_token"])
    except KeyError as exc:
        raise errors.CliError("token response did not contain access_token") from exc
