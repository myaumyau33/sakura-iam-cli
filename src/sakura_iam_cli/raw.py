"""Authenticated HTTP requests to explicitly supplied URLs."""

from __future__ import annotations

import base64
import re
import urllib.request

from . import config, errors, transport

_HTTP_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def prepare_request(
    method: str,
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> urllib.request.Request:
    """Validate the request before acquiring an access token."""
    if not _HTTP_TOKEN.fullmatch(method):
        raise errors.CliError("invalid HTTP method")
    config._validate_api_url(url)
    for name, value in (headers or {}).items():
        if not _HTTP_TOKEN.fullmatch(name) or "\r" in value or "\n" in value:
            raise errors.CliError("invalid HTTP header")
        if name.lower() == "authorization":
            raise errors.CliError("Authorization is supplied automatically")
    return urllib.request.Request(
        url, data=data, headers=headers or {}, method=method.upper()
    )


def send_request(request: urllib.request.Request, token: str) -> bytes:
    request.add_header("Authorization", f"Bearer {token}")
    return transport._request_bytes(request, service="HTTP endpoint", raw_errors=True)


def send_api_key_request(
    request: urllib.request.Request, access_token: str, access_token_secret: str
) -> bytes:
    if not access_token or not access_token_secret:
        raise errors.CliError("access token and access token secret must not be empty")
    credentials = base64.b64encode(
        f"{access_token}:{access_token_secret}".encode("utf-8")
    ).decode("ascii")
    request.add_header("Authorization", f"Basic {credentials}")
    return transport._request_bytes(request, service="HTTP endpoint", raw_errors=True)
