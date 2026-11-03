from __future__ import annotations

import base64
import urllib.parse
import urllib.request
from typing import Any

from sakura_iam_cli import errors, transport

CLOUD_API_BASE_URL = "https://secure.sakura.ad.jp/cloud/zone/{zone}/api/cloud/1.1/"


CLOUD_API_ZONES = frozenset(("tk1a", "tk1b", "is1a", "is1b", "is1c", "tk1v"))


def get_cloud_auth_status(
    access_token: str,
    access_token_secret: str,
    *,
    zone: str = "is1a",
) -> dict[str, Any]:
    """Return the Cloud API v1.1 authentication context for a project API key."""
    if zone not in CLOUD_API_ZONES:
        choices = ", ".join(sorted(CLOUD_API_ZONES))
        raise errors.CliError(f"unsupported zone {zone!r}; choose one of: {choices}")
    if not access_token or not access_token_secret:
        raise errors.CliError("access token and access token secret must not be empty")
    credentials = base64.b64encode(
        f"{access_token}:{access_token_secret}".encode("utf-8")
    ).decode("ascii")
    url = urllib.parse.urljoin(CLOUD_API_BASE_URL.format(zone=zone), "auth-status")
    return transport._request_json(
        urllib.request.Request(
            url,
            headers={"Authorization": f"Basic {credentials}"},
            method="GET",
        )
    )
