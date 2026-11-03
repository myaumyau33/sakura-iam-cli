from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from sakura_iam_cli import config, errors


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _request_bytes(
    request: urllib.request.Request,
    *,
    service: str = "IAM API",
    raw_errors: bool = False,
) -> bytes:
    config._validate_api_url(request.full_url)
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=30) as response:
            body = response.read()
    except urllib.error.HTTPError as exc:
        body = exc.read()
        if raw_errors:
            raise errors.HttpResponseError(exc.code, body) from exc
        detail = body.decode("utf-8", errors="replace")
        if 300 <= exc.code < 400:
            raise errors.CliError(
                f"{service} redirect refused (HTTP {exc.code})"
            ) from exc
        raise errors.CliError(f"{service} returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise errors.CliError(f"could not connect to {service}: {exc.reason}") from exc
    return body


def _request_json(request: urllib.request.Request) -> dict[str, Any]:
    body = _request_bytes(request)
    if not body:
        return {}
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise errors.CliError("IAM API returned invalid JSON") from exc


def request_iam(
    profile: config.Profile,
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
