from __future__ import annotations

import ipaddress
import json
import os
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from sakura_iam_cli import errors

DEFAULT_BASE_URL = "https://secure.sakura.ad.jp/cloud/api/iam/1.0/"


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
        raise errors.CliError("API URL must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise errors.CliError("API URL must not include credentials")
    if parsed.scheme == "https":
        return url
    if parsed.scheme == "http" and _is_loopback_host(parsed.hostname):
        return url
    raise errors.CliError(
        "API URL must use HTTPS (HTTP is allowed only for loopback hosts)"
    )


def _validate_private_file(path: Path, label: str) -> None:
    try:
        file_stat = path.stat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(file_stat.st_mode):
        raise errors.CliError(f"{label} is not a regular file: {path}")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise errors.CliError(
            f"{label} permissions are too open: {path}; run chmod 600 {path}"
        )


@dataclass(frozen=True)
class Profile:
    base_url: str
    project_id: str | None
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
        raise errors.CliError(f"settings file not found: {settings_path}") from exc
    except json.JSONDecodeError as exc:
        raise errors.CliError(f"invalid settings JSON: {exc}") from exc

    selected = profile_name or data.get("default_profile", "default")
    try:
        raw = data["profiles"][selected]
        values = {
            name: str(raw[name])
            for name in ("service_principal_id", "kid", "private_key")
        }
    except (KeyError, TypeError) as exc:
        raise errors.CliError(
            f"profile '{selected}' is missing a required setting: {exc}"
        ) from exc

    private_key = Path(values["private_key"]).expanduser()
    if not private_key.is_absolute():
        private_key = settings_path.parent / private_key
    _validate_private_file(private_key, "private key")
    return Profile(
        base_url=_validate_api_url(
            str(raw.get("base_url", DEFAULT_BASE_URL)).rstrip("/") + "/"
        ),
        project_id=str(raw["project_id"])
        if raw.get("project_id") is not None
        else None,
        service_principal_id=values["service_principal_id"],
        kid=values["kid"],
        private_key=private_key,
    )
