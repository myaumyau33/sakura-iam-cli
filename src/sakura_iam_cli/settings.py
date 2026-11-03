"""Validate and atomically edit settings without changing unrelated profiles."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import config, errors


def positive_id(value: object, label: str) -> str:
    text = str(value).strip()
    if not text.isdecimal() or int(text) <= 0:
        raise errors.CliError(f"{label} must be a positive integer")
    return str(int(text))


def validate_profile(profile: dict, settings_path: Path) -> dict:
    result = dict(profile)
    result["service_principal_id"] = positive_id(
        result.get("service_principal_id", ""), "service_principal_id"
    )
    kid = result.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise errors.CliError("kid must not be empty")
    result["kid"] = kid.strip()
    key_value = result.get("private_key")
    if not isinstance(key_value, str) or not key_value.strip():
        raise errors.CliError("private_key must not be empty")
    key_path = Path(key_value).expanduser()
    if not key_path.is_absolute():
        key_path = settings_path.parent / key_path
    config._validate_private_file(key_path, "private key")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise errors.CliError(
            f"could not read RSA private key {key_path}: {exc}"
        ) from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise errors.CliError(f"private key is not RSA: {key_path}")
    base_url = result.get("base_url")
    if base_url in (None, "", "-"):
        result.pop("base_url", None)
    else:
        result["base_url"] = config._validate_api_url(str(base_url).rstrip("/") + "/")
    project_id = result.get("project_id")
    if project_id in (None, "", "-"):
        result.pop("project_id", None)
    else:
        result["project_id"] = positive_id(project_id, "project_id")
    return result


@dataclass
class SettingsFile:
    path: Path
    document: dict
    original: bytes | None

    @classmethod
    def load(cls, path: Path, *, missing_ok: bool = False) -> SettingsFile:
        path = path.expanduser().resolve()
        if path.exists() and not path.is_file():
            raise errors.CliError(f"settings file is not a regular file: {path}")
        try:
            original = path.read_bytes()
        except FileNotFoundError as exc:
            if missing_ok:
                return cls(path, {"profiles": {}}, None)
            raise errors.CliError(f"settings file not found: {path}") from exc
        try:
            document = json.loads(original)
        except (ValueError, UnicodeDecodeError) as exc:
            raise errors.CliError(f"invalid settings JSON: {path}") from exc
        profiles = document.get("profiles") if isinstance(document, dict) else None
        if not isinstance(profiles, dict) or not all(
            isinstance(name, str) and name.strip() and isinstance(profile, dict)
            for name, profile in profiles.items()
        ):
            raise errors.CliError(
                "settings must contain a profiles object mapping names to profile objects"
            )
        if "default_profile" in document and (
            not isinstance(document["default_profile"], str)
            or not document["default_profile"].strip()
        ):
            raise errors.CliError("default_profile must be a non-empty profile name")
        return cls(path, document, original)

    def selected_name(self, requested: str | None) -> str:
        return requested or self.document.get("default_profile", "default")

    def save(self) -> None:
        profiles = self.document["profiles"]
        if self.document.get("default_profile", "default") not in profiles:
            raise errors.CliError(
                "default profile does not exist; choose it with 'config use NAME'"
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                os.chmod(temporary, 0o600)
                json.dump(self.document, stream, ensure_ascii=False, indent=2)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            try:
                current = self.path.read_bytes()
            except FileNotFoundError:
                current = None
            if current != self.original:
                raise errors.CliError(
                    "settings changed while editing; retry with the latest settings"
                )
            if self.original is None:
                try:
                    os.link(temporary, self.path)
                except FileExistsError as exc:
                    raise errors.CliError(
                        "settings file was created while editing; retry"
                    ) from exc
            else:
                os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)
