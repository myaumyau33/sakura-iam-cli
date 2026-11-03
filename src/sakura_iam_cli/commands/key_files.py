from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from sakura_iam_cli import core


def load_key_records(key_dir: Path) -> list[tuple[Path, dict]]:
    metadata_paths = sorted(key_dir.glob("*.public.json"))
    if not metadata_paths:
        raise core.CliError(f"no *.public.json upload records found in {key_dir}")
    records = []
    for path in metadata_paths:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise core.CliError(f"invalid upload record {path}: {exc}") from exc
        if "id" not in record:
            raise core.CliError(f"upload record does not contain key id: {path}")
        if "target_service_principal_id" not in record:
            raise core.CliError(
                f"upload record does not contain target service principal id: {path}"
            )
        records.append((path, record))
    return records


def load_api_key_credentials(path: Path) -> tuple[str, str]:
    _validate_credentials_file(path)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        access_token = value["access_token"]
        access_token_secret = value["access_token_secret"]
    except FileNotFoundError as exc:
        raise core.CliError(f"API key credentials file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise core.CliError(f"invalid API key credentials JSON: {exc}") from exc
    except (KeyError, TypeError) as exc:
        raise core.CliError(
            f"API key credentials file is missing a required setting: {exc}"
        ) from exc
    if not isinstance(access_token, str) or not isinstance(access_token_secret, str):
        raise core.CliError("API key credentials must be strings")
    return access_token, access_token_secret


def _validate_credentials_file(path: Path) -> None:
    try:
        file_stat = path.stat()
    except FileNotFoundError:
        return
    if not path.is_file():
        raise core.CliError(f"API key credentials is not a regular file: {path}")
    if os.name != "nt" and stat.S_IMODE(file_stat.st_mode) & 0o077:
        raise core.CliError(
            f"API key credentials permissions are too open: {path}; run chmod 600 {path}"
        )
