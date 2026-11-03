import base64
import json
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sakura_iam_cli.core import (
    CliError,
    Profile,
    create_assertion,
    generate_key_pairs,
    load_profile,
)


def decode_part(value: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def write_profile(tmp_path: Path, base_url: str = "https://example.test/") -> Path:
    private_key = tmp_path / "key.private.pem"
    private_key.write_text("placeholder", encoding="ascii")
    private_key.chmod(0o600)
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "profiles": {
                    "default": {
                        "base_url": base_url,
                        "project_id": "1",
                        "service_principal_id": "2",
                        "kid": "kid",
                        "private_key": private_key.name,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    settings.chmod(0o600)
    return settings


def test_generate_distinct_rsa_keys(tmp_path: Path):
    paths = generate_key_pairs(tmp_path, 2)
    assert len(paths) == 2
    private_paths = sorted(tmp_path.glob("*.private.pem"))
    keys = [
        serialization.load_pem_private_key(path.read_bytes(), None)
        for path in private_paths
    ]
    assert all(isinstance(key, rsa.RSAPrivateKey) for key in keys)
    assert keys[0].private_numbers() != keys[1].private_numbers()
    assert stat.S_IMODE(private_paths[0].stat().st_mode) == 0o600


def test_generate_refuses_overwrite(tmp_path: Path):
    generate_key_pairs(tmp_path, 1)
    with pytest.raises(CliError, match="overwrite"):
        generate_key_pairs(tmp_path, 1)


def test_assertion_claims(tmp_path: Path):
    generate_key_pairs(tmp_path, 1)
    profile = Profile(
        base_url="https://example.test/iam/1.0/",
        project_id=None,
        service_principal_id="sp-1",
        kid="kid-1",
        private_key=tmp_path / "sp-key-001.private.pem",
    )
    header, payload, _ = create_assertion(profile, now=1000).split(".")
    assert decode_part(header) == {"alg": "RS256", "kid": "kid-1", "typ": "JWT"}
    assert decode_part(payload) == {
        "aud": "https://example.test/iam/1.0/service-principals/oauth2/token",
        "exp": 1300,
        "iat": 1000,
        "iss": "sp-1",
        "sub": "sp-1",
    }


@pytest.mark.parametrize("include_null", [False, True])
def test_load_profile_without_project_id(tmp_path: Path, include_null):
    settings = write_profile(tmp_path)
    data = json.loads(settings.read_text())
    profile = data["profiles"]["default"]
    if include_null:
        profile["project_id"] = None
    else:
        del profile["project_id"]
    settings.write_text(json.dumps(data))

    loaded = load_profile(settings)
    assert loaded.project_id is None
    assert loaded.service_principal_id == "2"


def test_load_profile_retains_optional_project_default(tmp_path: Path):
    assert load_profile(write_profile(tmp_path)).project_id == "1"


def test_load_profile_requires_secure_files_and_https(tmp_path: Path):
    settings = write_profile(tmp_path)
    assert load_profile(settings).base_url == "https://example.test/"

    settings.chmod(0o644)
    with pytest.raises(CliError, match="settings file permissions"):
        load_profile(settings)
    settings.chmod(0o600)

    (tmp_path / "key.private.pem").chmod(0o644)
    with pytest.raises(CliError, match="private key permissions"):
        load_profile(settings)


def test_load_profile_allows_only_loopback_http(tmp_path: Path):
    settings = write_profile(tmp_path, "http://127.0.0.1:8000/api")
    assert load_profile(settings).base_url == "http://127.0.0.1:8000/api/"

    settings = write_profile(tmp_path, "http://example.test/api")
    with pytest.raises(CliError, match="must use HTTPS"):
        load_profile(settings)
