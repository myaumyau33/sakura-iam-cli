import base64
import json
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from sakura_iam_cli.core import CliError, Profile, create_assertion, generate_key_pairs
from sakura_iam_cli import core


def decode_part(value: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def test_generate_distinct_rsa_keys(tmp_path: Path):
    paths = generate_key_pairs(tmp_path, 2)
    assert len(paths) == 2
    private_paths = sorted(tmp_path.glob("*.private.pem"))
    keys = [serialization.load_pem_private_key(path.read_bytes(), None) for path in private_paths]
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
        project_id="project-1",
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


def test_service_principal_api_requests(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/iam/1.0/", "10", "auth-sp", "kid", tmp_path / "key")
    requests = []
    monkeypatch.setattr(
        core,
        "_request_json",
        lambda request: requests.append(request) or {"ok": True},
    )

    core.list_service_principals(
        profile, "token", page=2, per_page=50, project_id="10", ordering="-name"
    )
    core.create_service_principal(profile, "token", "10", "worker", "description")
    core.read_service_principal(profile, "token", "sp/1")
    core.update_service_principal(profile, "token", "sp/1", "renamed", "updated")
    core.delete_service_principal(profile, "token", "sp/1")
    core.list_service_principal_keys(
        profile, "token", "sp/1", page=1, per_page=20, ordering="-created_at"
    )

    assert [request.method for request in requests] == [
        "GET", "POST", "GET", "PUT", "DELETE", "GET"
    ]
    assert requests[0].full_url == (
        "https://example.test/iam/1.0/service-principals?"
        "page=2&per_page=50&project_id=10&ordering=-name"
    )
    assert json.loads(requests[1].data) == {
        "project_id": 10,
        "name": "worker",
        "description": "description",
    }
    assert requests[2].full_url.endswith("/service-principals/sp%2F1")
    assert json.loads(requests[3].data) == {"name": "renamed", "description": "updated"}
    assert requests[4].full_url.endswith("/service-principals/sp%2F1")
    assert requests[5].full_url.endswith(
        "/service-principals/sp%2F1/keys?page=1&per_page=20&ordering=-created_at"
    )
    assert all(request.headers["Authorization"] == "Bearer token" for request in requests)
