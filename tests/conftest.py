"""Fixtures for the read-only permission diagnostic."""

from copy import deepcopy
from pathlib import Path

import pytest

from sakura_iam_cli import core, transport
from sakura_iam_cli.commands import common


def sp_binding(role, subject=100, principal_type="service-principal"):
    return {
        "role": {"type": "preset", "id": role},
        "principals": [{"type": principal_type, "id": subject}],
    }


@pytest.fixture
def permission_api(monkeypatch):
    profile = core.Profile("https://example.test/", None, "100", "kid", Path("key"))
    responses = {
        "auth/context": {
            "auth_type": "service_principal",
            "resource_id": 100,
            "limited_to_project_id": 10,
        },
        "service-principals/100": {"id": 100, "project_id": 10},
        "service-principals/200": {"id": 200, "project_id": 20},
        "projects/10": {"id": 10, "parent_folder_id": 2},
        "projects/10/iam-policy": {
            "bindings": [
                sp_binding("owner"),
                sp_binding("unrelated", principal_type="user"),
            ]
        },
        "projects/20": {"id": 20, "parent_folder_id": None},
        "projects/20/iam-policy": {"bindings": [sp_binding("owner", 200)]},
        "folders/2": {"id": 2, "parent_id": 1},
        "folders/2/iam-policy": {"bindings": [sp_binding("config-editor")]},
        "folders/1": {"id": 1, "parent_id": None},
        "folders/1/iam-policy": {"bindings": [sp_binding("resource-viewer")]},
        "organization-iam-policy": {"bindings": [sp_binding("project-creator")]},
        "organization-id-policy": {"bindings": [sp_binding("identity-admin")]},
    }
    calls = []

    def request(actual_profile, token, method, path, **kwargs):
        assert actual_profile == profile
        assert token == "token"
        assert method == "GET", "permission checks must never change resources"
        calls.append(path)
        assert path in responses, f"unexpected endpoint: {path}"
        value = responses[path]
        if isinstance(value, Exception):
            raise value
        return deepcopy(value)

    monkeypatch.setattr(transport, "request_iam", request)
    monkeypatch.setattr(common, "authenticated", lambda *_: (profile, "token"))
    return profile, responses, calls


@pytest.fixture(scope="session")
def config_private_key(tmp_path_factory):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    path = tmp_path_factory.mktemp("configuration-key") / "auth.private.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path
