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


def test_project_api_key_requests(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key")
    requests = []
    monkeypatch.setattr(core, "_request_json", lambda request: requests.append(request) or {"id": 1})

    core.list_project_api_keys(profile, "token", page=2, per_page=25, ordering="name")
    core.create_project_api_key(
        profile, "token", "10", "key", "desc", ["viewer", "editor"], "server-1", "is1a"
    )
    core.read_project_api_key(profile, "token", "key/1")
    core.update_project_api_key(
        profile, "token", "key/1", "renamed", "updated", ["admin"]
    )
    core.delete_project_api_key(profile, "token", "key/1")
    core.list_iam_roles(profile, "token", page=1, per_page=100)
    core.read_iam_role(profile, "token", "role/1")

    assert [request.method for request in requests] == [
        "GET", "POST", "GET", "PUT", "DELETE", "GET", "GET"
    ]
    assert requests[0].full_url.endswith("/compat/api-keys?page=2&per_page=25&ordering=name")
    assert json.loads(requests[1].data) == {
        "project_id": 10,
        "name": "key",
        "description": "desc",
        "iam_roles": ["viewer", "editor"],
        "server_resource_id": "server-1",
        "zone_id": "is1a",
    }
    assert requests[2].full_url.endswith("/compat/api-keys/key%2F1")
    assert json.loads(requests[3].data) == {
        "name": "renamed", "description": "updated", "iam_roles": ["admin"]
    }
    assert requests[4].full_url.endswith("/compat/api-keys/key%2F1")
    assert requests[5].full_url.endswith("/iam-roles?page=1&per_page=100")
    assert requests[6].full_url.endswith("/iam-roles/role%2F1")


def test_project_requests(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key")
    requests = []
    monkeypatch.setattr(core, "_request_json", lambda request: requests.append(request) or {})

    core.list_projects(
        profile,
        "token",
        page=2,
        per_page=20,
        ordering="-code",
        iam_roles=["resource-viewer", "billing-viewer"],
        parent_folder_id="99",
    )
    core.create_project(profile, "token", "project-code", "Project", "desc", "99")
    core.read_project(profile, "token", "project/1")
    core.update_project(profile, "token", "project/1", "Renamed", "updated")
    core.delete_project(profile, "token", "project/1")
    core.move_projects(profile, "token", ["1", "2"], None)

    assert [request.method for request in requests] == [
        "GET", "POST", "GET", "PUT", "DELETE", "POST"
    ]
    assert requests[0].full_url.endswith(
        "/projects?page=2&per_page=20&ordering=-code&"
        "iam_role=resource-viewer%2Cbilling-viewer&parent_folder_id=99"
    )
    assert json.loads(requests[1].data) == {
        "code": "project-code",
        "name": "Project",
        "description": "desc",
        "parent_folder_id": 99,
    }
    assert requests[2].full_url.endswith("/projects/project%2F1")
    assert json.loads(requests[3].data) == {"name": "Renamed", "description": "updated"}
    assert requests[4].full_url.endswith("/projects/project%2F1")
    assert json.loads(requests[5].data) == {
        "project_ids": [1, 2], "parent_folder_id": None
    }


def test_folder_requests(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key")
    requests = []
    monkeypatch.setattr(core, "_request_json", lambda request: requests.append(request) or {})

    core.list_folders(
        profile, "token", page=2, per_page=20, folder_name="Production", parent_id="99"
    )
    core.create_folder(profile, "token", "Production", "desc", "99")
    core.read_folder(profile, "token", "folder/1")
    core.update_folder(profile, "token", "folder/1", "Renamed", "updated")
    core.delete_folder(profile, "token", "folder/1")
    core.move_folders(profile, "token", ["1", "2"], None)

    assert [request.method for request in requests] == [
        "GET", "POST", "GET", "PUT", "DELETE", "POST"
    ]
    assert requests[0].full_url.endswith(
        "/folders?page=2&per_page=20&folder_name=Production&parent_id=99"
    )
    assert json.loads(requests[1].data) == {
        "name": "Production", "description": "desc", "parent_id": 99
    }
    assert requests[2].full_url.endswith("/folders/folder%2F1")
    assert json.loads(requests[3].data) == {"name": "Renamed", "description": "updated"}
    assert requests[4].full_url.endswith("/folders/folder%2F1")
    assert json.loads(requests[5].data) == {"folder_ids": [1, 2], "parent_id": None}


def test_group_requests(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key")
    requests = []
    monkeypatch.setattr(core, "_request_json", lambda request: requests.append(request) or {})

    core.list_groups(
        profile, "token", page=2, per_page=20, ordering="-name", user_id="100"
    )
    core.create_group(profile, "token", "Operators", "desc")
    core.read_group(profile, "token", "group/1")
    core.update_group(profile, "token", "group/1", "Admins", "updated")
    core.delete_group(profile, "token", "group/1")
    core.list_group_memberships(profile, "token", "group/1")
    core.update_group_memberships(profile, "token", "group/1", ["100", "200"])

    assert [request.method for request in requests] == [
        "GET", "POST", "GET", "PUT", "DELETE", "GET", "PUT"
    ]
    assert requests[0].full_url.endswith(
        "/groups?page=2&per_page=20&ordering=-name&compat_user_id=100"
    )
    assert json.loads(requests[1].data) == {"name": "Operators", "description": "desc"}
    assert requests[2].full_url.endswith("/groups/group%2F1")
    assert json.loads(requests[3].data) == {"name": "Admins", "description": "updated"}
    assert requests[4].full_url.endswith("/groups/group%2F1")
    assert requests[5].full_url.endswith("/groups/group%2F1/memberships")
    assert json.loads(requests[6].data) == {"compat_users": [{"id": 100}, {"id": 200}]}


def test_user_requests(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key")
    requests = []
    monkeypatch.setattr(core, "_request_json", lambda request: requests.append(request) or {})

    core.list_users(profile, "token", page=2, per_page=20, ordering="-code")
    core.create_user(profile, "token", "User", "user-code", "Secret123", "desc", "u@example.com")
    core.read_user(profile, "token", "user/1")
    core.update_user(profile, "token", "user/1", "Renamed", "updated", "NewSecret123")
    core.delete_user(profile, "token", "user/1")
    core.register_user_email(profile, "token", "user/1", "new@example.com")
    core.unregister_user_email(profile, "token", "user/1")
    core.deactivate_user_otp(profile, "token", "user/1")
    core.list_trusted_devices(profile, "token", "user/1")
    core.delete_trusted_device(profile, "token", "user/1", "device/1")
    core.clear_trusted_devices(profile, "token", "user/1")
    core.list_security_keys(profile, "token", "user/1")
    core.read_security_key(profile, "token", "user/1", "key/1")
    core.delete_security_key(profile, "token", "user/1", "key/1")

    assert [request.method for request in requests] == [
        "GET", "POST", "GET", "PUT", "DELETE", "POST", "POST", "POST",
        "GET", "DELETE", "POST", "GET", "GET", "DELETE",
    ]
    assert requests[0].full_url.endswith("/compat/users?page=2&per_page=20&ordering=-code")
    assert json.loads(requests[1].data)["password"] == "Secret123"
    assert requests[2].full_url.endswith("/compat/users/user%2F1")
    assert json.loads(requests[3].data)["password"] == "NewSecret123"
    assert requests[5].full_url.endswith("/compat/users/user%2F1/register-email")
    assert json.loads(requests[5].data) == {"email": "new@example.com"}
    assert requests[6].full_url.endswith("/compat/users/user%2F1/unregister-email")
    assert requests[7].full_url.endswith("/compat/users/user%2F1/deactivate-otp")
    assert requests[8].full_url.endswith("/compat/users/user%2F1/trusted-devices")
    assert requests[9].full_url.endswith("/trusted-devices/device%2F1")
    assert requests[10].full_url.endswith("/compat/users/user%2F1/clear-trusted-devices")
    assert requests[11].full_url.endswith("/compat/users/user%2F1/security-keys")
    assert requests[12].full_url.endswith("/security-keys/key%2F1")
    assert requests[13].full_url.endswith("/security-keys/key%2F1")
