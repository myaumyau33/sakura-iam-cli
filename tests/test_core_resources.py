import json
from pathlib import Path

from sakura_iam_cli import core, transport
from sakura_iam_cli.core import (
    Profile,
)


def test_scim_configuration_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )

    core.list_scim_configurations(profile, "token", page=2, per_page=25)
    core.create_scim_configuration(profile, "token", "Microsoft Entra ID")
    core.read_scim_configuration(profile, "token", "config/id")
    core.update_scim_configuration(profile, "token", "config/id", "Renamed")
    core.delete_scim_configuration(profile, "token", "config/id")
    core.regenerate_scim_configuration_token(profile, "token", "config/id")

    assert [request.method for request in requests] == [
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "POST",
    ]
    assert requests[0].full_url.endswith("/scim-configurations?page=2&per_page=25")
    assert json.loads(requests[1].data) == {"name": "Microsoft Entra ID"}
    assert requests[2].full_url.endswith("/scim-configurations/config%2Fid")
    assert json.loads(requests[3].data) == {"name": "Renamed"}
    assert requests[4].full_url.endswith("/scim-configurations/config%2Fid")
    assert requests[5].full_url.endswith(
        "/scim-configurations/config%2Fid/regenerate-token"
    )


def test_project_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )

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
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "POST",
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
        "project_ids": [1, 2],
        "parent_folder_id": None,
    }


def test_folder_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )

    core.list_folders(
        profile, "token", page=2, per_page=20, folder_name="Production", parent_id="99"
    )
    core.create_folder(profile, "token", "Production", "desc", "99")
    core.read_folder(profile, "token", "folder/1")
    core.update_folder(profile, "token", "folder/1", "Renamed", "updated")
    core.delete_folder(profile, "token", "folder/1")
    core.move_folders(profile, "token", ["1", "2"], None)

    assert [request.method for request in requests] == [
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "POST",
    ]
    assert requests[0].full_url.endswith(
        "/folders?page=2&per_page=20&folder_name=Production&parent_id=99"
    )
    assert json.loads(requests[1].data) == {
        "name": "Production",
        "description": "desc",
        "parent_id": 99,
    }
    assert requests[2].full_url.endswith("/folders/folder%2F1")
    assert json.loads(requests[3].data) == {"name": "Renamed", "description": "updated"}
    assert requests[4].full_url.endswith("/folders/folder%2F1")
    assert json.loads(requests[5].data) == {"folder_ids": [1, 2], "parent_id": None}


def test_group_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )

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
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "GET",
        "PUT",
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
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )

    core.list_users(profile, "token", page=2, per_page=20, ordering="-code")
    core.create_user(
        profile, "token", "User", "user-code", "Secret123", "desc", "u@example.com"
    )
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
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "POST",
        "POST",
        "POST",
        "GET",
        "DELETE",
        "POST",
        "GET",
        "GET",
        "DELETE",
    ]
    assert requests[0].full_url.endswith(
        "/compat/users?page=2&per_page=20&ordering=-code"
    )
    assert json.loads(requests[1].data)["password"] == "Secret123"
    assert requests[2].full_url.endswith("/compat/users/user%2F1")
    assert json.loads(requests[3].data)["password"] == "NewSecret123"
    assert requests[5].full_url.endswith("/compat/users/user%2F1/register-email")
    assert json.loads(requests[5].data) == {"email": "new@example.com"}
    assert requests[6].full_url.endswith("/compat/users/user%2F1/unregister-email")
    assert requests[7].full_url.endswith("/compat/users/user%2F1/deactivate-otp")
    assert requests[8].full_url.endswith("/compat/users/user%2F1/trusted-devices")
    assert requests[9].full_url.endswith("/trusted-devices/device%2F1")
    assert requests[10].full_url.endswith(
        "/compat/users/user%2F1/clear-trusted-devices"
    )
    assert requests[11].full_url.endswith("/compat/users/user%2F1/security-keys")
    assert requests[12].full_url.endswith("/security-keys/key%2F1")
    assert requests[13].full_url.endswith("/security-keys/key%2F1")
