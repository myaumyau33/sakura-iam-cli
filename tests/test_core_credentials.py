import json
from pathlib import Path

import pytest

from sakura_iam_cli import core, transport
from sakura_iam_cli.core import (
    CliError,
    Profile,
)


def test_service_principal_api_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "auth-sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport,
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
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "GET",
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
    assert all(
        request.headers["Authorization"] == "Bearer token" for request in requests
    )


def test_project_api_key_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport,
        "_request_json",
        lambda request: requests.append(request) or {"id": 1},
    )

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
        "GET",
        "POST",
        "GET",
        "PUT",
        "DELETE",
        "GET",
        "GET",
    ]
    assert requests[0].full_url.endswith(
        "/compat/api-keys?page=2&per_page=25&ordering=name"
    )
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
        "name": "renamed",
        "description": "updated",
        "iam_roles": ["admin"],
    }
    assert requests[4].full_url.endswith("/compat/api-keys/key%2F1")
    assert requests[5].full_url.endswith("/iam-roles?page=1&per_page=100")
    assert requests[6].full_url.endswith("/iam-roles/role%2F1")


def test_cloud_auth_status_uses_basic_auth_and_zone(tmp_path: Path, monkeypatch):
    requests = []
    monkeypatch.setattr(
        transport,
        "_request_json",
        lambda request: requests.append(request) or {"is_ok": True},
    )

    response = core.get_cloud_auth_status("access", "secret", zone="tk1b")

    assert response == {"is_ok": True}
    assert requests[0].method == "GET"
    assert requests[0].full_url == (
        "https://secure.sakura.ad.jp/cloud/zone/tk1b/api/cloud/1.1/auth-status"
    )
    assert requests[0].headers["Authorization"] == "Basic YWNjZXNzOnNlY3JldA=="


def test_cloud_auth_status_rejects_unknown_zone():
    with pytest.raises(CliError, match="unsupported zone"):
        core.get_cloud_auth_status("access", "secret", zone="invalid")
