import json
from pathlib import Path

from sakura_iam_cli import core, transport
from sakura_iam_cli.core import (
    Profile,
)


def test_id_role_and_policy_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )
    bindings = [
        {
            "role": {"type": "preset", "id": "identity-admin"},
            "principals": [{"type": "user", "id": 100}],
        }
    ]

    core.list_id_roles(profile, "token", page=2, per_page=25)
    core.read_id_role(profile, "token", "identity/admin")
    core.read_organization_id_policy(profile, "token")
    core.update_organization_id_policy(profile, "token", bindings)

    assert [request.method for request in requests] == ["GET", "GET", "GET", "PUT"]
    assert requests[0].full_url.endswith("/id-roles?page=2&per_page=25")
    assert requests[1].full_url.endswith("/id-roles/identity%2Fadmin")
    assert requests[2].full_url.endswith("/organization-id-policy")
    assert requests[3].full_url.endswith("/organization-id-policy")
    assert json.loads(requests[3].data) == {"bindings": bindings}
    assert all(
        request.headers["Authorization"] == "Bearer token" for request in requests
    )


def test_organization_and_service_policy_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )
    rules = [
        {
            "code": "cloud-restrict-zone",
            "spec": {
                "contents": [{"allow_all": True, "deny_all": False, "values": {}}]
            },
            "is_active": True,
            "is_dry_run": False,
        }
    ]

    core.read_organization(profile, "token")
    core.update_organization(profile, "token", "New Organization")
    core.get_service_policy_status(profile, "token")
    core.enable_service_policy(profile, "token")
    core.disable_service_policy(profile, "token")
    core.list_service_policy_rule_templates(
        profile,
        "token",
        page=2,
        per_page=25,
        name="Zone",
        code="zone",
        rule_type="list",
    )
    core.list_organization_service_policy_rules(
        profile,
        "token",
        is_active=True,
        is_dry_run=False,
        code="zone",
        rule_type="list",
    )
    core.update_organization_service_policy_rules(profile, "token", rules)

    assert [request.method for request in requests] == [
        "GET",
        "PUT",
        "GET",
        "POST",
        "POST",
        "GET",
        "GET",
        "PUT",
    ]
    assert requests[0].full_url.endswith("/organization")
    assert json.loads(requests[1].data) == {"name": "New Organization"}
    assert requests[2].full_url.endswith("/service-policy-status")
    assert requests[3].full_url.endswith("/enable-service-policy")
    assert requests[4].full_url.endswith("/disable-service-policy")
    assert requests[5].full_url.endswith(
        "/service-policy-rule-templates?page=2&per_page=25&name=Zone&code=zone&type=list"
    )
    assert requests[6].full_url.endswith(
        "/organization-service-policy?is_active=true&is_dry_run=false&code=zone&type=list"
    )
    assert json.loads(requests[7].data) == {"rules": rules}


def test_auth_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )
    password_policy = {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_symbols": False,
    }
    conditions = {
        "ip_restriction": {"mode": "allow_all"},
        "require_two_factor_auth": {"enabled": True},
        "datetime_restriction": {"after": None, "before": None},
    }

    core.read_auth_context(profile, "token")
    core.read_password_policy(profile, "token")
    core.update_password_policy(profile, "token", password_policy)
    core.read_auth_conditions(profile, "token")
    core.update_auth_conditions(profile, "token", conditions)

    assert [request.method for request in requests] == [
        "GET",
        "GET",
        "PUT",
        "GET",
        "PUT",
    ]
    assert requests[0].full_url.endswith("/auth/context")
    assert requests[1].full_url.endswith("/organization-password-policy")
    assert json.loads(requests[2].data) == password_policy
    assert requests[3].full_url.endswith("/organization-auth-conditions")
    assert json.loads(requests[4].data) == conditions


def test_iam_policy_requests(tmp_path: Path, monkeypatch):
    profile = Profile(
        "https://example.test/iam/1.0/", "10", "sp", "kid", tmp_path / "key"
    )
    requests = []
    monkeypatch.setattr(
        transport, "_request_json", lambda request: requests.append(request) or {}
    )
    bindings = [
        {
            "role": {"type": "preset", "id": "owner"},
            "principals": [{"type": "user", "id": 100}],
        }
    ]

    core.read_organization_iam_policy(profile, "token")
    core.update_organization_iam_policy(profile, "token", bindings)
    core.read_folder_iam_policy(profile, "token", "20")
    core.update_folder_iam_policy(profile, "token", "20", bindings)
    core.read_project_iam_policy(profile, "token", "30")
    core.update_project_iam_policy(profile, "token", "30", bindings)

    assert [request.method for request in requests] == [
        "GET",
        "PUT",
        "GET",
        "PUT",
        "GET",
        "PUT",
    ]
    assert requests[0].full_url.endswith("/organization-iam-policy")
    assert requests[1].full_url.endswith("/organization-iam-policy")
    assert requests[2].full_url.endswith("/folders/20/iam-policy")
    assert requests[3].full_url.endswith("/folders/20/iam-policy")
    assert requests[4].full_url.endswith("/projects/30/iam-policy")
    assert requests[5].full_url.endswith("/projects/30/iam-policy")
    assert all(
        json.loads(request.data) == {"bindings": bindings} for request in requests[1::2]
    )
