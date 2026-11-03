from pathlib import Path

from sakura_iam_cli import core, transport

FIELDS = {
    "name": "Company SSO",
    "description": "Employees",
    "idp_entity_id": "urn:example:idp",
    "idp_login_url": "https://idp.example.com/login",
    "idp_logout_url": "",
    "idp_certificate": "-----BEGIN CERTIFICATE-----\nexample\n-----END CERTIFICATE-----\n",
}


def test_sso_api_methods_paths_and_request_bodies(monkeypatch):
    profile = core.Profile("https://example.test/", None, "100", "kid", Path("key"))
    calls = []

    def request(actual_profile, token, method, path, **kwargs):
        assert actual_profile == profile
        assert token == "token"
        calls.append((method, path, kwargs))
        return {"id": 1, **FIELDS}

    monkeypatch.setattr(transport, "request_iam", request)
    core.list_sso_profiles(profile, "token", page=2, per_page=25)
    core.create_sso_profile(profile, "token", **FIELDS)
    core.read_sso_profile(profile, "token", "1/2")
    core.update_sso_profile(profile, "token", "1/2", **FIELDS)
    core.delete_sso_profile(profile, "token", "1/2")
    core.assign_sso_profile(profile, "token", "1/2")
    core.unassign_sso_profile(profile, "token", "1/2")
    assert calls == [
        ("GET", "sso-profiles", {"query": {"page": 2, "per_page": 25}}),
        ("POST", "sso-profiles", {"json_body": FIELDS}),
        ("GET", "sso-profiles/1%2F2", {}),
        ("PUT", "sso-profiles/1%2F2", {"json_body": FIELDS}),
        ("DELETE", "sso-profiles/1%2F2", {}),
        ("POST", "sso-profiles/1%2F2/assign", {}),
        ("POST", "sso-profiles/1%2F2/unassign", {}),
    ]


def test_draft_sso_profile_sends_all_required_properties(monkeypatch):
    calls = []
    monkeypatch.setattr(
        transport, "request_iam", lambda *args, **kwargs: calls.append(kwargs) or {}
    )
    profile = core.Profile("https://example.test/", None, "100", "kid", Path("key"))
    core.create_sso_profile(profile, "token", name="Draft")
    assert calls[0]["json_body"] == {
        "name": "Draft",
        "description": "",
        "idp_entity_id": "",
        "idp_login_url": "",
        "idp_logout_url": "",
        "idp_certificate": "",
    }
