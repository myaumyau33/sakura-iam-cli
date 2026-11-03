import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core, transport
from sakura_iam_cli.commands import common

runner = CliRunner()
FIELDS = {
    "name": "SSO",
    "description": "Employees",
    "idp_entity_id": "urn:example:idp",
    "idp_login_url": "https://idp.example.com/login",
    "idp_logout_url": "https://idp.example.com/logout",
    "idp_certificate": "old certificate",
}


@pytest.fixture
def sso_api(monkeypatch):
    calls, auth_calls = [], []
    profile = core.Profile("https://iam.example.test/", None, "100", "kid", Path("key"))

    def authenticate(ctx):
        auth_calls.append(ctx.obj)
        return profile, "token"

    def request(actual_profile, token, method, path, **kwargs):
        assert actual_profile == profile and token == "token"
        calls.append((method, path, kwargs))
        response = {
            "id": 1,
            **FIELDS,
            "assigned": False,
            "sp_entity_id": "https://sp.example.com/entity",
            "sp_acs_url": "https://sp.example.com/acs",
            "created_at": "timestamp",
        }
        if method == "GET" and path == "sso-profiles":
            return {"items": [response], "count": 1}
        if method == "DELETE":
            return {}
        return {
            **response,
            **kwargs.get("json_body", {}),
            "assigned": path.endswith("/assign"),
        }

    monkeypatch.setattr(common, "authenticated", authenticate)
    monkeypatch.setattr(transport, "request_iam", request)
    return calls, auth_calls


def test_sso_list_and_get_keep_sp_metadata_and_selected_profile(sso_api):
    listed = runner.invoke(
        cli.app,
        ["--profile", "admin", "sso", "list", "--page", "2", "--per-page", "25"],
    )
    fetched = runner.invoke(cli.app, ["sso", "get", "1"])
    assert listed.exit_code == fetched.exit_code == 0
    assert sso_api[1][0].profile_name == "admin"
    assert sso_api[0][0] == (
        "GET",
        "sso-profiles",
        {"query": {"page": 2, "per_page": 25}},
    )
    assert json.loads(fetched.stdout)["sp_acs_url"] == "https://sp.example.com/acs"
    assert (
        json.loads(listed.stdout)["items"][0]["sp_entity_id"]
        == "https://sp.example.com/entity"
    )


def test_sso_create_draft_does_not_assign(sso_api):
    result = runner.invoke(cli.app, ["sso", "create", "--name", "Draft"])
    assert result.exit_code == 0, result.output
    assert len(sso_api[0]) == 1
    method, path, kwargs = sso_api[0][0]
    assert (method, path) == ("POST", "sso-profiles")
    assert kwargs["json_body"] == {
        "name": "Draft",
        "description": "",
        "idp_entity_id": "",
        "idp_login_url": "",
        "idp_logout_url": "",
        "idp_certificate": "",
    }
    assert json.loads(result.stdout)["assigned"] is False


def test_sso_create_with_certificate_file(sso_api, tmp_path):
    certificate = tmp_path / "idp.crt"
    certificate.write_text("certificate with newline\n")
    result = runner.invoke(
        cli.app,
        [
            "sso",
            "create",
            "--name",
            "Company",
            "--description",
            "Employees",
            "--idp-entity-id",
            "urn:example:idp",
            "--idp-login-url",
            "https://idp.example.com/login",
            "--idp-certificate-file",
            str(certificate),
        ],
    )
    assert result.exit_code == 0, result.output
    fields = sso_api[0][0][2]["json_body"]
    assert fields["idp_certificate"] == certificate.read_text()
    assert fields["idp_entity_id"] == "urn:example:idp"
    assert fields["idp_logout_url"] == ""


def test_sso_update_merges_unspecified_values_and_excludes_readonly_fields(sso_api):
    result = runner.invoke(cli.app, ["sso", "update", "1", "--name", "Renamed"])
    assert result.exit_code == 0, result.output
    assert [entry[:2] for entry in sso_api[0]] == [
        ("GET", "sso-profiles/1"),
        ("PUT", "sso-profiles/1"),
    ]
    assert sso_api[0][1][2]["json_body"] == {**FIELDS, "name": "Renamed"}


def test_sso_update_can_explicitly_clear_values_and_accept_literal_certificate(sso_api):
    result = runner.invoke(
        cli.app,
        [
            "sso",
            "update",
            "1",
            "--idp-logout-url",
            "",
            "--idp-certificate",
            "new certificate",
        ],
    )
    assert result.exit_code == 0
    assert sso_api[0][1][2]["json_body"] == {
        **FIELDS,
        "idp_logout_url": "",
        "idp_certificate": "new certificate",
    }


@pytest.mark.parametrize(
    "action,method,path",
    [
        ("assign", "POST", "sso-profiles/1/assign"),
        ("unassign", "POST", "sso-profiles/1/unassign"),
        ("delete", "DELETE", "sso-profiles/1"),
    ],
)
def test_sso_assignment_and_delete_call_only_explicit_operation(
    sso_api, action, method, path
):
    result = runner.invoke(cli.app, ["sso", action, "1"])
    assert result.exit_code == 0, result.output
    assert sso_api[0] == [(method, path, {})]
    if action != "delete":
        assert json.loads(result.stdout)["assigned"] is (action == "assign")


@pytest.mark.parametrize(
    "args",
    [
        ["create", "--name", "SSO"],
        ["update", "1", "--name", "Renamed"],
        ["assign", "1"],
        ["unassign", "1"],
        ["delete", "1"],
    ],
)
def test_sso_mutations_support_offline_dry_run(sso_api, args):
    result = runner.invoke(cli.app, ["sso", *args, "--dry-run"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["dry_run"] is True
    assert sso_api == ([], [])


@pytest.mark.parametrize(
    "args",
    [
        ["update", "1"],
        [
            "create",
            "--name",
            "SSO",
            "--idp-certificate",
            "text",
            "--idp-certificate-file",
            "missing.crt",
        ],
        [
            "create",
            "--name",
            "SSO",
            "--idp-certificate-file",
            "/missing-certificate-file",
        ],
    ],
)
def test_sso_invalid_inputs_do_not_authenticate(sso_api, args):
    result = runner.invoke(cli.app, ["sso", *args])
    assert result.exit_code == 1
    assert sso_api == ([], [])


@pytest.mark.parametrize(
    "current", [{"name": "incomplete"}, None, {**FIELDS, "idp_certificate": None}]
)
def test_sso_update_does_not_wipe_settings_on_invalid_get_response(
    sso_api, monkeypatch, current
):
    monkeypatch.setattr(core, "read_sso_profile", lambda *_: current)
    result = runner.invoke(cli.app, ["sso", "update", "1", "--name", "Renamed"])
    assert result.exit_code == 1
    assert sso_api[0] == []


def test_sso_http_failure_does_not_implicitly_unassign(sso_api, monkeypatch):
    def reject(*args):
        raise core.CliError("HTTP 409: assigned profile cannot be deleted")

    monkeypatch.setattr(core, "delete_sso_profile", reject)
    result = runner.invoke(cli.app, ["sso", "delete", "1"])
    assert result.exit_code == 1
    assert "HTTP 409" in result.stderr
    assert sso_api[0] == []
