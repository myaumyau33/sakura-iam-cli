import pytest

from sakura_iam_cli.core import CliError
from sakura_iam_cli.permission_audit import PermissionAudit


def run(api, *, subject="100", scope=None, target=None, iam=None, identity=None):
    return PermissionAudit(api[0], "token", subject).run(
        scope, target, iam or [], identity or []
    )


def test_includes_project_all_ancestors_and_id_policy(permission_api):
    report = run(
        permission_api,
        iam=["owner", "config-editor", "resource-viewer", "project-creator"],
        identity=["identity-admin"],
    )
    assert report["status"] == "present"
    assert report["complete"] is True
    assert report["target"] == {"type": "project", "id": "10"}
    assert [item["source"] for item in report["iam"]["policies"]] == [
        "projects/10/iam-policy",
        "folders/2/iam-policy",
        "folders/1/iam-policy",
        "organization-iam-policy",
    ]
    assert report["iam"]["checks"][2]["sources"] == ["folders/1/iam-policy"]
    assert report["id"]["checks"][0]["sources"] == ["organization-id-policy"]


def test_folder_scope_does_not_inherit_from_descendant_projects(permission_api):
    report = run(permission_api, scope="folder", target="2", iam=["owner"])
    assert report["status"] == "missing"
    assert "projects/10/iam-policy" not in permission_api[2]
    assert report["iam"]["checks"][0]["sources"] == []


def test_organization_scope_only_reads_organization_policies(permission_api):
    report = run(permission_api, scope="organization", iam=["project-creator"])
    assert report["status"] == "present"
    assert len(report["iam"]["policies"]) == 1
    assert not any(
        path.startswith(("projects/", "folders/")) for path in permission_api[2]
    )


def test_id_admin_is_not_an_iam_role_and_owner_is_not_an_id_role(permission_api):
    report = run(permission_api, iam=["identity-admin"], identity=["owner"])
    assert report["status"] == "missing"
    assert all(
        check["status"] == "missing"
        for kind in ("iam", "id")
        for check in report[kind]["checks"]
    )


@pytest.mark.parametrize(
    "endpoint",
    ["organization-iam-policy", "folders/1/iam-policy", "folders/2", "projects/10"],
)
def test_unreadable_or_unknown_ancestry_does_not_prove_a_role_is_missing(
    permission_api, endpoint
):
    permission_api[1][endpoint] = CliError("HTTP 403: access denied")
    report = run(permission_api, iam=["not-found"])
    assert report["status"] == "unknown"
    assert report["iam"]["complete"] is False
    assert report["id"]["complete"] is True
    assert report["iam"]["checks"][0]["status"] == "unknown"


def test_positive_evidence_still_proves_a_required_role_when_an_ancestor_is_unreadable(
    permission_api,
):
    permission_api[1]["organization-iam-policy"] = CliError("HTTP 403")
    report = run(permission_api, iam=["owner"])
    assert report["status"] == "present"
    assert report["complete"] is False


def test_id_policy_failure_is_unknown_and_does_not_erase_iam_evidence(permission_api):
    permission_api[1]["organization-id-policy"] = CliError("HTTP 403")
    report = run(permission_api, iam=["owner"], identity=["identity-admin"])
    assert report["status"] == "unknown"
    assert report["iam"]["checks"][0]["status"] == "present"
    assert report["id"]["checks"][0]["status"] == "unknown"


def test_missing_ancestor_parent_field_is_not_assumed_to_mean_root(permission_api):
    permission_api[1]["folders/2"] = {"id": 2}
    report = run(permission_api, iam=["not-found"])
    assert report["status"] == "unknown"
    assert any("parent_id" in issue["error"] for issue in report["issues"])


def test_successful_http_response_with_invalid_policy_is_unknown(permission_api):
    permission_api[1]["projects/10/iam-policy"] = {"status": 403, "detail": "denied"}
    report = run(permission_api, iam=["owner"])
    assert report["status"] == "unknown"
    assert "bindings array" in report["iam"]["policies"][0]["error"]


def test_parent_metadata_for_another_resource_is_not_trusted(permission_api):
    permission_api[1]["folders/2"] = {"id": 99, "parent_id": None}
    report = run(permission_api, iam=["not-found"])
    assert report["status"] == "unknown"
    assert any("different resource" in issue["error"] for issue in report["issues"])


def test_ancestry_cycles_are_reported_instead_of_hanging(permission_api):
    permission_api[1]["folders/1"]["parent_id"] = 2
    report = run(permission_api, iam=["not-found"])
    assert report["status"] == "unknown"
    assert any("cycle" in issue["error"] for issue in report["issues"])


def test_current_sp_home_can_be_resolved_without_sp_read_permission(permission_api):
    permission_api[1]["service-principals/100"] = CliError("HTTP 403")
    assert run(permission_api)["home_project_id"] == "10"
    assert "service-principals/100" not in permission_api[2]


def test_context_failure_falls_back_to_sp_metadata(permission_api):
    permission_api[1]["auth/context"] = CliError("HTTP 503")
    report = run(permission_api)
    assert report["target"] == {"type": "project", "id": "10"}
    assert report["complete"] is True
    assert report["issues"][0]["source"] == "auth/context"


def test_cannot_resolve_default_target_but_id_check_is_still_independent(
    permission_api,
):
    permission_api[1]["auth/context"] = CliError("HTTP 503")
    permission_api[1]["service-principals/100"] = CliError("HTTP 403")
    report = run(permission_api, identity=["identity-admin"])
    assert report["status"] == "present"
    assert report["target"]["type"] == "unknown"
    assert report["iam"]["complete"] is False
    assert report["id"]["complete"] is True


def test_admin_profile_can_inspect_another_sp(permission_api):
    report = run(permission_api, subject="200", iam=["owner"])
    assert report["target"] == {"type": "project", "id": "20"}
    assert report["status"] == "present"
    assert "auth/context" not in permission_api[2]
    assert report["id"]["checks"] == []


def test_unverified_other_sp_cannot_be_called_missing(permission_api):
    permission_api[1]["service-principals/200"] = CliError("HTTP 404")
    report = run(
        permission_api, subject="200", scope="organization", identity=["identity-admin"]
    )
    assert report["subject_verified"] is False
    assert report["status"] == "unknown"


def test_other_project_warning_does_not_incorrectly_deny_iam_operations(permission_api):
    report = run(permission_api, scope="project", target="20", iam=["project-creator"])
    assert report["status"] == "present"
    assert report["warnings"]
    assert "IAM" in report["warnings"][0]
