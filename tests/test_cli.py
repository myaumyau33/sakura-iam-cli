import json
import stat
from pathlib import Path

from typer.testing import CliRunner

from sakura_iam_cli import cli
from sakura_iam_cli.core import Profile

runner = CliRunner()


def test_delete_dry_run_does_not_authenticate_or_modify_record(tmp_path: Path, monkeypatch):
    record_path = tmp_path / "sp-key-001.public.json"
    original = {
        "id": 123,
        "target_service_principal_id": "target-sp",
        "status": "uploaded",
    }
    record_path.write_text(json.dumps(original))
    monkeypatch.setattr(
        cli, "load_profile", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    result = runner.invoke(
        cli.app,
        ["sp-key", "delete", "--key-dir", str(tmp_path), "--dry-run"],
    )
    assert result.exit_code == 0
    assert "would_delete" in result.stdout
    assert json.loads(record_path.read_text()) == original


def test_delete_uses_recorded_id_and_marks_record_deleted(tmp_path: Path, monkeypatch):
    record_path = tmp_path / "sp-key-001.public.json"
    record_path.write_text(
        json.dumps(
            {
                "id": 123,
                "kid": "kid",
                "target_service_principal_id": "target-sp",
                "status": "uploaded",
            }
        )
    )
    profile = Profile("https://example.test/", "p", "sp", "auth-kid", tmp_path / "auth.pem")
    deleted = []
    monkeypatch.setattr(cli, "load_profile", lambda *_: profile)
    monkeypatch.setattr(cli, "issue_access_token", lambda _: "token")
    monkeypatch.setattr(
        cli,
        "delete_service_principal_key",
        lambda actual_profile, token, sp_id, key_id: deleted.append(
            (actual_profile, token, sp_id, key_id)
        ),
    )

    result = runner.invoke(
        cli.app, ["sp-key", "delete", "--key-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert deleted == [(profile, "token", "target-sp", "123")]
    assert json.loads(record_path.read_text())["status"] == "deleted"


def test_disable_uses_recorded_target_and_updates_status(tmp_path: Path, monkeypatch):
    record_path = tmp_path / "sp-key-001.public.json"
    record_path.write_text(json.dumps({
        "id": 123,
        "target_service_principal_id": "target-sp",
        "status": "enabled",
    }))
    profile = Profile("https://example.test/", "p", "auth-sp", "kid", tmp_path / "auth.pem")
    changed = []
    monkeypatch.setattr(cli, "load_profile", lambda *_: profile)
    monkeypatch.setattr(cli, "issue_access_token", lambda _: "token")
    monkeypatch.setattr(
        cli,
        "change_service_principal_key_state",
        lambda actual_profile, token, sp_id, key_id, action: changed.append(
            (actual_profile, token, sp_id, key_id, action)
        ) or {"id": 123, "status": "disabled"},
    )

    result = runner.invoke(
        cli.app, ["sp-key", "disable", "--key-dir", str(tmp_path)]
    )
    assert result.exit_code == 0
    assert changed == [(profile, "token", "target-sp", "123", "disable")]
    assert json.loads(record_path.read_text())["status"] == "disabled"


def test_service_principal_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["sp", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_api_key_create_saves_secret_with_private_permissions(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", tmp_path / "auth.pem")
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "create_project_api_key",
        lambda *_: {"id": 123, "access_token": "token", "access_token_secret": "secret"},
    )
    output = tmp_path / "credentials.json"
    result = runner.invoke(
        cli.app,
        [
            "api-key", "create", "--name", "automation", "--iam-role", "admin",
            "--output", str(output),
        ],
    )
    assert result.exit_code == 0
    assert json.loads(output.read_text())["access_token_secret"] == "secret"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


def test_api_key_single_server_options_must_be_paired():
    result = runner.invoke(
        cli.app,
        [
            "api-key", "create", "--name", "single", "--iam-role", "viewer",
            "--server-resource-id", "server-1",
        ],
    )
    assert result.exit_code == 1
    assert "must be specified together" in result.stderr


def test_api_key_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["api-key", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_api_key_auth_status_reads_created_credentials(tmp_path: Path, monkeypatch):
    credentials = tmp_path / "api-key.json"
    credentials.write_text(
        json.dumps({"access_token": "access", "access_token_secret": "secret"})
    )
    credentials.chmod(0o600)
    calls = []
    monkeypatch.setattr(
        cli,
        "get_cloud_auth_status",
        lambda *args, **kwargs: calls.append((args, kwargs))
        or {"is_ok": True, "Account": {"ID": "123"}},
    )

    result = runner.invoke(
        cli.app, ["api-key", "auth-status", str(credentials), "--zone", "tk1a"]
    )

    assert result.exit_code == 0
    assert calls == [(('access', 'secret'), {"zone": "tk1a"})]
    assert json.loads(result.stdout)["Account"]["ID"] == "123"


def test_api_key_auth_status_rejects_open_credentials_file(
    tmp_path: Path, monkeypatch
):
    credentials = tmp_path / "api-key.json"
    credentials.write_text(
        json.dumps({"access_token": "access", "access_token_secret": "secret"})
    )
    credentials.chmod(0o644)
    monkeypatch.setattr(
        cli,
        "get_cloud_auth_status",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("requested")),
    )

    result = runner.invoke(cli.app, ["api-key", "auth-status", str(credentials)])

    assert result.exit_code == 1
    assert "permissions are too open" in result.stderr


def test_provisioning_create_saves_secret_with_restricted_permissions(
    tmp_path: Path, monkeypatch
):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "create_scim_configuration",
        lambda *args: {
            "id": "config-1",
            "name": args[-1],
            "base_url": "https://example.test/scim/config-1/v2/",
            "secret_token": "secret",
        },
    )
    output = tmp_path / "provisioning.json"

    result = runner.invoke(
        cli.app,
        [
            "provisioning",
            "create",
            "--name",
            "Microsoft Entra ID",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(output.read_text())["secret_token"] == "secret"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "secret" not in result.stdout


def test_provisioning_commands(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    calls = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "list_scim_configurations",
        lambda *args, **kwargs: calls.append(("list", args, kwargs)) or {"items": []},
    )
    monkeypatch.setattr(
        cli,
        "read_scim_configuration",
        lambda *args: calls.append(("get", args)) or {"id": args[-1]},
    )
    monkeypatch.setattr(
        cli,
        "update_scim_configuration",
        lambda *args: calls.append(("update", args)) or {"id": args[-2]},
    )

    listed = runner.invoke(
        cli.app, ["provisioning", "list", "--page", "2", "--per-page", "25"]
    )
    fetched = runner.invoke(cli.app, ["provisioning", "get", "config-1"])
    updated = runner.invoke(
        cli.app,
        ["provisioning", "update", "config-1", "--name", "Renamed"],
    )

    assert listed.exit_code == fetched.exit_code == updated.exit_code == 0
    assert calls[0] == ("list", (profile, "token"), {"page": 2, "per_page": 25})
    assert calls[1] == ("get", (profile, "token", "config-1"))
    assert calls[2] == ("update", (profile, "token", "config-1", "Renamed"))


def test_provisioning_destructive_dry_runs_do_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    deleted = runner.invoke(
        cli.app, ["provisioning", "delete", "config-1", "--dry-run"]
    )
    regenerated = runner.invoke(
        cli.app,
        ["provisioning", "regenerate-token", "config-1", "--dry-run"],
    )

    assert deleted.exit_code == regenerated.exit_code == 0
    assert "would_delete" in deleted.stdout
    assert "would_regenerate_token" in regenerated.stdout


def test_provisioning_regenerate_token_saves_secret(tmp_path: Path, monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "regenerate_scim_configuration_token",
        lambda *args: {"secret_token": "new-secret"},
    )
    output = tmp_path / "new-token.json"

    result = runner.invoke(
        cli.app,
        [
            "provisioning",
            "regenerate-token",
            "config-1",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert json.loads(output.read_text()) == {"secret_token": "new-secret"}
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert "new-secret" not in result.stdout


def test_id_role_commands(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    calls = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "list_id_roles",
        lambda *args, **kwargs: calls.append((args, kwargs)) or {"items": []},
    )
    monkeypatch.setattr(
        cli,
        "read_id_role",
        lambda *args: calls.append((args, {})) or {"id": args[-1]},
    )

    listed = runner.invoke(cli.app, ["id-role", "list", "--page", "2", "--per-page", "25"])
    fetched = runner.invoke(cli.app, ["id-role", "get", "identity-admin"])

    assert listed.exit_code == 0
    assert fetched.exit_code == 0
    assert calls[0] == ((profile, "token"), {"page": 2, "per_page": 25})
    assert calls[1] == ((profile, "token", "identity-admin"), {})


def test_id_policy_update_validates_and_updates(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text(json.dumps({"bindings": [{
        "role": {"type": "preset", "id": "identity-admin"},
        "principals": [{"type": "user", "id": 100}],
    }]}))
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "update_organization_id_policy",
        lambda *args: received.append(args) or {"bindings": args[-1]},
    )

    result = runner.invoke(cli.app, ["id-policy", "update", str(policy_file)])

    assert result.exit_code == 0
    assert received == [(profile, "token", [{
        "role": {"type": "preset", "id": "identity-admin"},
        "principals": [{"type": "user", "id": 100}],
    }])]


def test_id_policy_update_dry_run_does_not_authenticate(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text('{"bindings": []}')
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    result = runner.invoke(
        cli.app, ["id-policy", "update", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "would_update" in result.stdout


def test_id_policy_rejects_invalid_document(tmp_path: Path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_text('{"bindings": [{"role": {"type": "custom", "id": "admin"}}]}')

    result = runner.invoke(cli.app, ["id-policy", "update", str(policy_file), "--dry-run"])

    assert result.exit_code == 1
    assert "role" in result.stderr


def test_organization_update_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    result = runner.invoke(
        cli.app, ["organization", "update", "--name", "New Organization", "--dry-run"]
    )

    assert result.exit_code == 0
    assert "would_update" in result.stdout


def test_service_policy_state_dry_runs_do_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    for action in ("enable", "disable"):
        result = runner.invoke(cli.app, ["service-policy", action, "--dry-run"])
        assert result.exit_code == 0
        assert f"would_{action}" in result.stdout


def test_service_policy_update_normalizes_list_response(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "service-policy.json"
    policy_file.write_text(json.dumps({"rules": [{
        "code": "cloud-restrict-zone",
        "name": "ゾーン制限",
        "spec": {"contents": [{
            "allow_all": False,
            "deny_all": False,
            "values": {"allowed_values": ["is:iaas"]},
        }]},
        "is_active": True,
        "is_dry_run": False,
    }]}))
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "update_organization_service_policy_rules",
        lambda *args: received.append(args) or {"rules": args[-1]},
    )

    result = runner.invoke(cli.app, ["service-policy", "update", str(policy_file)])

    assert result.exit_code == 0
    assert received[0][2][0]["code"] == "cloud-restrict-zone"
    assert "name" not in received[0][2][0]


def test_service_policy_update_rejects_invalid_rules(tmp_path: Path):
    policy_file = tmp_path / "service-policy.json"
    policy_file.write_text('{"rules": [{"code": "rule", "is_active": true}]}')

    result = runner.invoke(
        cli.app, ["service-policy", "update", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "is_dry_run" in result.stderr


def test_password_policy_update_validates_and_dry_runs(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "password-policy.json"
    policy_file.write_text(json.dumps({
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_symbols": False,
    }))
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    result = runner.invoke(
        cli.app, ["auth", "update-password-policy", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 0
    assert "would_update" in result.stdout


def test_password_policy_rejects_out_of_range_length(tmp_path: Path):
    policy_file = tmp_path / "password-policy.json"
    policy_file.write_text(json.dumps({
        "min_length": 7,
        "require_uppercase": False,
        "require_lowercase": False,
        "require_symbols": False,
    }))

    result = runner.invoke(
        cli.app, ["auth", "update-password-policy", str(policy_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "8 through 64" in result.stderr


def test_auth_conditions_update_validates_and_updates(tmp_path: Path, monkeypatch):
    conditions_file = tmp_path / "conditions.json"
    conditions = {
        "ip_restriction": {
            "mode": "allow_list",
            "source_network": ["192.0.2.0/24"],
        },
        "require_two_factor_auth": {"enabled": True},
        "datetime_restriction": {
            "after": "2026-08-01T00:00:00+09:00",
            "before": None,
        },
    }
    conditions_file.write_text(json.dumps(conditions))
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "update_auth_conditions",
        lambda *args: received.append(args) or args[-1],
    )

    result = runner.invoke(cli.app, ["auth", "update-conditions", str(conditions_file)])

    assert result.exit_code == 0
    assert received == [(profile, "token", conditions)]


def test_auth_conditions_reject_invalid_network(tmp_path: Path):
    conditions_file = tmp_path / "conditions.json"
    conditions_file.write_text(json.dumps({
        "ip_restriction": {"mode": "allow_list", "source_network": ["not-a-cidr"]},
        "require_two_factor_auth": {"enabled": False},
        "datetime_restriction": {"after": None, "before": None},
    }))

    result = runner.invoke(
        cli.app, ["auth", "update-conditions", str(conditions_file), "--dry-run"]
    )

    assert result.exit_code == 1
    assert "IPv4 CIDR" in result.stderr


def test_iam_policy_requires_exactly_one_target():
    missing = runner.invoke(cli.app, ["iam-policy", "get"])
    duplicate = runner.invoke(
        cli.app,
        ["iam-policy", "get", "--organization", "--project-id", "10"],
    )

    assert missing.exit_code == 1
    assert duplicate.exit_code == 1
    assert "exactly one" in missing.stderr
    assert "exactly one" in duplicate.stderr


def test_iam_policy_update_dry_run_does_not_authenticate(tmp_path: Path, monkeypatch):
    policy_file = tmp_path / "iam-policy.json"
    policy_file.write_text(json.dumps({"bindings": [{
        "role": {"type": "preset", "id": "owner"},
        "principals": [{"type": "group", "id": 100}],
    }]}))
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )

    result = runner.invoke(
        cli.app,
        [
            "iam-policy", "update", str(policy_file),
            "--folder-id", "20", "--dry-run",
        ],
    )

    assert result.exit_code == 0
    output = json.loads(result.stdout)
    assert output["status"] == "would_update"
    assert output["target"] == {"type": "folder", "id": "20"}


def test_iam_policy_get_dispatches_project(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    received = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "read_project_iam_policy",
        lambda *args: received.append(args) or {"bindings": []},
    )

    result = runner.invoke(cli.app, ["iam-policy", "get", "--project-id", "30"])

    assert result.exit_code == 0
    assert received == [(profile, "token", "30")]


def test_merge_iam_policy_bindings_preserves_existing_and_deduplicates():
    bindings = [{
        "role": {"type": "preset", "id": "owner"},
        "principals": [{"type": "user", "id": 10}],
    }]
    principals = [
        {"type": "user", "id": 10},
        {"type": "service-principal", "id": 20},
    ]

    merged = cli.merge_iam_policy_bindings(bindings, ["owner", "viewer"], principals)

    assert bindings[0]["principals"] == [{"type": "user", "id": 10}]
    assert merged == [
        {
            "role": {"type": "preset", "id": "owner"},
            "principals": [
                {"type": "user", "id": 10},
                {"type": "service-principal", "id": 20},
            ],
        },
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": principals,
        },
    ]


def test_iam_role_choices_preselect_common_roles_and_mark_partial_roles():
    principals = [
        {"type": "user", "id": 10},
        {"type": "service-principal", "id": 20},
    ]
    bindings = [
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": principals,
        },
        {
            "role": {"type": "preset", "id": "editor"},
            "principals": [{"type": "user", "id": 10}],
        },
    ]
    roles = [
        {
            "id": "viewer", "name": "Viewer", "category": "cloud",
            "lowest_grantable_resource": "project",
        },
        {
            "id": "editor", "name": "Editor", "category": "cloud",
            "lowest_grantable_resource": "project",
        },
        {
            "id": "folder-admin", "name": "Folder Admin", "category": "iam",
            "lowest_grantable_resource": "folder",
        },
    ]

    choices = cli.build_iam_role_choices(roles, "project", bindings, principals)

    assert [choice.value for choice in choices] == ["viewer", "editor"]
    assert choices[0].checked is True
    assert choices[1].checked is False
    assert "一部割当済み" in choices[1].title


def test_iam_role_choices_preselect_all_existing_roles_for_one_principal():
    principal = {"type": "user", "id": 10}
    bindings = [
        {
            "role": {"type": "preset", "id": role_id},
            "principals": [principal],
        }
        for role_id in ("viewer", "editor")
    ]
    roles = [
        {
            "id": role_id, "name": role_id, "category": "cloud",
            "lowest_grantable_resource": "project",
        }
        for role_id in ("viewer", "editor")
    ]

    choices = cli.build_iam_role_choices(roles, "project", bindings, [principal])

    assert all(choice.checked for choice in choices)


def test_remove_iam_policy_bindings_removes_only_selected_assignments():
    bindings = [
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": [
                {"type": "user", "id": 10},
                {"type": "service-principal", "id": 20},
            ],
        },
        {
            "role": {"type": "preset", "id": "editor"},
            "principals": [{"type": "user", "id": 10}],
        },
    ]

    updated = cli.remove_iam_policy_bindings(
        bindings, ["viewer"], [{"type": "user", "id": 10}]
    )

    assert updated == [
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": [{"type": "service-principal", "id": 20}],
        },
        bindings[1],
    ]


def test_remove_iam_policy_bindings_drops_empty_binding():
    bindings = [{
        "role": {"type": "preset", "id": "viewer"},
        "principals": [{"type": "user", "id": 10}],
    }]

    updated = cli.remove_iam_policy_bindings(
        bindings, ["viewer"], [{"type": "user", "id": 10}]
    )

    assert updated == []


def test_iam_policy_add_interactively_selects_principals_and_roles(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter([
        ["service-principal", "user"],
        [20],
        [10],
        ["owner", "viewer"],
    ])
    updated = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "read_organization_iam_policy",
        lambda *_: {"bindings": [{
            "role": {"type": "preset", "id": "owner"},
            "principals": [{"type": "user", "id": 10}],
        }]},
    )
    monkeypatch.setattr(
        cli,
        "list_service_principals",
        lambda *args, **kwargs: {
            "count": 1, "items": [{"id": 20, "name": "Worker"}]
        },
    )
    monkeypatch.setattr(
        cli,
        "list_users",
        lambda *args, **kwargs: {
            "count": 1, "items": [{"id": 10, "name": "User", "code": "user"}]
        },
    )
    monkeypatch.setattr(
        cli,
        "list_iam_roles",
        lambda *args, **kwargs: {
            "count": 2,
            "items": [
                {
                    "id": "owner", "name": "Owner", "category": "iam",
                    "lowest_grantable_resource": "project",
                },
                {
                    "id": "viewer", "name": "Viewer", "category": "cloud",
                    "lowest_grantable_resource": "project",
                },
            ],
        },
    )
    monkeypatch.setattr(cli, "interactive_checkbox", lambda *_: next(selections))
    monkeypatch.setattr(cli, "interactive_confirm", lambda *_: True)
    monkeypatch.setattr(
        cli,
        "update_organization_iam_policy",
        lambda *args: updated.append(args) or {"bindings": args[-1]},
    )

    result = runner.invoke(cli.app, ["iam-policy", "add", "--organization"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "updated"
    assert len(updated) == 1
    owner, viewer = updated[0][-1]
    assert owner["principals"] == [
        {"type": "user", "id": 10},
        {"type": "service-principal", "id": 20},
    ]
    assert viewer["principals"] == [
        {"type": "service-principal", "id": 20},
        {"type": "user", "id": 10},
    ]


def test_iam_policy_add_dry_run_does_not_update(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter([["user"], [10], ["viewer"]])
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli, "read_project_iam_policy", lambda *_: {"bindings": []}
    )
    monkeypatch.setattr(
        cli,
        "list_users",
        lambda *args, **kwargs: {"count": 1, "items": [{"id": 10, "name": "User"}]},
    )
    monkeypatch.setattr(
        cli,
        "list_iam_roles",
        lambda *args, **kwargs: {"count": 1, "items": [{
            "id": "viewer", "name": "Viewer", "category": "cloud",
            "lowest_grantable_resource": "project",
        }]},
    )
    monkeypatch.setattr(cli, "interactive_checkbox", lambda *_: next(selections))
    monkeypatch.setattr(
        cli,
        "interactive_confirm",
        lambda *_: (_ for _ in ()).throw(AssertionError("confirmed")),
    )
    monkeypatch.setattr(
        cli,
        "update_project_iam_policy",
        lambda *_: (_ for _ in ()).throw(AssertionError("updated")),
    )

    result = runner.invoke(
        cli.app, ["iam-policy", "add", "--project-id", "30", "--dry-run"]
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["status"] == "would_update"


def test_interactive_iam_policy_target_selects_organization(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(cli, "interactive_select", lambda *_: "organization")
    monkeypatch.setattr(
        cli, "read_organization", lambda *_: {"id": 1, "name": "Organization"}
    )

    assert cli.select_iam_policy_target(profile, "token") == ("organization", None)


def test_interactive_iam_policy_target_selects_folder(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter(["folder", "20"])
    monkeypatch.setattr(cli, "interactive_select", lambda *_: next(selections))
    monkeypatch.setattr(
        cli,
        "list_folders",
        lambda *args, **kwargs: {
            "count": 1, "items": [{"id": 20, "name": "Production"}]
        },
    )

    assert cli.select_iam_policy_target(profile, "token") == ("folder", "20")


def test_interactive_iam_policy_target_selects_project(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter(["project", "30"])
    monkeypatch.setattr(cli, "interactive_select", lambda *_: next(selections))
    monkeypatch.setattr(
        cli,
        "list_projects",
        lambda *args, **kwargs: {
            "count": 1,
            "items": [{"id": 30, "name": "Application", "code": "app"}],
        },
    )

    assert cli.select_iam_policy_target(profile, "token") == ("project", "30")


def test_iam_policy_delete_dry_run_removes_selected_assignment(monkeypatch):
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    selections = iter([["user"], [10], ["viewer"]])
    bindings = [
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": [
                {"type": "user", "id": 10},
                {"type": "service-principal", "id": 20},
            ],
        },
        {
            "role": {"type": "preset", "id": "editor"},
            "principals": [{"type": "user", "id": 10}],
        },
    ]
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli, "read_project_iam_policy", lambda *_: {"bindings": bindings}
    )
    monkeypatch.setattr(
        cli,
        "list_users",
        lambda *args, **kwargs: {
            "count": 2,
            "items": [
                {"id": 10, "name": "Assigned", "code": "assigned"},
                {"id": 99, "name": "Unassigned", "code": "unassigned"},
            ],
        },
    )
    monkeypatch.setattr(
        cli,
        "list_iam_roles",
        lambda *args, **kwargs: {
            "count": 2,
            "items": [
                {"id": "viewer", "name": "Viewer", "category": "cloud"},
                {"id": "editor", "name": "Editor", "category": "cloud"},
            ],
        },
    )
    seen_choices = []

    def select(_message, choices):
        seen_choices.append(choices)
        return next(selections)

    monkeypatch.setattr(cli, "interactive_checkbox", select)
    monkeypatch.setattr(
        cli,
        "interactive_confirm",
        lambda *_: (_ for _ in ()).throw(AssertionError("confirmed")),
    )
    monkeypatch.setattr(
        cli,
        "update_project_iam_policy",
        lambda *_: (_ for _ in ()).throw(AssertionError("updated")),
    )

    result = runner.invoke(
        cli.app, ["iam-policy", "delete", "--project-id", "30", "--dry-run"]
    )

    assert result.exit_code == 0
    assert [choice.value for choice in seen_choices[1]] == [10]
    output = json.loads(result.stdout)
    assert output["bindings"][0]["principals"] == [
        {"type": "service-principal", "id": 20}
    ]
    assert output["bindings"][1] == bindings[1]


def test_project_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["project", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_project_move_dry_run_to_root_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(
        cli.app,
        ["project", "move", "--project-id", "1", "--project-id", "2", "--to-root", "--dry-run"],
    )
    assert result.exit_code == 0
    assert '"parent_folder_id": null' in result.stdout
    assert "would_move" in result.stdout


def test_project_move_requires_exactly_one_destination():
    result = runner.invoke(cli.app, ["project", "move", "--project-id", "1"])
    assert result.exit_code == 1
    assert "exactly one" in result.stderr


def test_folder_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["folder", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_folder_move_dry_run_to_root_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(
        cli.app,
        ["folder", "move", "--folder-id", "1", "--folder-id", "2", "--to-root", "--dry-run"],
    )
    assert result.exit_code == 0
    assert '"parent_id": null' in result.stdout
    assert "would_move" in result.stdout


def test_folder_move_requires_exactly_one_destination():
    result = runner.invoke(cli.app, ["folder", "move", "--folder-id", "1"])
    assert result.exit_code == 1
    assert "exactly one" in result.stderr


def test_group_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(cli.app, ["group", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_group_set_members_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    result = runner.invoke(
        cli.app,
        ["group", "set-members", "1", "--user-id", "100", "--user-id", "200", "--dry-run"],
    )
    assert result.exit_code == 0
    assert "would_replace_members" in result.stdout


def test_group_set_members_requires_users_or_clear():
    result = runner.invoke(cli.app, ["group", "set-members", "1"])
    assert result.exit_code == 1
    assert "--clear" in result.stderr


def test_user_create_reads_password_file_without_printing_password(tmp_path: Path, monkeypatch):
    password_file = tmp_path / "password"
    password_file.write_text("Secret123\n")
    profile = Profile("https://example.test/", "10", "sp", "kid", tmp_path / "auth.pem")
    received = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(
        cli,
        "create_user",
        lambda *args: received.append(args) or {"id": 123, "name": "User"},
    )
    result = runner.invoke(
        cli.app,
        [
            "user", "create", "--name", "User", "--code", "user-code",
            "--password-file", str(password_file),
        ],
    )
    assert result.exit_code == 0
    assert received[0][4] == "Secret123"
    assert "Secret123" not in result.stdout


def test_user_destructive_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        cli, "authenticated", lambda *_: (_ for _ in ()).throw(AssertionError("authenticated"))
    )
    for arguments in (
        ["user", "delete", "1", "--dry-run"],
        ["user", "deactivate-otp", "1", "--dry-run"],
        ["user", "clear-trusted-devices", "1", "--dry-run"],
        ["user", "delete-security-key", "1", "2", "--dry-run"],
    ):
        result = runner.invoke(cli.app, arguments)
        assert result.exit_code == 0
        assert "would_" in result.stdout


def test_resource_mv_dry_run_resolves_paths_without_mutation(monkeypatch):
    tree = cli.ResourceTree(
        [{"id": 1, "name": "Production", "parent_id": None}],
        [{"id": 10, "name": "App", "code": "app", "parent_folder_id": None}],
    )
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(cli, "load_resource_tree", lambda *_: tree)
    monkeypatch.setattr(
        cli, "move_projects", lambda *_: (_ for _ in ()).throw(AssertionError("moved"))
    )
    result = runner.invoke(
        cli.app, ["resource", "mv", "/app", "/Production", "--dry-run"]
    )
    assert result.exit_code == 0
    assert "would_move" in result.stdout
    assert '"id": "10"' in result.stdout


def test_resource_mkdir_parents_creates_each_missing_folder(monkeypatch):
    tree = cli.ResourceTree(
        [{"id": 1, "name": "Production", "parent_id": None}], []
    )
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    created = []
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(cli, "load_resource_tree", lambda *_: tree)

    def fake_create(_profile, _token, name, description, parent_id):
        created.append((name, description, parent_id))
        return {"id": len(created) + 1, "name": name, "parent_id": parent_id}

    monkeypatch.setattr(cli, "create_folder", fake_create)
    result = runner.invoke(
        cli.app,
        [
            "resource", "mkdir", "/Production/App/Logs", "--parents",
            "--description", "log folder",
        ],
    )
    assert result.exit_code == 0
    assert created == [("App", "", "1"), ("Logs", "log folder", "2")]


def test_resource_mkdir_dry_run_does_not_create(monkeypatch):
    tree = cli.ResourceTree([], [])
    profile = Profile("https://example.test/", "10", "sp", "kid", Path("key"))
    monkeypatch.setattr(cli, "authenticated", lambda *_: (profile, "token"))
    monkeypatch.setattr(cli, "load_resource_tree", lambda *_: tree)
    monkeypatch.setattr(
        cli, "create_folder", lambda *_: (_ for _ in ()).throw(AssertionError("created"))
    )
    result = runner.invoke(
        cli.app, ["resource", "mkdir", "/One/Two", "-p", "--dry-run"]
    )
    assert result.exit_code == 0
    assert "would_create" in result.stdout
