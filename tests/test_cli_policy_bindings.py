from sakura_iam_cli.commands import (
    policy_bindings,
)


def test_merge_iam_policy_bindings_preserves_existing_and_deduplicates():
    bindings = [
        {
            "role": {"type": "preset", "id": "owner"},
            "principals": [{"type": "user", "id": 10}],
        }
    ]
    principals = [
        {"type": "user", "id": 10},
        {"type": "service-principal", "id": 20},
    ]

    merged = policy_bindings.merge_iam_policy_bindings(
        bindings, ["owner", "viewer"], principals
    )

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
            "id": "viewer",
            "name": "Viewer",
            "category": "cloud",
            "lowest_grantable_resource": "project",
        },
        {
            "id": "editor",
            "name": "Editor",
            "category": "cloud",
            "lowest_grantable_resource": "project",
        },
        {
            "id": "folder-admin",
            "name": "Folder Admin",
            "category": "iam",
            "lowest_grantable_resource": "folder",
        },
    ]

    choices = policy_bindings.build_iam_role_choices(
        roles, "project", bindings, principals
    )

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
            "id": role_id,
            "name": role_id,
            "category": "cloud",
            "lowest_grantable_resource": "project",
        }
        for role_id in ("viewer", "editor")
    ]

    choices = policy_bindings.build_iam_role_choices(
        roles, "project", bindings, [principal]
    )

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

    updated = policy_bindings.remove_iam_policy_bindings(
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
    bindings = [
        {
            "role": {"type": "preset", "id": "viewer"},
            "principals": [{"type": "user", "id": 10}],
        }
    ]

    updated = policy_bindings.remove_iam_policy_bindings(
        bindings, ["viewer"], [{"type": "user", "id": 10}]
    )

    assert updated == []
