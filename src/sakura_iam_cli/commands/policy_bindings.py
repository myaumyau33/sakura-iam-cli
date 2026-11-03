from __future__ import annotations

import questionary


def role_is_grantable_at(role: dict, scope: str) -> bool:
    levels = {"organization": 0, "folder": 1, "project": 2}
    lowest = role.get("lowest_grantable_resource")
    return (
        isinstance(lowest, str) and lowest in levels and levels[scope] <= levels[lowest]
    )


def build_iam_role_choices(
    roles: list[dict], scope: str, bindings: list[dict], principals: list[dict]
) -> list[questionary.Choice]:
    selected_principals = {
        (principal["type"], principal["id"]) for principal in principals
    }
    assignment_counts: dict[str, int] = {}
    for binding in bindings:
        role = binding.get("role")
        binding_principals = binding.get("principals")
        if not isinstance(role, dict) or not isinstance(binding_principals, list):
            continue
        role_id = role.get("id")
        if not isinstance(role_id, str):
            continue
        assigned = {
            (principal.get("type"), principal.get("id"))
            for principal in binding_principals
            if isinstance(principal, dict)
        }
        assignment_counts[role_id] = len(selected_principals & assigned)

    choices = []
    for role in roles:
        if "id" not in role or not role_is_grantable_at(role, scope):
            continue
        role_id = str(role["id"])
        assigned_count = assignment_counts.get(role_id, 0)
        fully_assigned = bool(selected_principals) and assigned_count == len(
            selected_principals
        )
        partial_label = (
            " [一部割当済み]" if 0 < assigned_count < len(selected_principals) else ""
        )
        choices.append(
            questionary.Choice(
                f"[{role.get('category', '-')}] "
                f"{role.get('name', role_id)} ({role_id}){partial_label}",
                value=role_id,
                checked=fully_assigned,
            )
        )
    return choices


def merge_iam_policy_bindings(
    bindings: list[dict], role_ids: list[str], principals: list[dict]
) -> list[dict]:
    merged = [
        {
            "role": dict(binding["role"]),
            "principals": [dict(principal) for principal in binding["principals"]],
        }
        for binding in bindings
    ]
    by_role = {binding["role"]["id"]: binding for binding in merged}
    for role_id in role_ids:
        binding = by_role.get(role_id)
        if binding is None:
            binding = {
                "role": {"type": "preset", "id": role_id},
                "principals": [],
            }
            merged.append(binding)
            by_role[role_id] = binding
        existing = {
            (principal["type"], principal["id"]) for principal in binding["principals"]
        }
        for principal in principals:
            key = (principal["type"], principal["id"])
            if key not in existing:
                binding["principals"].append(dict(principal))
                existing.add(key)
    return merged


def build_iam_role_removal_choices(
    roles: list[dict], bindings: list[dict], principals: list[dict]
) -> list[questionary.Choice]:
    selected_principals = {
        (principal["type"], principal["id"]) for principal in principals
    }
    role_assignments: dict[str, set[tuple[object, object]]] = {}
    for binding in bindings:
        role = binding.get("role")
        binding_principals = binding.get("principals")
        if not isinstance(role, dict) or not isinstance(binding_principals, list):
            continue
        role_id = role.get("id")
        if not isinstance(role_id, str):
            continue
        role_assignments[role_id] = {
            (principal.get("type"), principal.get("id"))
            for principal in binding_principals
            if isinstance(principal, dict)
        }
    roles_by_id = {
        str(role["id"]): role
        for role in roles
        if isinstance(role, dict) and "id" in role
    }
    choices = []
    for role_id, assigned in role_assignments.items():
        assigned_count = len(selected_principals & assigned)
        if assigned_count == 0:
            continue
        role = roles_by_id.get(role_id, {"id": role_id})
        partial_label = (
            " [一部のみ割当済み]"
            if assigned_count < len(selected_principals)
            else " [全対象に割当済み]"
        )
        choices.append(
            questionary.Choice(
                f"[{role.get('category', '-')}] "
                f"{role.get('name', role_id)} ({role_id}){partial_label}",
                value=role_id,
            )
        )
    return choices


def remove_iam_policy_bindings(
    bindings: list[dict], role_ids: list[str], principals: list[dict]
) -> list[dict]:
    removals = {(principal["type"], principal["id"]) for principal in principals}
    selected_roles = set(role_ids)
    updated = []
    for binding in bindings:
        role = dict(binding["role"])
        binding_principals = [dict(principal) for principal in binding["principals"]]
        if role["id"] in selected_roles:
            binding_principals = [
                principal
                for principal in binding_principals
                if (principal["type"], principal["id"]) not in removals
            ]
        if binding_principals:
            updated.append({"role": role, "principals": binding_principals})
    return updated
