from __future__ import annotations

from typing import Any

from sakura_iam_cli import config, transport


def list_service_policy_rule_templates(
    profile: config.Profile,
    token: str,
    *,
    page: int | None = None,
    per_page: int | None = None,
    name: str | None = None,
    code: str | None = None,
    rule_type: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "service-policy-rule-templates",
        query={
            "page": page,
            "per_page": per_page,
            "name": name,
            "code": code,
            "type": rule_type,
        },
    )


def list_organization_service_policy_rules(
    profile: config.Profile,
    token: str,
    *,
    is_active: bool | None = None,
    is_dry_run: bool | None = None,
    name: str | None = None,
    code: str | None = None,
    rule_type: str | None = None,
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "GET",
        "organization-service-policy",
        query={
            "is_active": is_active,
            "is_dry_run": is_dry_run,
            "name": name,
            "code": code,
            "type": rule_type,
        },
    )


def update_organization_service_policy_rules(
    profile: config.Profile, token: str, rules: list[dict[str, Any]]
) -> dict[str, Any]:
    return transport.request_iam(
        profile,
        token,
        "PUT",
        "organization-service-policy",
        json_body={"rules": rules},
    )
