"""Conservative checks of SP role assignments, rather than operation simulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PolicyEvidence:
    source: str
    roles: list[str] = field(default_factory=list)
    complete: bool = True
    error: str | None = None


def resource_id(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("resource ID must be a positive integer")
    if not str(value).isdecimal() or int(value) <= 0:
        raise ValueError("resource ID must be a positive integer")
    return str(int(value))


def policy_roles(document: Any, subject_id: str) -> tuple[list[str], list[str]]:
    """Keep positive evidence even if other bindings cannot be interpreted."""
    if not isinstance(document, dict) or not isinstance(document.get("bindings"), list):
        return [], ["policy response did not contain a bindings array"]
    roles: set[str] = set()
    problems: list[str] = []
    for index, binding in enumerate(document["bindings"]):
        try:
            if not isinstance(binding, dict):
                raise ValueError("binding must be an object")
            role = binding.get("role")
            if (
                not isinstance(role, dict)
                or role.get("type") != "preset"
                or not isinstance(role.get("id"), str)
                or not role["id"]
            ):
                raise ValueError("unsupported or invalid role")
            principals = binding.get("principals")
            if not isinstance(principals, list):
                raise ValueError("principals must be an array")
            for principal in principals:
                if not isinstance(principal, dict) or principal.get("type") not in {
                    "user",
                    "group",
                    "service-principal",
                }:
                    raise ValueError("unsupported or invalid principal")
                principal_id = resource_id(principal.get("id"))
                if (
                    principal["type"] == "service-principal"
                    and principal_id == subject_id
                ):
                    roles.add(role["id"])
        except ValueError as exc:
            problems.append(f"bindings[{index}]: {exc}")
    return sorted(roles), problems


def evaluate_roles(
    evidence: list[PolicyEvidence], required: list[str], complete: bool
) -> list[dict]:
    checks = []
    roles = (
        list(dict.fromkeys(required))
        if required
        else sorted({role for item in evidence for role in item.roles})
    )
    for role in roles:
        sources = [item.source for item in evidence if role in item.roles]
        status = "present" if sources else ("missing" if complete else "unknown")
        checks.append({"role": role, "status": status, "sources": sources})
    return checks


def report_status(checks: list[dict], complete: bool, has_requirements: bool) -> str:
    if any(check["status"] == "missing" for check in checks):
        return "missing"
    if any(check["status"] == "unknown" for check in checks):
        return "unknown"
    if has_requirements:
        return "present"
    return "complete" if complete else "unknown"
