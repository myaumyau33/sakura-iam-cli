from __future__ import annotations

import ipaddress
import json
from datetime import datetime
from pathlib import Path

from sakura_iam_cli import core
from sakura_iam_cli.commands import common


def load_role_policy(path: Path, label: str) -> list[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise core.CliError(f"{label} file not found: {path}") from exc
    except OSError as exc:
        raise core.CliError(f"could not read {label} file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise core.CliError(f"invalid {label} JSON in {path}: {exc}") from exc

    if not isinstance(document, dict) or set(document) != {"bindings"}:
        raise core.CliError(f"{label} must be a JSON object containing only 'bindings'")
    bindings = document["bindings"]
    if not isinstance(bindings, list):
        raise core.CliError(f"{label} 'bindings' must be an array")
    for binding_index, binding in enumerate(bindings):
        location = f"bindings[{binding_index}]"
        if not isinstance(binding, dict) or set(binding) != {"role", "principals"}:
            raise core.CliError(f"{location} must contain only 'role' and 'principals'")
        role = binding["role"]
        if (
            not isinstance(role, dict)
            or set(role) != {"type", "id"}
            or role.get("type") != "preset"
            or not isinstance(role.get("id"), str)
            or not role["id"]
        ):
            raise core.CliError(
                f"{location}.role must contain type 'preset' and a non-empty string id"
            )
        principals = binding["principals"]
        if not isinstance(principals, list):
            raise core.CliError(f"{location}.principals must be an array")
        for principal_index, principal in enumerate(principals):
            principal_location = f"{location}.principals[{principal_index}]"
            if (
                not isinstance(principal, dict)
                or set(principal) != {"type", "id"}
                or not isinstance(principal.get("type"), str)
                or not principal["type"]
                or not isinstance(principal.get("id"), int)
                or isinstance(principal["id"], bool)
            ):
                raise core.CliError(
                    f"{principal_location} must contain a non-empty string type and an integer id"
                )
    return bindings


def load_id_policy(path: Path) -> list[dict]:
    return load_role_policy(path, "ID policy")


def validate_rule_spec(spec: object, location: str) -> None:
    if not isinstance(spec, dict) or not set(spec) <= {"contents"}:
        raise core.CliError(f"{location} may contain only a 'contents' array")
    if "contents" not in spec:
        return
    contents = spec["contents"]
    if not isinstance(contents, list):
        raise core.CliError(f"{location}.contents must be an array")
    for index, content in enumerate(contents):
        content_location = f"{location}.contents[{index}]"
        allowed_keys = {"values", "allow_all", "deny_all", "enforce"}
        if not isinstance(content, dict) or not set(content) <= allowed_keys:
            raise core.CliError(f"{content_location} contains unsupported fields")
        for key in ("allow_all", "deny_all", "enforce"):
            if key in content and not isinstance(content[key], bool):
                raise core.CliError(f"{content_location}.{key} must be a boolean")
        if "values" not in content:
            continue
        values = content["values"]
        if not isinstance(values, dict) or not set(values) <= {
            "allowed_values",
            "denied_values",
        }:
            raise core.CliError(
                f"{content_location}.values contains unsupported fields"
            )
        for key, items in values.items():
            if not isinstance(items, list) or not all(
                isinstance(item, str) for item in items
            ):
                raise core.CliError(
                    f"{content_location}.values.{key} must be an array of strings"
                )


def load_service_policy_rules(path: Path) -> list[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise core.CliError(f"service policy file not found: {path}") from exc
    except OSError as exc:
        raise core.CliError(
            f"could not read service policy file {path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise core.CliError(f"invalid service policy JSON in {path}: {exc}") from exc
    if not isinstance(document, dict) or set(document) != {"rules"}:
        raise core.CliError(
            "service policy must be a JSON object containing only 'rules'"
        )
    rules = document["rules"]
    if not isinstance(rules, list):
        raise core.CliError("service policy 'rules' must be an array")
    normalized = []
    for index, rule in enumerate(rules):
        location = f"rules[{index}]"
        allowed_keys = {
            "code",
            "spec",
            "dry_run_spec",
            "is_active",
            "is_dry_run",
            "name",
        }
        if not isinstance(rule, dict) or not set(rule) <= allowed_keys:
            raise core.CliError(f"{location} contains unsupported fields")
        if not isinstance(rule.get("code"), str) or not rule["code"]:
            raise core.CliError(f"{location}.code must be a non-empty string")
        for key in ("is_active", "is_dry_run"):
            if not isinstance(rule.get(key), bool):
                raise core.CliError(f"{location}.{key} must be a boolean")
        if "spec" not in rule and "dry_run_spec" not in rule:
            raise core.CliError(f"{location} must contain 'spec' or 'dry_run_spec'")
        for key in ("spec", "dry_run_spec"):
            if key in rule:
                validate_rule_spec(rule[key], f"{location}.{key}")
        normalized.append({key: value for key, value in rule.items() if key != "name"})
    return normalized


def load_password_policy(path: Path) -> dict:
    policy = common.load_json_object(path, "password policy")
    required = {
        "min_length",
        "require_uppercase",
        "require_lowercase",
        "require_symbols",
    }
    if set(policy) != required:
        raise core.CliError(
            "password policy must contain only min_length, require_uppercase, "
            "require_lowercase, and require_symbols"
        )
    min_length = policy["min_length"]
    if (
        not isinstance(min_length, int)
        or isinstance(min_length, bool)
        or not 8 <= min_length <= 64
    ):
        raise core.CliError(
            "password policy min_length must be an integer from 8 through 64"
        )
    for key in required - {"min_length"}:
        if not isinstance(policy[key], bool):
            raise core.CliError(f"password policy {key} must be a boolean")
    return policy


def validate_datetime(value: object, location: str) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise core.CliError(f"{location} must be an ISO 8601 date-time string or null")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise core.CliError(
            f"{location} must be an ISO 8601 date-time string or null"
        ) from exc
    if parsed.tzinfo is None:
        raise core.CliError(f"{location} must include a UTC offset")


def load_auth_conditions(path: Path) -> dict:
    conditions = common.load_json_object(path, "authentication conditions")
    required = {"ip_restriction", "require_two_factor_auth", "datetime_restriction"}
    if set(conditions) != required:
        raise core.CliError(
            "authentication conditions must contain only ip_restriction, "
            "require_two_factor_auth, and datetime_restriction"
        )

    restriction = conditions["ip_restriction"]
    if not isinstance(restriction, dict) or restriction.get("mode") not in {
        "allow_all",
        "allow_list",
    }:
        raise core.CliError("ip_restriction.mode must be 'allow_all' or 'allow_list'")
    if restriction["mode"] == "allow_all":
        if set(restriction) != {"mode"}:
            raise core.CliError("allow_all ip_restriction may contain only 'mode'")
    else:
        if set(restriction) != {"mode", "source_network"}:
            raise core.CliError(
                "allow_list ip_restriction requires only mode and source_network"
            )
        networks = restriction["source_network"]
        if not isinstance(networks, list) or not networks:
            raise core.CliError(
                "ip_restriction.source_network must be a non-empty array"
            )
        for index, network in enumerate(networks):
            if not isinstance(network, str):
                raise core.CliError(
                    f"ip_restriction.source_network[{index}] must be an IPv4 CIDR"
                )
            try:
                parsed_network = ipaddress.ip_network(network, strict=False)
            except ValueError as exc:
                raise core.CliError(
                    f"ip_restriction.source_network[{index}] must be an IPv4 CIDR"
                ) from exc
            if parsed_network.version != 4 or "/" not in network:
                raise core.CliError(
                    f"ip_restriction.source_network[{index}] must be an IPv4 CIDR"
                )

    two_factor = conditions["require_two_factor_auth"]
    if (
        not isinstance(two_factor, dict)
        or set(two_factor) != {"enabled"}
        or not isinstance(two_factor["enabled"], bool)
    ):
        raise core.CliError(
            "require_two_factor_auth must contain only a boolean enabled field"
        )

    datetime_restriction = conditions["datetime_restriction"]
    if not isinstance(datetime_restriction, dict) or set(datetime_restriction) != {
        "after",
        "before",
    }:
        raise core.CliError("datetime_restriction must contain only after and before")
    validate_datetime(datetime_restriction["after"], "datetime_restriction.after")
    validate_datetime(datetime_restriction["before"], "datetime_restriction.before")
    return conditions
