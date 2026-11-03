import pytest

from sakura_iam_cli.permissions import PolicyEvidence, evaluate_roles, policy_roles


def binding(role, principal_type="service-principal", subject=100):
    return {
        "role": {"type": "preset", "id": role},
        "principals": [{"type": principal_type, "id": subject}],
    }


def test_policy_matches_only_the_selected_service_principal():
    document = {
        "bindings": [
            binding("owner", subject="0100"),
            binding("ignored-user", "user"),
            binding("ignored-group", "group"),
            binding("other-sp", subject=200),
        ]
    }
    assert policy_roles(document, "100") == (["owner"], [])


@pytest.mark.parametrize(
    "document", [None, [], {}, {"bindings": None}, {"bindings": "bad"}]
)
def test_missing_policy_data_is_not_an_empty_policy(document):
    roles, problems = policy_roles(document, "100")
    assert roles == []
    assert problems


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        {"role": {}, "principals": []},
        {"role": {"type": "custom", "id": "owner"}, "principals": []},
        {"role": {"type": "preset", "id": "owner"}, "principals": [None]},
    ],
)
def test_malformed_bindings_keep_positive_evidence_but_mark_incomplete(invalid):
    roles, problems = policy_roles({"bindings": [binding("owner"), invalid]}, "100")
    assert roles == ["owner"]
    assert problems


def test_known_roles_pass_but_missing_roles_are_unknown_with_partial_evidence():
    evidence = [
        PolicyEvidence("project:10", ["owner"]),
        PolicyEvidence("organization", complete=False),
    ]
    checks = evaluate_roles(evidence, ["owner", "viewer", "owner"], False)
    assert checks == [
        {"role": "owner", "status": "present", "sources": ["project:10"]},
        {"role": "viewer", "status": "unknown", "sources": []},
    ]
