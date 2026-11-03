"""Read IAM ancestry and organization ID policies without modifying resources."""

from __future__ import annotations

from dataclasses import asdict

from . import core
from .permissions import (
    PolicyEvidence,
    evaluate_roles,
    policy_roles,
    report_status,
    resource_id,
)

_READ_ERRORS = (core.CliError, OSError, ValueError, TypeError)


class PermissionAudit:
    def __init__(self, profile: core.Profile, token: str, subject_id: str):
        self.profile = profile
        self.token = token
        self.subject_id = resource_id(subject_id)
        self.iam: list[PolicyEvidence] = []
        self.identity: list[PolicyEvidence] = []
        self.issues: list[dict] = []
        self.ancestry_complete = True
        self.subject_verified = self.subject_id == resource_id(
            profile.service_principal_id
        )
        self.home_project_id: str | None = None
        self.project_limit: str | None = None

    def read(self, source: str, fetch):
        try:
            value = fetch()
            if not isinstance(value, dict):
                raise ValueError("API response must be an object")
            return value
        except _READ_ERRORS as exc:
            self.issues.append({"source": source, "error": str(exc)})
            return None

    def identify(self) -> None:
        if self.subject_verified:
            context = self.read(
                "auth/context", lambda: core.read_auth_context(self.profile, self.token)
            )
            if context is not None:
                try:
                    if (
                        context.get("auth_type") != "service_principal"
                        or resource_id(context.get("resource_id")) != self.subject_id
                    ):
                        raise ValueError(
                            "auth context does not identify the configured service principal"
                        )
                    limit = context.get("limited_to_project_id")
                    self.project_limit = None if limit is None else resource_id(limit)
                    self.home_project_id = self.project_limit
                except ValueError as exc:
                    self.issues.append({"source": "auth/context", "error": str(exc)})
        if self.home_project_id is None:
            source = f"service-principals/{self.subject_id}"
            subject = self.read(
                source,
                lambda: core.read_service_principal(
                    self.profile, self.token, self.subject_id
                ),
            )
            if subject is not None:
                try:
                    if resource_id(subject.get("id")) != self.subject_id:
                        raise ValueError("API returned a different service principal")
                    self.home_project_id = resource_id(subject.get("project_id"))
                    self.subject_verified = True
                except ValueError as exc:
                    self.issues.append({"source": source, "error": str(exc)})

    def policy(self, kind: str, source: str, fetch) -> None:
        target = self.iam if kind == "iam" else self.identity
        document = self.read(source, fetch)
        if document is None:
            target.append(
                PolicyEvidence(source, complete=False, error=self.issues[-1]["error"])
            )
            return
        roles, problems = policy_roles(document, self.subject_id)
        target.append(
            PolicyEvidence(source, roles, not problems, "; ".join(problems) or None)
        )

    def parent_id(self, source: str, document: dict | None, field: str) -> str | None:
        if document is None:
            self.ancestry_complete = False
            return None
        try:
            if resource_id(document.get("id")) != source.rsplit("/", 1)[-1]:
                raise ValueError(
                    "API returned a different resource; ancestry is unknown"
                )
            if field not in document:
                raise ValueError(f"API response omitted {field}; ancestry is unknown")
            return None if document[field] is None else resource_id(document[field])
        except ValueError as exc:
            self.ancestry_complete = False
            self.issues.append({"source": source, "error": str(exc)})
            return None

    def collect_iam(self, scope: str, target_id: str | None) -> None:
        folder_id = None
        if scope == "project":
            self.policy(
                "iam",
                f"projects/{target_id}/iam-policy",
                lambda: core.read_project_iam_policy(
                    self.profile, self.token, target_id
                ),
            )
            source = f"projects/{target_id}"
            project = self.read(
                source, lambda: core.read_project(self.profile, self.token, target_id)
            )
            folder_id = self.parent_id(source, project, "parent_folder_id")
        elif scope == "folder":
            folder_id = target_id
        elif scope != "organization":
            self.ancestry_complete = False
            self.issues.append(
                {
                    "source": "target",
                    "error": "cannot determine target project; specify --project-id, --folder-id, or --organization",
                }
            )
        visited: set[str] = set()
        while folder_id is not None:
            if folder_id in visited:
                self.ancestry_complete = False
                self.issues.append(
                    {
                        "source": f"folders/{folder_id}",
                        "error": "cycle in folder ancestry",
                    }
                )
                break
            visited.add(folder_id)
            current = folder_id
            self.policy(
                "iam",
                f"folders/{current}/iam-policy",
                lambda: core.read_folder_iam_policy(self.profile, self.token, current),
            )
            source = f"folders/{current}"
            folder = self.read(
                source, lambda: core.read_folder(self.profile, self.token, current)
            )
            folder_id = self.parent_id(source, folder, "parent_id")
        self.policy(
            "iam",
            "organization-iam-policy",
            lambda: core.read_organization_iam_policy(self.profile, self.token),
        )

    def run(
        self,
        scope: str | None,
        target_id: str | None,
        iam_roles: list[str],
        id_roles: list[str],
    ) -> dict:
        self.identify()
        if scope is None:
            scope, target_id = (
                ("project", self.home_project_id)
                if self.home_project_id
                else ("unknown", None)
            )
        self.collect_iam(scope, target_id)
        self.policy(
            "id",
            "organization-id-policy",
            lambda: core.read_organization_id_policy(self.profile, self.token),
        )
        iam_complete = (
            self.subject_verified
            and self.ancestry_complete
            and all(item.complete for item in self.iam)
        )
        id_complete = self.subject_verified and all(
            item.complete for item in self.identity
        )
        iam_checks = evaluate_roles(self.iam, iam_roles, iam_complete)
        if scope == "unknown":
            for check in iam_checks:
                check["status"] = "unknown"
        id_checks = evaluate_roles(self.identity, id_roles, id_complete)
        complete = iam_complete and id_complete
        warnings = []
        if (
            scope == "project"
            and self.project_limit is not None
            and target_id != self.project_limit
        ):
            warnings.append(
                "対象はSPの操作可能プロジェクトと異なります。IAM操作を除くクラウドAPIは、ロールがあっても操作できない場合があります。"
            )
        return {
            "service_principal_id": self.subject_id,
            "subject_verified": self.subject_verified,
            "home_project_id": self.home_project_id,
            "limited_to_project_id": self.project_limit,
            "target": {"type": scope, "id": target_id},
            "status": report_status(
                (iam_checks if iam_roles else []) + (id_checks if id_roles else [])
                if iam_roles or id_roles
                else iam_checks + id_checks,
                complete,
                bool(iam_roles or id_roles),
            ),
            "complete": complete,
            "iam": {
                "required_roles": list(dict.fromkeys(iam_roles)),
                "complete": iam_complete,
                "checks": iam_checks,
                "policies": [asdict(item) for item in self.iam],
            },
            "id": {
                "required_roles": list(dict.fromkeys(id_roles)),
                "complete": id_complete,
                "checks": id_checks,
                "policies": [asdict(item) for item in self.identity],
            },
            "issues": self.issues,
            "warnings": warnings,
        }
