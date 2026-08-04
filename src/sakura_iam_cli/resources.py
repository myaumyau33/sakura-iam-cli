from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .core import CliError


ResourceKind = Literal["folder", "project"]


@dataclass(frozen=True)
class Resource:
    kind: ResourceKind
    id: str
    name: str
    parent_id: str | None
    code: str | None = None

    @classmethod
    def folder(cls, value: dict[str, Any]) -> "Resource":
        parent = value.get("parent_id")
        return cls("folder", str(value["id"]), str(value["name"]), None if parent is None else str(parent))

    @classmethod
    def project(cls, value: dict[str, Any]) -> "Resource":
        parent = value.get("parent_folder_id")
        return cls(
            "project",
            str(value["id"]),
            str(value["name"]),
            None if parent is None else str(parent),
            str(value["code"]),
        )


class ResourceTree:
    def __init__(self, folders: list[dict[str, Any]], projects: list[dict[str, Any]]) -> None:
        self.resources = [Resource.folder(item) for item in folders] + [
            Resource.project(item) for item in projects
        ]
        self.by_id = {(resource.kind, resource.id): resource for resource in self.resources}

    def children(self, folder_id: str | None) -> list[Resource]:
        return sorted(
            (resource for resource in self.resources if resource.parent_id == folder_id),
            key=lambda resource: (resource.kind != "folder", resource.name, resource.id),
        )

    def resolve_folder(self, reference: str) -> Resource | None:
        if reference == "/":
            return None
        if reference.startswith("folder:"):
            folder_id = reference.removeprefix("folder:")
            try:
                return self.by_id[("folder", folder_id)]
            except KeyError as exc:
                raise CliError(f"folder not found: {reference}") from exc
        segments = self._path_segments(reference)
        current: str | None = None
        resolved: Resource | None = None
        for segment in segments:
            matches = [
                resource
                for resource in self.children(current)
                if resource.kind == "folder" and resource.name == segment
            ]
            resolved = self._one(matches, reference)
            current = resolved.id
        return resolved

    def resolve_resource(self, reference: str) -> Resource:
        if reference.startswith("folder:") or reference.startswith("project:"):
            kind, resource_id = reference.split(":", 1)
            try:
                return self.by_id[(kind, resource_id)]  # type: ignore[index]
            except KeyError as exc:
                raise CliError(f"resource not found: {reference}") from exc
        segments = self._path_segments(reference)
        if not segments:
            raise CliError("the root cannot be moved")
        parent_path = "/" + "/".join(segments[:-1])
        parent = self.resolve_folder(parent_path) if len(segments) > 1 else None
        leaf = segments[-1]
        matches = [
            resource
            for resource in self.children(None if parent is None else parent.id)
            if resource.name == leaf or (resource.kind == "project" and resource.code == leaf)
        ]
        return self._one(matches, reference)

    def ensure_valid_move(self, sources: list[Resource], destination: Resource | None) -> None:
        destination_id = None if destination is None else destination.id
        for source in sources:
            if source.kind != "folder":
                continue
            current = destination_id
            while current is not None:
                if current == source.id:
                    raise CliError(f"cannot move folder {source.name!r} into itself or its descendant")
                parent = self.by_id.get(("folder", current))
                current = None if parent is None else parent.parent_id

    def plan_mkdir(self, path: str, parents: bool) -> tuple[str | None, list[str]]:
        segments = self._path_segments(path)
        if not segments:
            raise CliError("cannot create the root folder")
        current: str | None = None
        for index, segment in enumerate(segments):
            matches = [
                resource
                for resource in self.children(current)
                if resource.kind == "folder" and resource.name == segment
            ]
            if matches:
                folder = self._one(matches, path)
                current = folder.id
                if index == len(segments) - 1:
                    if parents:
                        return current, []
                    raise CliError(f"folder already exists: {path}")
                continue
            missing = segments[index:]
            if len(missing) > 1 and not parents:
                parent_path = "/" + "/".join(segments[:index])
                raise CliError(f"parent folder not found: {parent_path or '/'}; use --parents")
            return current, missing
        raise AssertionError("unreachable")

    def add_folder(self, value: dict[str, Any]) -> Resource:
        resource = Resource.folder(value)
        self.resources.append(resource)
        self.by_id[(resource.kind, resource.id)] = resource
        return resource

    @staticmethod
    def _path_segments(reference: str) -> list[str]:
        if not reference.startswith("/"):
            raise CliError(f"resource path must be absolute: {reference}")
        return [segment for segment in reference.strip("/").split("/") if segment]

    @staticmethod
    def _one(matches: list[Resource], reference: str) -> Resource:
        if not matches:
            raise CliError(f"resource not found: {reference}")
        if len(matches) > 1:
            choices = ", ".join(f"{item.kind}:{item.id}" for item in matches)
            raise CliError(f"ambiguous resource path {reference!r}; use one of: {choices}")
        return matches[0]
