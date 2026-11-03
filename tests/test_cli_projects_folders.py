from typer.testing import CliRunner

from sakura_iam_cli import cli
from sakura_iam_cli.commands import (
    common,
)

runner = CliRunner()


def test_project_delete_dry_run_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(cli.app, ["project", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_project_move_dry_run_to_root_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(
        cli.app,
        [
            "project",
            "move",
            "--project-id",
            "1",
            "--project-id",
            "2",
            "--to-root",
            "--dry-run",
        ],
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
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(cli.app, ["folder", "delete", "123", "--dry-run"])
    assert result.exit_code == 0
    assert "would_delete" in result.stdout


def test_folder_move_dry_run_to_root_does_not_authenticate(monkeypatch):
    monkeypatch.setattr(
        common,
        "authenticated",
        lambda *_: (_ for _ in ()).throw(AssertionError("authenticated")),
    )
    result = runner.invoke(
        cli.app,
        [
            "folder",
            "move",
            "--folder-id",
            "1",
            "--folder-id",
            "2",
            "--to-root",
            "--dry-run",
        ],
    )
    assert result.exit_code == 0
    assert '"parent_id": null' in result.stdout
    assert "would_move" in result.stdout


def test_folder_move_requires_exactly_one_destination():
    result = runner.invoke(cli.app, ["folder", "move", "--folder-id", "1"])
    assert result.exit_code == 1
    assert "exactly one" in result.stderr
