import json
import os
import stat

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core, transport
from sakura_iam_cli.config import load_profile

runner = CliRunner()


@pytest.fixture(autouse=True)
def local_settings_only(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    def unexpected(*args, **kwargs):
        pytest.fail("configuration must not authenticate or call any API")

    monkeypatch.setattr(core, "load_profile", unexpected)
    monkeypatch.setattr(core, "issue_access_token", unexpected)
    monkeypatch.setattr(transport._NO_REDIRECT_OPENER, "open", unexpected)


def create_settings(key, *extra):
    result = runner.invoke(
        cli.app,
        [
            "config",
            "init",
            "--service-principal-id",
            "100",
            "--kid",
            "kid",
            "--private-key",
            str(key),
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output


def test_init_prompts_for_three_fields_and_creates_usable_settings(
    tmp_path, config_private_key
):
    result = runner.invoke(
        cli.app, ["config", "init"], input=f"100\nkid\n{config_private_key}\n"
    )
    assert result.exit_code == 0, result.output
    path = tmp_path / "settings.json"
    assert json.loads(path.read_text()) == {
        "default_profile": "default",
        "profiles": {
            "default": {
                "service_principal_id": "100",
                "kid": "kid",
                "private_key": str(config_private_key),
            }
        },
    }
    assert load_profile(path).kid == "kid"
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "BEGIN PRIVATE KEY" not in result.output


def test_add_preserves_profiles_metadata_and_default(tmp_path, config_private_key):
    create_settings(config_private_key)
    path = tmp_path / "settings.json"
    original = json.loads(path.read_text())
    original["custom"] = {"keep": True}
    original["profiles"]["default"]["custom"] = [1, 2]
    path.write_text(json.dumps(original))
    result = runner.invoke(
        cli.app,
        ["config", "add", "production"],
        input=f"200\nprod-kid\n{config_private_key}\n",
    )
    assert result.exit_code == 0, result.output
    saved = json.loads(path.read_text())
    assert saved["default_profile"] == "default"
    assert saved["custom"] == original["custom"]
    assert saved["profiles"]["default"] == original["profiles"]["default"]
    assert saved["profiles"]["production"]["service_principal_id"] == "200"


def test_add_can_prompt_for_name_and_set_default(tmp_path, config_private_key):
    create_settings(config_private_key)
    result = runner.invoke(
        cli.app,
        ["config", "add", "--default"],
        input=f"production\n200\nprod-kid\n{config_private_key}\n",
    )
    assert result.exit_code == 0, result.output
    assert (
        json.loads((tmp_path / "settings.json").read_text())["default_profile"]
        == "production"
    )


def test_edit_single_field_does_not_prompt_or_change_other_fields(
    tmp_path, config_private_key
):
    create_settings(
        config_private_key,
        "--base-url",
        "https://iam.example.test/",
        "--project-id",
        "10",
    )
    path = tmp_path / "settings.json"
    original = json.loads(path.read_text())
    result = runner.invoke(cli.app, ["config", "edit", "--kid", "replacement"])
    assert result.exit_code == 0, result.output
    expected = original
    expected["profiles"]["default"]["kid"] = "replacement"
    assert json.loads(path.read_text()) == expected


def test_edit_interactively_keeps_required_defaults_and_clears_optional_fields(
    tmp_path, config_private_key
):
    create_settings(
        config_private_key,
        "--base-url",
        "https://iam.example.test/",
        "--project-id",
        "10",
    )
    result = runner.invoke(cli.app, ["config", "edit"], input="\nnew-kid\n\n-\n-\n")
    assert result.exit_code == 0, result.output
    profile = load_profile(tmp_path / "settings.json")
    assert profile.kid == "new-kid"
    assert profile.project_id is None
    assert profile.base_url == "https://secure.sakura.ad.jp/cloud/api/iam/1.0/"


def test_global_settings_profile_and_relative_key_path(tmp_path, config_private_key):
    key = tmp_path / "local.pem"
    key.write_bytes(config_private_key.read_bytes())
    key.chmod(0o600)
    settings = tmp_path / "nested" / "custom settings.json"
    result = runner.invoke(
        cli.app,
        [
            "--settings",
            str(settings),
            "--profile",
            "test",
            "config",
            "init",
            "--service-principal-id",
            "100",
            "--kid",
            "kid",
            "--private-key",
            "local.pem",
        ],
    )
    assert result.exit_code == 0, result.output
    profile = load_profile(settings, "test")
    assert profile.private_key == key
    result = runner.invoke(
        cli.app,
        [
            "--settings",
            str(settings),
            "--profile",
            "test",
            "config",
            "edit",
            "--kid",
            "new",
        ],
    )
    assert result.exit_code == 0, result.output
    assert load_profile(settings).kid == "new"


def test_use_and_list_do_not_require_private_key_access(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(
        json.dumps(
            {
                "default_profile": "old",
                "profiles": {
                    "old": {
                        "service_principal_id": "100",
                        "private_key": "/missing/key",
                    },
                    "new": {"service_principal_id": "200"},
                },
            }
        )
    )
    result = runner.invoke(cli.app, ["config", "use", "new"])
    assert result.exit_code == 0, result.output
    assert json.loads(path.read_text())["default_profile"] == "new"
    result = runner.invoke(cli.app, ["config", "list"])
    assert result.exit_code == 0
    assert "old" in result.stdout and "new" in result.stdout
    assert "200" in result.stdout


@pytest.mark.parametrize(
    "command",
    [
        ["config", "init"],
        ["config", "add", "default"],
        ["config", "edit", "missing"],
        ["config", "use", "missing"],
    ],
)
def test_existing_settings_are_preserved_on_invalid_mutation(
    tmp_path, config_private_key, command
):
    create_settings(config_private_key)
    path = tmp_path / "settings.json"
    original = path.read_bytes()
    result = runner.invoke(cli.app, command)
    assert result.exit_code == 1
    assert path.read_bytes() == original


def test_cancelled_init_does_not_create_settings(tmp_path):
    result = runner.invoke(cli.app, ["config", "init"], input="100\n")
    assert result.exit_code != 0
    assert not (tmp_path / "settings.json").exists()


def test_cancelled_edit_does_not_change_settings(tmp_path, config_private_key):
    create_settings(config_private_key)
    path = tmp_path / "settings.json"
    original = path.read_bytes()
    result = runner.invoke(cli.app, ["config", "edit"], input="\n")
    assert result.exit_code != 0
    assert path.read_bytes() == original


def test_invalid_key_does_not_write_settings(tmp_path):
    key = tmp_path / "invalid.pem"
    key.write_text("not a key")
    key.chmod(0o600)
    result = runner.invoke(
        cli.app,
        [
            "config",
            "init",
            "--service-principal-id",
            "100",
            "--kid",
            "kid",
            "--private-key",
            str(key),
        ],
    )
    assert result.exit_code == 1
    assert "RSA private key" in result.stderr
    assert not (tmp_path / "settings.json").exists()
