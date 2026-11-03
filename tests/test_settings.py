import json
import os
import stat

import pytest

from sakura_iam_cli.core import CliError
from sakura_iam_cli.settings import SettingsFile, validate_profile


def document():
    return {
        "default_profile": "default",
        "profiles": {"default": {"kid": "original"}},
        "custom": [1, 2],
    }


def test_new_settings_are_written_with_private_permissions(tmp_path):
    path = tmp_path / "nested" / "settings.json"
    settings = SettingsFile.load(path, missing_ok=True)
    assert not path.exists()
    settings.document = document()
    settings.save()
    assert json.loads(path.read_text()) == document()
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not list(path.parent.glob(".settings.json.*"))


def test_atomic_replace_failure_preserves_original_and_cleans_up(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(document()))
    original = path.read_bytes()
    settings = SettingsFile.load(path)
    settings.document["profiles"]["default"]["kid"] = "replacement"

    def fail(*args):
        raise OSError("replace failed")

    monkeypatch.setattr(os, "replace", fail)
    with pytest.raises(OSError, match="replace failed"):
        settings.save()
    assert path.read_bytes() == original
    assert not list(tmp_path.glob(".settings.json.*"))


def test_change_during_edit_is_not_overwritten(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(document()))
    settings = SettingsFile.load(path)
    settings.document["profiles"]["default"]["kid"] = "replacement"
    external = {**document(), "concurrent": "keep"}
    path.write_text(json.dumps(external))
    with pytest.raises(CliError, match="changed while editing"):
        settings.save()
    assert json.loads(path.read_text()) == external
    assert not list(tmp_path.glob(".settings.json.*"))


def test_initial_creation_race_is_not_overwritten(tmp_path):
    path = tmp_path / "settings.json"
    settings = SettingsFile.load(path, missing_ok=True)
    settings.document = document()
    path.write_text("external data")
    with pytest.raises(CliError, match="changed while editing"):
        settings.save()
    assert path.read_text() == "external data"


@pytest.mark.parametrize(
    "contents",
    ["not json", "[]", "{}", '{"profiles":[]}', '{"profiles":{"broken":null}}'],
)
def test_invalid_settings_are_not_modified(tmp_path, contents):
    path = tmp_path / "settings.json"
    path.write_text(contents)
    with pytest.raises(CliError):
        SettingsFile.load(path)
    assert path.read_text() == contents


def test_settings_directory_is_rejected(tmp_path):
    with pytest.raises(CliError, match="regular file"):
        SettingsFile.load(tmp_path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink and permissions")
def test_symlink_updates_target_and_remains_a_symlink(tmp_path):
    target = tmp_path / "actual.json"
    target.write_text(json.dumps(document()))
    path = tmp_path / "settings.json"
    path.symlink_to(target)
    settings = SettingsFile.load(path)
    settings.document["profiles"]["default"]["kid"] = "replacement"
    settings.save()
    assert path.is_symlink()
    assert json.loads(target.read_text())["profiles"]["default"]["kid"] == "replacement"
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("service_principal_id", "0", "positive integer"),
        ("service_principal_id", "bad", "positive integer"),
        ("kid", "", "kid must not be empty"),
        ("project_id", "0", "positive integer"),
        ("base_url", "http://example.com/", "HTTPS"),
        ("private_key", "/missing/key.pem", "RSA private key"),
    ],
)
def test_invalid_profile_fields_fail_before_saving(
    tmp_path, config_private_key, field, value, message
):
    profile = {
        "service_principal_id": "100",
        "kid": "kid",
        "private_key": str(config_private_key),
    }
    profile[field] = value
    with pytest.raises(CliError, match=message):
        validate_profile(profile, tmp_path / "settings.json")


def test_unchanged_relative_key_is_resolved_against_settings_directory(
    tmp_path, config_private_key
):
    key = tmp_path / "relative.pem"
    key.write_bytes(config_private_key.read_bytes())
    key.chmod(0o600)
    profile = {
        "service_principal_id": "100",
        "kid": "kid",
        "private_key": "relative.pem",
        "custom": {"keep": True},
    }
    assert validate_profile(profile, tmp_path / "settings.json") == profile
