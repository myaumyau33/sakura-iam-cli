import base64
import io
import json
import os
import urllib.error

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core, transport
from sakura_iam_cli.commands import common

runner = CliRunner()
URL = "https://api.example.com/status?detail=true"


@pytest.fixture(autouse=True)
def forbid_sp_authentication(monkeypatch):
    def unexpected(*args):
        pytest.fail("API key requests must not load SP settings or acquire an SP token")

    monkeypatch.setattr(common, "authenticated", unexpected)
    monkeypatch.setattr(core, "load_profile", unexpected)
    monkeypatch.setattr(core, "issue_access_token", unexpected)


@pytest.fixture
def credentials(tmp_path):
    path = tmp_path / "api-key.json"
    path.write_text(
        json.dumps({"access_token": "access", "access_token_secret": "secret"})
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def requests(monkeypatch):
    calls = []

    def open_request(request, *, timeout):
        calls.append((request, timeout))
        return io.BytesIO(b"\x00\xffraw response\n")

    monkeypatch.setattr(transport._NO_REDIRECT_OPENER, "open", open_request)
    return calls


def test_api_key_raw_url_uses_basic_auth_without_settings(credentials, requests):
    result = runner.invoke(
        cli.app,
        [
            "--settings",
            "/missing-settings.json",
            "--profile",
            "unused",
            "api-key",
            "raw-url",
            "get",
            URL,
            "--credentials",
            str(credentials),
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout_bytes == b"\x00\xffraw response\n"
    request, timeout = requests[0]
    assert request.full_url == URL
    assert request.method == "GET"
    assert request.data is None
    assert timeout == 30
    scheme, encoded = request.get_header("Authorization").split()
    assert scheme == "Basic"
    assert base64.b64decode(encoded) == b"access:secret"


@pytest.mark.parametrize("option", ["--json", "--data"])
@pytest.mark.parametrize("source", ["literal", "file", "stdin"])
def test_api_key_raw_url_body_and_headers(
    credentials, requests, tmp_path, option, source
):
    body = '{"message":"日本語"}'
    value = body
    if source == "file":
        path = tmp_path / "body.json"
        path.write_text(body)
        value = f"@{path}"
    elif source == "stdin":
        value = "-"
    result = runner.invoke(
        cli.app,
        [
            "api-key",
            "raw-url",
            "POST",
            URL,
            "--credentials",
            str(credentials),
            option,
            value,
            "-H",
            "Content-Type: application/custom+json",
            "-H",
            "X-Request-ID: example",
        ],
        input=body if source == "stdin" else None,
    )
    assert result.exit_code == 0, result.output
    request = requests[0][0]
    assert request.data == body.encode()
    assert request.get_header("Content-type") == "application/custom+json"
    assert request.get_header("X-request-id") == "example"


@pytest.mark.parametrize(
    "contents, message",
    [
        ("broken JSON", "invalid API key credentials JSON"),
        ("{}", "missing a required setting"),
        ('{"access_token":1,"access_token_secret":"secret"}', "must be strings"),
        ('{"access_token":"","access_token_secret":"secret"}', "must not be empty"),
        ('{"access_token":"access","access_token_secret":""}', "must not be empty"),
    ],
)
def test_api_key_raw_url_rejects_invalid_credentials(
    credentials, requests, contents, message
):
    credentials.write_text(contents)
    result = runner.invoke(
        cli.app, ["api-key", "raw-url", "GET", URL, "--credentials", str(credentials)]
    )
    assert result.exit_code == 1
    assert message in result.stderr
    assert requests == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX file permissions")
def test_api_key_raw_url_requires_private_credentials(credentials, requests):
    credentials.chmod(0o644)
    result = runner.invoke(
        cli.app, ["api-key", "raw-url", "GET", URL, "--credentials", str(credentials)]
    )
    assert result.exit_code == 1
    assert "permissions are too open" in result.stderr
    assert requests == []


def test_api_key_raw_url_requires_credentials_option(requests):
    result = runner.invoke(cli.app, ["api-key", "raw-url", "GET", URL])
    assert result.exit_code == 2
    assert "--credentials" in result.output
    assert requests == []


@pytest.mark.parametrize(
    "extra, message",
    [
        (["-H", "aUtHoRiZaTiOn: other"], "Authorization"),
        (["--json", "broken"], "invalid JSON"),
        (["--json", "{}", "--data", "raw"], "cannot be combined"),
    ],
)
def test_api_key_raw_url_rejects_invalid_request_before_reading_credentials(
    requests, extra, message
):
    result = runner.invoke(
        cli.app,
        [
            "api-key",
            "raw-url",
            "POST",
            URL,
            "--credentials",
            "/missing-api-key.json",
            *extra,
        ],
    )
    assert result.exit_code == 1
    assert message in result.stderr
    assert requests == []


@pytest.mark.parametrize("status", [302, 403])
@pytest.mark.parametrize(
    "body", [b"denied", '{"message":"権限がありません"}\n'.encode(), b"\xff\x00", b""]
)
def test_api_key_raw_url_errors_do_not_follow_redirects(
    monkeypatch, credentials, status, body
):
    calls = []

    def reject(request, **kwargs):
        calls.append(request)
        raise urllib.error.HTTPError(
            request.full_url,
            status,
            "error",
            {"Location": "https://other.example.com/"},
            io.BytesIO(body),
        )

    monkeypatch.setattr(transport._NO_REDIRECT_OPENER, "open", reject)
    result = runner.invoke(
        cli.app, ["api-key", "raw-url", "GET", URL, "--credentials", str(credentials)]
    )
    assert result.exit_code == 1
    assert result.stderr_bytes == body
    assert result.stdout_bytes == b""
    assert len(calls) == 1
