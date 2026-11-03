import io
import urllib.error
from pathlib import Path

import pytest
from typer.testing import CliRunner

from sakura_iam_cli import cli, core, transport
from sakura_iam_cli.commands import common

runner = CliRunner()


@pytest.fixture
def authenticated(monkeypatch):
    calls = []
    profile = core.Profile("https://auth.example.test/", None, "sp", "kid", Path("key"))

    def authenticate(ctx):
        calls.append(ctx.obj)
        return profile, "sp-token"

    monkeypatch.setattr(common, "authenticated", authenticate)
    return calls


@pytest.fixture
def requests(monkeypatch):
    calls = []

    def open_request(request, *, timeout):
        calls.append((request, timeout))
        return io.BytesIO(b'{"ok":true}')

    monkeypatch.setattr(transport._NO_REDIRECT_OPENER, "open", open_request)
    return calls


def test_raw_url_uses_selected_profile_and_explicit_url(authenticated, requests):
    result = runner.invoke(
        cli.app,
        [
            "--settings",
            "other.json",
            "--profile",
            "test",
            "raw-url",
            "post",
            "https://iam.example.com/status?mode=full",
        ],
    )

    assert result.exit_code == 0, result.output
    assert result.stdout_bytes == b'{"ok":true}'
    assert authenticated[0].settings == Path("other.json")
    assert authenticated[0].profile_name == "test"
    request, timeout = requests[0]
    assert timeout == 30
    assert request.full_url == "https://iam.example.com/status?mode=full"
    assert request.method == "POST"
    assert request.get_header("Authorization") == "Bearer sp-token"
    assert request.data is None


@pytest.mark.parametrize("source", ["literal", "file", "stdin"])
def test_raw_url_json_body(authenticated, requests, tmp_path, source):
    payload = '{"message":"日本語"}'
    value = payload
    if source == "file":
        path = tmp_path / "payload.json"
        path.write_text(payload)
        value = f"@{path}"
    elif source == "stdin":
        value = "-"

    result = runner.invoke(
        cli.app,
        [
            "raw-url",
            "PATCH",
            "https://iam.example.com/status",
            "--json",
            value,
            "-H",
            "X-Request-ID: example",
            "-H",
            "Accept: application/problem+json",
        ],
        input=payload if source == "stdin" else None,
    )

    assert result.exit_code == 0, result.output
    request = requests[0][0]
    assert request.data == payload.encode()
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Accept") == "application/problem+json"
    assert request.get_header("X-request-id") == "example"


def test_raw_url_sends_binary_body_from_file(authenticated, requests, tmp_path):
    path = tmp_path / "payload.bin"
    path.write_bytes(b"\x00\xff\r\n")
    result = runner.invoke(
        cli.app,
        [
            "raw-url",
            "PUT",
            "https://iam.example.com/status",
            "-d",
            f"@{path}",
            "-H",
            "Content-Type: application/octet-stream",
        ],
    )
    assert result.exit_code == 0, result.output
    assert requests[0][0].data == path.read_bytes()
    assert requests[0][0].get_header("Content-type") == "application/octet-stream"


@pytest.mark.parametrize("body", [b"plain text\n", b"[1,2]", b"\x00\xff", b""])
def test_raw_url_preserves_response_bytes(monkeypatch, authenticated, body):
    monkeypatch.setattr(
        transport._NO_REDIRECT_OPENER, "open", lambda *a, **k: io.BytesIO(body)
    )
    result = runner.invoke(
        cli.app, ["raw-url", "GET", "https://iam.example.com/status"]
    )
    assert result.exit_code == 0
    assert result.stdout_bytes == body


@pytest.mark.parametrize(
    "args, message",
    [
        (["GET", "http://iam.example.com/status"], "HTTPS"),
        (["GET", "file:///tmp/settings.json"], "host"),
        (["GET", "https://user:password@iam.example.com/status"], "credentials"),
        (["BAD METHOD", "https://iam.example.com/status"], "HTTP method"),
        (
            ["POST", "https://iam.example.com/status", "--json", "broken"],
            "invalid JSON",
        ),
        (
            ["POST", "https://iam.example.com/status", "--json", "{}", "-d", "data"],
            "cannot be combined",
        ),
        (["GET", "https://iam.example.com/status", "-H", "broken"], "Name: Value"),
        (
            ["GET", "https://iam.example.com/status", "-H", "Authorization: other"],
            "Authorization",
        ),
        (
            [
                "GET",
                "https://iam.example.com/status",
                "-H",
                "X-Name: value\r\nInjected: value",
            ],
            "HTTP header",
        ),
        (
            ["POST", "https://iam.example.com/status", "-d", "@/missing-payload-file"],
            "No such file",
        ),
    ],
)
def test_raw_url_rejects_invalid_requests_before_authentication(
    authenticated, requests, args, message
):
    result = runner.invoke(cli.app, ["raw-url", *args])
    assert result.exit_code == 1
    assert message in result.stderr
    assert authenticated == []
    assert requests == []


@pytest.mark.parametrize("status", [302, 307, 403, 500])
@pytest.mark.parametrize(
    "body", [b"details", '{"message":"権限がありません"}\n'.encode(), b"\xff\x00", b""]
)
def test_raw_url_http_error_exits_without_following_redirect(
    monkeypatch, authenticated, status, body
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
        cli.app, ["raw-url", "POST", "https://iam.example.com/status"]
    )
    assert result.exit_code == 1
    assert result.stderr_bytes == body
    assert result.stdout_bytes == b""
    assert len(calls) == 1


def test_raw_url_supports_local_http(authenticated, requests):
    result = runner.invoke(cli.app, ["raw-url", "GET", "http://127.0.0.1:8080/status"])
    assert result.exit_code == 0
    assert requests[0][0].full_url == "http://127.0.0.1:8080/status"
