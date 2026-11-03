from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path
from typing import Annotated

import typer

from sakura_iam_cli import core, errors, raw
from sakura_iam_cli.commands import apps, common, key_files

MethodArgument = Annotated[
    str, typer.Argument(help="HTTP method, e.g. GET, POST, PATCH, DELETE.")
]
UrlArgument = Annotated[str, typer.Argument(help="Absolute URL to call.")]
DataOption = Annotated[
    str | None,
    typer.Option("--data", "-d", help="Raw body: literal text, @file, or - for stdin."),
]
JsonOption = Annotated[
    str | None,
    typer.Option("--json", help="JSON body: literal JSON, @file, or - for stdin."),
]
HeaderOption = Annotated[
    list[str] | None,
    typer.Option(
        "--header", "-H", help="Request header as 'Name: Value'; repeat as needed."
    ),
]


def read_body(value: str) -> bytes:
    """Accept literal UTF-8 text, @file, or - for standard input."""
    if value == "-":
        return sys.stdin.buffer.read()
    if value.startswith("@"):
        return Path(value[1:]).read_bytes()
    return value.encode("utf-8")


def parse_headers(values: list[str]) -> dict[str, str]:
    headers = {}
    for value in values:
        name, separator, content = value.partition(":")
        if not separator:
            raise core.CliError("headers must use 'Name: Value' format")
        headers[name.strip().lower()] = content.strip()
    return headers


def prepare_request(
    method: str,
    url: str,
    data: str | None,
    json_body: str | None,
    header: list[str] | None,
) -> urllib.request.Request:
    if data is not None and json_body is not None:
        raise core.CliError("--data and --json cannot be combined")
    headers = parse_headers(header or [])
    body = None
    if json_body is not None:
        body = read_body(json_body)
        try:
            json.loads(body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise core.CliError("invalid JSON request body") from exc
        headers.setdefault("content-type", "application/json")
        headers.setdefault("accept", "application/json")
    elif data is not None:
        body = read_body(data)
    return raw.prepare_request(method, url, data=body, headers=headers)


def fail_http_response(error: errors.HttpResponseError) -> None:
    sys.stderr.buffer.write(error.body)
    raise typer.Exit(1)


@apps.app.command("raw-url")
def raw_url(
    ctx: typer.Context,
    method: MethodArgument,
    url: UrlArgument,
    data: DataOption = None,
    json_body: JsonOption = None,
    header: HeaderOption = None,
) -> None:
    """Call a URL with SP Bearer authentication and print the unmodified response body."""
    try:
        request = prepare_request(method, url, data, json_body, header)
        _, token = common.authenticated(ctx)
        response = raw.send_request(request, token)
        sys.stdout.buffer.write(response)
    except errors.HttpResponseError as exc:
        fail_http_response(exc)
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))


@apps.api_key_app.command("raw-url")
def api_key_raw_url(
    method: MethodArgument,
    url: UrlArgument,
    credentials: Annotated[
        Path,
        typer.Option(
            "--credentials",
            help="Mode-0600 JSON file created by 'api-key create --output'.",
        ),
    ],
    data: DataOption = None,
    json_body: JsonOption = None,
    header: HeaderOption = None,
) -> None:
    """Call a URL with API key Basic authentication; no SP settings are needed."""
    try:
        request = prepare_request(method, url, data, json_body, header)
        access_token, secret = key_files.load_api_key_credentials(credentials)
        response = raw.send_api_key_request(request, access_token, secret)
        sys.stdout.buffer.write(response)
    except errors.HttpResponseError as exc:
        fail_http_response(exc)
    except (core.CliError, OSError, ValueError) as exc:
        common.fail(core.CliError(str(exc)))
