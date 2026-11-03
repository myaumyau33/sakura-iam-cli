from __future__ import annotations


class CliError(Exception):
    """An error that should be shown without a traceback."""


class HttpResponseError(CliError):
    """An unsuccessful HTTP response whose body must be preserved verbatim."""

    def __init__(self, status: int, body: bytes) -> None:
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body
