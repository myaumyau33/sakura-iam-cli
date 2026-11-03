import urllib.error
import urllib.request

import pytest

from sakura_iam_cli import transport
from sakura_iam_cli.core import (
    CliError,
)


def test_request_rejects_non_http_urls_and_redirects(monkeypatch):
    with pytest.raises(CliError, match="API URL"):
        transport._request_json(urllib.request.Request("file:///tmp/settings.json"))

    error = urllib.error.HTTPError(
        "https://example.test/", 302, "Found", {"Location": "https://evil.test/"}, None
    )

    def raise_redirect(*args, **kwargs):
        raise error

    monkeypatch.setattr(transport._NO_REDIRECT_OPENER, "open", raise_redirect)
    with pytest.raises(CliError, match="redirect refused"):
        transport._request_json(urllib.request.Request("https://example.test/"))
