"""The HTTP client's guarantees: https only, bounded, and honest about failure."""

from __future__ import annotations

import pytest

from toolseal.core.net import USER_AGENT, HttpError, get_json, post_json


@pytest.mark.parametrize(
    "url",
    ["http://example.test/x", "file:///etc/passwd", "ftp://example.test/x", "gopher://x"],
)
def test_non_https_is_refused(url: str) -> None:
    # urlopen honours file: and custom schemes, so this is enforced rather than
    # assumed - a URL that becomes configurable must not become a file read.
    with pytest.raises(HttpError, match="non-https"):
        get_json(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:11434/v1",
        "http://127.0.0.1:11434/v1",
        "http://[::1]:11434/v1",
    ],
)
def test_plaintext_loopback_is_allowed(url: str) -> None:
    # Matches check D1: plaintext to localhost never crosses a network, and
    # refusing it made the client unusable against the local runtimes this
    # project targets. A connection error here means the scheme check passed.
    with pytest.raises(HttpError) as caught:
        get_json(url)

    assert "non-https" not in str(caught.value)


def test_a_non_loopback_host_is_still_refused_over_http() -> None:
    # The exemption is for the host, not for the scheme in general.
    with pytest.raises(HttpError, match="non-https"):
        get_json("http://10.0.0.5:11434/v1")


def test_post_also_enforces_the_scheme() -> None:
    with pytest.raises(HttpError, match="non-https"):
        post_json("http://example.test/x", {"a": 1})


def test_user_agent_identifies_the_tool() -> None:
    # Registry operators should be able to see who is crawling and rate-limit
    # rather than block outright.
    assert "toolseal/" in USER_AGENT
