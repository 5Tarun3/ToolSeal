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


def test_post_also_enforces_the_scheme() -> None:
    with pytest.raises(HttpError, match="non-https"):
        post_json("http://example.test/x", {"a": 1})


def test_user_agent_identifies_the_tool() -> None:
    # Registry operators should be able to see who is crawling and rate-limit
    # rather than block outright.
    assert "toolseal/" in USER_AGENT
