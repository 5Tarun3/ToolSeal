"""Redaction is a security control, so it is tested rather than assumed.

The negative cases matter as much as the positive ones: a filter that scrubs
ordinary text makes diagnostics useless and gets switched off.
"""

from __future__ import annotations

import logging

import pytest

from toolseal.logging import REDACTED, RedactingFilter, redact


@pytest.mark.parametrize(
    "secret",
    [
        'OPENAI_API_KEY="sk-abcdefghijklmnop1234"',  # toolseal:allow A1 - OpenAI-shaped env line
        "ANTHROPIC_API_KEY=sk-ant-0123456789abcdef",  # toolseal:allow A1 - Anthropic-shaped var
        "db_password: hunter2thisislong",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
        "token=ghp_0123456789abcdefghijklmnopqrst",  # toolseal:allow A1 - GitHub token shape
        "AKIAIOSFODNN7EXAMPLE",  # toolseal:allow A1 - AWS access key shape
        "-----BEGIN RSA PRIVATE KEY-----",  # toolseal:allow A1 - PEM private-key header
    ],
)
def test_credentials_are_scrubbed(secret: str) -> None:
    scrubbed = redact(secret)

    assert REDACTED in scrubbed
    assert "sk-abcdefghijklmnop1234" not in scrubbed  # toolseal:allow A1 - must not leak out
    assert "hunter2thisislong" not in scrubbed
    assert "eyJhbGciOiJIUzI1NiJ9" not in scrubbed


@pytest.mark.parametrize(
    "benign",
    [
        "resolved 14 dependencies",
        "wrote config to .toolseal/config.toml",
        "keyring backend: Windows Credential Manager",
    ],
)
def test_benign_text_is_untouched(benign: str) -> None:
    assert redact(benign) == benign


def test_filter_scrubs_message_and_args() -> None:
    key = "sk-abcdefghijklmnop1234"  # toolseal:allow A1 - feeds the %s-formatted log record args
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="using %s",
        args=(f"api_key={key}",),
        exc_info=None,
    )

    assert RedactingFilter().filter(record) is True
    assert key not in record.getMessage()
    assert REDACTED in record.getMessage()
