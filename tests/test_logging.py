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
        'OPENAI_API_KEY="sk-abcdefghijklmnop1234"',
        "ANTHROPIC_API_KEY=sk-ant-0123456789abcdef",
        "db_password: hunter2thisislong",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9",
        "token=ghp_0123456789abcdefghijklmnopqrst",
        "AKIAIOSFODNN7EXAMPLE",
        "-----BEGIN RSA PRIVATE KEY-----",
    ],
)
def test_credentials_are_scrubbed(secret: str) -> None:
    scrubbed = redact(secret)

    assert REDACTED in scrubbed
    assert "sk-abcdefghijklmnop1234" not in scrubbed
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
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="using %s",
        args=("api_key=sk-abcdefghijklmnop1234",),
        exc_info=None,
    )

    assert RedactingFilter().filter(record) is True
    assert "sk-abcdefghijklmnop1234" not in record.getMessage()
    assert REDACTED in record.getMessage()
