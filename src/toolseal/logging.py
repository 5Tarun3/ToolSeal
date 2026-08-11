"""Logging setup with mandatory secret redaction.

toolseal handles provider credentials, so its own diagnostic output is a
disclosure risk. Redaction is applied as a logging *filter* rather than at call
sites, because a call site that forgets to redact is precisely the failure mode
being guarded against.

This is the tool applying check ``A4`` (credential reachable in logs) to itself.
Redaction is best-effort defence in depth, not a licence to log secrets.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Final

REDACTED: Final = "[REDACTED]"

_LOG_FORMAT: Final = "%(levelname)s %(name)s: %(message)s"

# Each rule is (pattern, replacement). Order matters only in that broad
# assignment matching runs first, so provider-specific shapes act as a backstop
# for secrets that appear outside an assignment.
_RULES: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    # NAME=value / NAME: value, where NAME looks credential-bearing.
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?)[A-Za-z0-9_]*)"
            r"(\s*[:=]\s*)(['\"]?)([^\s'\",;]+)\3"
        ),
        rf"\g<1>\g<2>\g<3>{REDACTED}\g<3>",
    ),
    # Authorization: Bearer <token> / Basic <token>
    (
        re.compile(r"(?i)\b(authorization\s*:\s*)(bearer|basic)(\s+)(\S+)"),
        rf"\g<1>\g<2>\g<3>{REDACTED}",
    ),
    # Well-known credential shapes, matched wherever they appear.
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"), REDACTED),
)


def redact(text: str) -> str:
    """Return *text* with anything that looks like a credential replaced.

    Safe to call on arbitrary input; it never raises.
    """
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


def _redact_arg(value: object) -> object:
    return redact(value) if isinstance(value, str) else value


class RedactingFilter(logging.Filter):
    """Scrub credential-looking substrings from a record before it is emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)

        args = record.args
        if isinstance(args, dict):
            record.args = {key: _redact_arg(value) for key, value in args.items()}
        elif isinstance(args, tuple):
            record.args = tuple(_redact_arg(value) for value in args)

        return True


def configure_logging(*, verbose: bool = False) -> None:
    """Install a stderr handler with redaction applied.

    Diagnostics go to stderr so that stdout stays reserved for machine-readable
    command output.
    """
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    handler.addFilter(RedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose else logging.WARNING)
