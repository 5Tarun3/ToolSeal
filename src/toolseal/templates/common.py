"""Templates every generated project gets, whatever framework it targets.

`guards.py` in particular is framework-independent by design. It holds the
credential redaction filter and the approval decorator, and the approval
decorator is also what the translation layer emits as a *compensating guard*
when a target framework cannot carry `destructiveHint`. Keeping one copy means
a tool lowered into any framework gets the same behaviour restored.
"""

from __future__ import annotations

from string import Template

GUARDS_PY = Template('''"""Security guards for $project_name.

`require_approval` is also what a scaffolder emits as a *compensating guard*:
when a tool declares itself destructive but the target framework has no field to
carry that declaration, the behaviour is reinstated here instead. It is the
remediation for check F2.

`configure_logging` satisfies F1 (tool invocations are recorded) and A4
(credentials never reach the log), and redaction is a filter rather than a
convention because a call site that forgets to redact is the failure being
guarded against.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from collections.abc import Callable
from functools import wraps
from typing import Any

REDACTED = "[REDACTED]"

_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\\b([A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIALS?)[A-Za-z0-9_]*)"
            r"(\\s*[:=]\\s*)([\\'\\"]?)([^\\s\\'\\",;]+)\\3"
        ),
        r"\\g<1>\\g<2>\\g<3>" + REDACTED + r"\\g<3>",
    ),
    (
        re.compile(r"(?i)\\b(authorization\\s*:\\s*)(bearer|basic)(\\s+)(\\S+)"),
        r"\\g<1>\\g<2>\\g<3>" + REDACTED,
    ),
    (re.compile(r"\\bsk-[A-Za-z0-9_-]{16,}"), REDACTED),
    (re.compile(r"\\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\\bAKIA[0-9A-Z]{16}\\b"), REDACTED),
)


def redact(text: str) -> str:
    """Replace anything that looks like a credential. Never raises."""
    for pattern, replacement in _RULES:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """A4: scrub credentials from every record before it is emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact(value) if isinstance(value, str) else value for value in record.args
            )
        return True


def configure_logging(level: int = logging.INFO) -> None:
    """F1 + A4: record what the agent does, without recording secrets."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    handler.addFilter(RedactingFilter())

    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)


ALLOWED_ENVIRONMENT = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "SYSTEMROOT",
        "TOOLSEAL_ASSUME_YES",
    }
)
"""Variables a tool subprocess is allowed to see.

E2: a tool that inherits the parent environment inherits every cloud CLI
profile, SSH agent socket and exported API key along with it. The allowlist is
the parts a process genuinely needs to run - anything else has to be passed
deliberately.
"""


def minimal_environment(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment a child process should get: an allowlist, plus *extra*.

    Use this rather than `os.environ` when launching a tool, an MCP server, or
    anything else this project spawns.
    """
    env = {name: os.environ[name] for name in ALLOWED_ENVIRONMENT if name in os.environ}
    if extra:
        env.update(extra)
    return env


def require_approval(reason: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """F2: refuse a destructive call unless a human confirms it.

    Approval is skipped when `TOOLSEAL_ASSUME_YES` is set, which exists for CI
    and for the evaluation harness. It is deliberately an environment variable
    rather than an argument, so that granting it is a visible act of
    configuration rather than something a model can pass at call time.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if os.environ.get("TOOLSEAL_ASSUME_YES") == "1":
                logging.getLogger("$package_name").warning(
                    "approval bypassed for %s (%s)", function.__name__, reason
                )
                return function(*args, **kwargs)

            if not sys.stdin.isatty():
                message = (
                    f"{function.__name__} requires approval ({reason}) "
                    "but no terminal is attached"
                )
                raise PermissionError(message)

            answer = input(f"Allow {function.__name__}? {reason} [y/N] ").strip().lower()
            if answer != "y":
                message = f"{function.__name__} was not approved"
                raise PermissionError(message)
            return function(*args, **kwargs)

        return wrapper

    return decorate
''')


ENV_EXAMPLE = Template("""# Copy to .env and fill in. Never commit .env.
#
# A1/A2: this file holds placeholders only. Real credentials belong in the OS
# keychain, and `toolseal init` puts them there.
$env_body
""")


README_MD = Template("""# $project_name

An agent built on $framework_name with $provider_name.

## Run

```bash
pip install -r requirements.txt
python agent.py "your prompt here"
```

$provider_note

## What is already handled

This project was scaffolded with secure defaults. Each is marked in the source
with the check it satisfies:

| Check | Default |
| --- | --- |
| `A2` | `.env` is ignored by git; only `.env.example` is tracked |
| `A4` | Logging redacts anything credential-shaped |
| `B1` | Tools are bound from an explicit list, not discovered wholesale |
| `B3` | Filesystem access is confined to `workspace/` after path resolution |
| `C1` | Dependencies are pinned in `requirements.txt` |
| `E3` | Request timeout and recursion limit are both set |
| `F1` | Tool invocations are logged |
| `F2` | `require_approval` is available for destructive tools |

Verify at any time:

```bash
toolseal audit
```
""")
