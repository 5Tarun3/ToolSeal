"""Source templates for a LangGraph project.

These are ``string.Template`` rather than f-strings or Jinja, for two reasons.
The output is Python source full of braces, which an ``str.format`` template
would fight; and ``$`` placeholders cannot appear by accident in generated code,
so a substitution bug is a loud :class:`KeyError` rather than a silent literal.

Every security-relevant line in the generated project carries the check id it
satisfies. A developer who deletes one should be able to see what they are
deleting, and `toolseal audit` will say the same thing later.
"""

from __future__ import annotations

from string import Template

AGENT_PY = Template('''"""Entry point for $project_name.

Generated with secure defaults. Lines marked with a check id are the reason this
project audits clean; changing them is allowed, and `toolseal audit` will notice.
"""

from __future__ import annotations

import logging
import sys

from langchain.agents import create_agent
from $chat_module import $chat_class

from guards import configure_logging
from tools import TOOLS

log = logging.getLogger("$package_name")

# E3: a wall-clock bound on every provider call. Without one, a hung endpoint
# hangs the agent forever and there is no way to notice from inside.
REQUEST_TIMEOUT_SECONDS = 60.0

# E3: bounds the tool-calling loop. An agent that cannot terminate is a
# resource-exhaustion bug (OWASP LLM10 Unbounded Consumption).
RECURSION_LIMIT = 25


def build_agent():
    """Construct the agent with an explicit, minimal tool set."""
    model = $chat_class(
        model="$model",
        base_url="$base_url",
        temperature=0,
        client_kwargs={"timeout": REQUEST_TIMEOUT_SECONDS},
    )

    # B1: an explicit tool list, not every tool in scope. Binding everything to
    # every session is the overprovisioning default this scaffold avoids.
    return create_agent(model, list(TOOLS))


def main(argv: list[str] | None = None) -> int:
    configure_logging()

    args = list(sys.argv[1:] if argv is None else argv)
    prompt = " ".join(args).strip()
    if not prompt:
        print("usage: python agent.py <prompt>", file=sys.stderr)
        return 2

    agent = build_agent()
    try:
        result = agent.invoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"recursion_limit": RECURSION_LIMIT},
        )
    except Exception:
        # The provider endpoint is the most common failure and its exceptions
        # can carry request context, so this is logged rather than printed raw.
        log.exception("agent run failed")
        return 1

    for message in result["messages"]:
        log.debug("%s: %s", type(message).__name__, message.content)
    print(result["messages"][-1].content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''')


TOOLS_PY = Template('''"""Tools available to $project_name.

Add tools here. Two rules the audit enforces:

* No shell or code-execution tool without a justification recorded in
  `toolseal.toml` (check B2).
* Filesystem tools stay inside the workspace (check B3).
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.tools import tool

# B3: filesystem access is rooted at the project workspace, not at "/" or "~".
WORKSPACE = (Path(__file__).resolve().parent / "workspace").resolve()


@tool
def read_workspace_file(relative_path: str) -> str:
    """Read a UTF-8 text file from the project workspace."""
    target = (WORKSPACE / relative_path).resolve()

    # B3: confinement is enforced after resolution, so `../` and symlinks cannot
    # walk out of the workspace. Checking the string before resolving would not.
    if not target.is_relative_to(WORKSPACE):
        message = f"path escapes the workspace: {relative_path!r}"
        raise ValueError(message)
    if not target.is_file():
        message = f"no such file in workspace: {relative_path!r}"
        raise FileNotFoundError(message)

    return target.read_text(encoding="utf-8")


# B1: the explicit set bound to the agent. Adding a tool here is a deliberate
# act, which is the point.
TOOLS = (read_workspace_file,)
''')


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
