"""Templates every generated project gets, whatever framework it targets.

`guards.py` in particular is framework-independent by design. It holds the
credential redaction filter and the approval decorator, and the approval
decorator is also what the translation layer emits as a *compensating guard*
when a target framework cannot carry `destructiveHint`. Keeping one copy means
a tool lowered into any framework gets the same behaviour restored.
"""

from __future__ import annotations

from string import Template
from typing import Final

# The tool set every generated project starts with. Recorded in `toolseal.toml`
# under `[tools] enabled` and read back at runtime by `agent_config.py`, so it
# is written down exactly once even though two frameworks might read it.
DEFAULT_TOOL_NAMES: Final[tuple[str, ...]] = ("read_workspace_file",)

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


class ToolCallError(RuntimeError):
    """A tool reported failure.

    G3: an MCP error result arrives as ordinary content, so without this a
    failed call is indistinguishable from a successful one unless somebody
    parses English prose. Raising turns it back into a failure the framework
    can see.
    """


class SchemaViolationError(ValueError):
    """Arguments did not satisfy the tool's own declared schema."""


_ERROR_PREFIXES = ("Error executing tool", "error:", "Traceback (most recent call last)")


def raise_on_tool_error(function: Callable[..., Any]) -> Callable[..., Any]:
    """G3: map an error-shaped result onto the failure channel.

    Recognising an error by its text is unpleasant, and it is what the wire
    format leaves available: the adapter has already flattened `isError` into a
    content block by the time this sees it.
    """

    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        result = function(*args, **kwargs)
        text = result if isinstance(result, str) else repr(result)
        if any(marker in text for marker in _ERROR_PREFIXES):
            raise ToolCallError(text[:500])
        return result

    return wrapper


def validate_against_schema(
    schema: dict[str, Any],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """G2: enforce the declared constraints before the call is dispatched.

    The constraints survive translation but nothing checks them, so an
    out-of-range argument is sent and only the server refuses it. A server that
    does not validate has no second line at all.

    Deliberately small: `enum`, numeric bounds, string length and pattern. These
    are the keywords that actually narrow a value. A full JSON Schema validator
    would be a dependency, and a generated project should not acquire one to
    check four things.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            properties = schema.get("properties") or {}
            for name, value in kwargs.items():
                rules = properties.get(name)
                if isinstance(rules, dict):
                    _check_value(name, value, rules)
            return function(*args, **kwargs)

        return wrapper

    return decorate


def _check_value(name: str, value: Any, rules: dict[str, Any]) -> None:
    allowed = rules.get("enum")
    if isinstance(allowed, list) and value not in allowed:
        message = f"{name}={value!r} is not one of {allowed}"
        raise SchemaViolationError(message)

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum, maximum = rules.get("minimum"), rules.get("maximum")
        if minimum is not None and value < minimum:
            message = f"{name}={value} is below the minimum {minimum}"
            raise SchemaViolationError(message)
        if maximum is not None and value > maximum:
            message = f"{name}={value} is above the maximum {maximum}"
            raise SchemaViolationError(message)

    if isinstance(value, str):
        shortest, longest = rules.get("minLength"), rules.get("maxLength")
        if shortest is not None and len(value) < shortest:
            message = f"{name} is shorter than {shortest} characters"
            raise SchemaViolationError(message)
        if longest is not None and len(value) > longest:
            message = f"{name} is longer than {longest} characters"
            raise SchemaViolationError(message)

        pattern = rules.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            message = f"{name} does not match {pattern!r}"
            raise SchemaViolationError(message)


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


AGENT_CONFIG_PY = Template('''"""Shared configuration for $project_name.

Every framework entrypoint in this project imports from here rather than
hard-coding the model, the provider or the tool list a second time.

Two kinds of value live here, and editing `toolseal.toml` affects only one of
them:

* **Baked in at scaffold time, fixed for this project:** PROVIDER_ID,
  PROVIDER_NAME, DEFAULT_MODEL, DEFAULT_BASE_URL, CREDENTIAL_ENV_VAR. These
  describe the provider this project was generated for and are resolved once,
  when the project is created. Editing `toolseal.toml` does not change them -
  re-scaffold, or edit this file directly, to target a different provider.
* **Read live from `toolseal.toml` on every import:** MODEL, BASE_URL,
  TOOL_NAMES. These are what a user is expected to change after scaffolding,
  so every entrypoint reads them from the one file instead of a value frozen
  into source - editing `toolseal.toml` changes what every entrypoint does,
  together.

Only the standard library is imported here - never a framework package, and
never `toolseal` itself. toolseal is a setup-time tool: this project must run
on a machine where toolseal was never installed. This module reads the
handful of fields it needs from `toolseal.toml` with `tomllib` directly rather
than through toolseal's own `Manifest` class, which stays the one parser
inside toolseal but is not available here.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Final

_ROOT = Path(__file__).resolve().parent
_MANIFEST_PATH = _ROOT / "toolseal.toml"

try:
    _TOML_TEXT = _MANIFEST_PATH.read_text(encoding="utf-8")
except OSError:
    _MESSAGE = (
        f"no toolseal.toml found next to {__file__}; "
        "this project was not scaffolded by toolseal, or the file was moved"
    )
    raise RuntimeError(_MESSAGE) from None

try:
    _DATA = tomllib.loads(_TOML_TEXT)
except tomllib.TOMLDecodeError as exc:
    _MESSAGE = f"toolseal.toml is not valid TOML: {exc}"
    raise RuntimeError(_MESSAGE) from None

# Baked at scaffold time: facts about the provider this project targets,
# resolved once from the provider registry when `toolseal init` ran.
PROVIDER_ID: Final = "$provider_id"
PROVIDER_NAME: Final = "$provider_name"
DEFAULT_MODEL: Final = "$default_model"
DEFAULT_BASE_URL: Final = "$default_base_url"
CREDENTIAL_ENV_VAR: Final[str | None] = $credential_env_var

_stack = _DATA.get("stack")
_stack = _stack if isinstance(_stack, dict) else {}

# Read live: editing toolseal.toml changes these for every entrypoint.
MODEL: str = str(_stack.get("model") or "") or DEFAULT_MODEL
BASE_URL: str = str(_stack.get("base_url") or "") or DEFAULT_BASE_URL

_tools = _DATA.get("tools")
_tools = _tools if isinstance(_tools, dict) else {}
_enabled = _tools.get("enabled")

# B1: the explicit tool list every framework entrypoint in this project binds
# from. Each entrypoint's own tools.py still defines the actual tool objects,
# in the shape its framework wants them - this is only the list of names that
# should be active, so it cannot say something different in each one.
TOOL_NAMES: tuple[str, ...] = (
    tuple(str(item) for item in _enabled) if isinstance(_enabled, list) else ()
)
''')


def render_agent_config(
    *,
    project_name: str,
    provider_id: str,
    provider_name: str,
    default_model: str,
    default_base_url: str,
    credential_env_var: str | None,
) -> str:
    """Render `agent_config.py`, with *provider*'s facts baked in as literals.

    The provider binding - its id, display name, default model, default
    endpoint and credential variable name - is known the moment a framework
    adapter resolves the provider at scaffold time. Baking it in here, rather
    than re-resolving it at import time through `provider_registry`, is what
    lets the generated module stand alone: it never needs toolseal installed
    to know what it was scaffolded for.
    """
    literal_credential = "None" if credential_env_var is None else repr(credential_env_var)
    return AGENT_CONFIG_PY.substitute(
        project_name=project_name,
        provider_id=provider_id,
        provider_name=provider_name,
        default_model=default_model,
        default_base_url=default_base_url,
        credential_env_var=literal_credential,
    )


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
