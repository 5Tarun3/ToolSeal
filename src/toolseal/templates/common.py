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

import json
import logging
import os
import re
import sys
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from functools import wraps
from typing import Any
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlsplit

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


# --- evidence ----------------------------------------------------------------
#
# Every decision a call-path guard makes leaves one JSON line: which guard, which
# tool, what it decided and why, and what the decision cost. Never the arguments -
# an evidence log holding every payload that crossed a guard would be the most
# valuable file in a deployed agent.
#
# Where records go is TOOLSEAL_EVIDENCE: unset means .toolseal/evidence.jsonl next
# to this file (rotated); "-" means stderr, the natural choice in a container;
# "off" means nothing; anything else is a path.
#
# Evidence is best-effort. If the sink cannot be written - a read-only filesystem,
# a full disk, a bad path - one warning goes to stderr, recording stops, and the
# guard's decision is unaffected: a refusal is still a refusal.

EVIDENCE_SCHEMA = 1
EVIDENCE_MAX_BYTES = 5_000_000
EVIDENCE_BACKUPS = 3
EVIDENCE_REASONS = frozenset(
    {
        "checked",
        "approved",
        "declined",
        "approval_override",
        "no_tty",
        "egress",
        "schema",
        "timeout",
        "tool_error",
    }
)

_evidence_lock = threading.Lock()
_evidence_state: dict[str, Any] = {"resolved": False, "sink": None, "warned": False}


def _evidence_failed(detail: str) -> None:
    """Warn once per process, then stop recording."""
    _evidence_state["sink"] = None
    if _evidence_state["warned"]:
        return
    _evidence_state["warned"] = True
    print(
        f"toolseal: evidence not recorded ({detail}); set TOOLSEAL_EVIDENCE to a "
        "writable path, '-' for stderr, or 'off'. Further failures are silent.",
        file=sys.stderr,
    )


class _EvidenceFileHandler(RotatingFileHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        _evidence_failed("write failed")


class _EvidenceStreamHandler(logging.StreamHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        _evidence_failed("write failed")


def _evidence_sink() -> logging.Handler | None:
    if _evidence_state["resolved"]:
        return _evidence_state["sink"]
    with _evidence_lock:
        if _evidence_state["resolved"]:
            return _evidence_state["sink"]
        target = os.environ.get("TOOLSEAL_EVIDENCE", "").strip()
        handler: logging.Handler | None = None
        try:
            if target == "off":
                handler = None
            elif target == "-":
                handler = _EvidenceStreamHandler(sys.stderr)
            else:
                if target:
                    path = Path(target)
                else:
                    here = globals().get("__file__")
                    base = Path(here).resolve().parent if here else Path.cwd()
                    path = base / ".toolseal" / "evidence.jsonl"
                path.parent.mkdir(parents=True, exist_ok=True)
                handler = _EvidenceFileHandler(
                    path,
                    maxBytes=EVIDENCE_MAX_BYTES,
                    backupCount=EVIDENCE_BACKUPS,
                    encoding="utf-8",
                )
            if handler is not None:
                handler.setFormatter(logging.Formatter("%(message)s"))
            _evidence_state["sink"] = handler
        except OSError as exc:
            _evidence_failed(type(exc).__name__)
        _evidence_state["resolved"] = True
        return _evidence_state["sink"]


def _record(guard: str, tool: str, outcome: str, reason: str, elapsed_us: float) -> None:
    """Record one guard decision. *reason* must come from EVIDENCE_REASONS."""
    if reason not in EVIDENCE_REASONS:
        message = f"evidence reason {reason!r} is not in EVIDENCE_REASONS"
        raise ValueError(message)
    sink = _evidence_sink()
    if sink is None:
        return
    stamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    line = json.dumps(
        {
            "schema": EVIDENCE_SCHEMA,
            "ts": stamp.replace("+00:00", "Z"),
            "layer": "decorator",
            "guard": guard,
            "tool": tool,
            "outcome": outcome,
            "reason": reason,
            "elapsed_us": round(elapsed_us, 1),
        },
        separators=(",", ":"),
    )
    sink.handle(logging.makeLogRecord({"msg": line, "levelno": logging.INFO}))


def _micros_since(started: float) -> float:
    return (time.perf_counter() - started) * 1_000_000


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
        started = time.perf_counter()
        text = result if isinstance(result, str) else repr(result)
        if any(marker in text for marker in _ERROR_PREFIXES):
            _record(
                "raise_on_tool_error", function.__name__, "error", "tool_error",
                _micros_since(started),
            )
            raise ToolCallError(text[:500])
        _record(
            "raise_on_tool_error", function.__name__, "allowed", "checked",
            _micros_since(started),
        )
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
            started = time.perf_counter()
            properties = schema.get("properties") or {}
            try:
                for name, value in kwargs.items():
                    rules = properties.get(name)
                    if isinstance(rules, dict):
                        _check_value(name, value, rules)
            except SchemaViolationError:
                _record(
                    "validate_against_schema", function.__name__, "refused", "schema",
                    _micros_since(started),
                )
                raise
            _record(
                "validate_against_schema", function.__name__, "allowed", "checked",
                _micros_since(started),
            )
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
            started = time.perf_counter()
            if os.environ.get("TOOLSEAL_ASSUME_YES") == "1":
                logging.getLogger("$package_name").warning(
                    "approval bypassed for %s (%s)", function.__name__, reason
                )
                # Recorded as the override, never as an approval: a call that
                # went through because the variable was set must be told apart
                # from one a human agreed to.
                _record(
                    "require_approval", function.__name__, "allowed", "approval_override",
                    _micros_since(started),
                )
                return function(*args, **kwargs)

            if not sys.stdin.isatty():
                _record(
                    "require_approval", function.__name__, "refused", "no_tty",
                    _micros_since(started),
                )
                message = (
                    f"{function.__name__} requires approval ({reason}) "
                    "but no terminal is attached"
                )
                raise PermissionError(message)

            # elapsed_us below includes the human's answer time; it is a record
            # of what the decision cost, not a machine measurement.
            answer = input(f"Allow {function.__name__}? {reason} [y/N] ").strip().lower()
            if answer != "y":
                _record(
                    "require_approval", function.__name__, "refused", "declined",
                    _micros_since(started),
                )
                message = f"{function.__name__} was not approved"
                raise PermissionError(message)
            _record(
                "require_approval", function.__name__, "allowed", "approved",
                _micros_since(started),
            )
            return function(*args, **kwargs)

        return wrapper

    return decorate


class GuardTimeoutError(TimeoutError):
    """`BOUND_RUNTIME`: a guarded call did not return within its bound.

    Raising this is not proof the underlying call stopped - see
    `bound_runtime`'s docstring for exactly what is, and is not, promised.
    """


class EgressPolicyError(PermissionError):
    """`RESTRICT_EGRESS`: a guarded call named a host outside its allowlist.

    Raising this is not proof no other host was reached - see
    `restrict_egress`'s docstring for exactly what is, and is not, checked.
    """


def bound_runtime(seconds: float) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """P46/BOUND_RUNTIME: stop waiting for a call once *seconds* have passed.

    `policy.tool.<name>.timeout_seconds` in `toolseal.toml` forces this guard
    (see `translate/lower.py`). The wrapped call runs on a daemon worker
    thread; if it has not finished within *seconds*, `GuardTimeoutError` is
    raised on the caller's thread instead of waiting any longer.

    What this does not promise: Python has no supported way to forcibly kill
    a running thread, so a call that times out is not stopped - it keeps
    running in the background, and whatever it eventually returns, or any
    side effect it performs, is simply discarded. This bounds how long the
    *caller* waits, not how long the *callee* runs. `signal.alarm` would stop
    the callee outright, but only from the main thread of the main
    interpreter, and not at all on Windows - both of which this project must
    run on - so a guard built on it would work on one platform and silently
    do nothing on another. Bounding the wait honestly, everywhere, beats
    claiming to bound execution and only sometimes managing it.
    """
    if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or seconds <= 0:
        message = f"bound_runtime requires a positive number of seconds, got {seconds!r}"
        raise ValueError(message)

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            outcome: list[Any] = []
            failure: list[Exception] = []
            spent: list[float] = []
            started = time.perf_counter()

            def run() -> None:
                began = time.perf_counter()
                try:
                    outcome.append(function(*args, **kwargs))
                except Exception as exc:  # the caller's thread re-raises this, not this one
                    failure.append(exc)
                finally:
                    spent.append(time.perf_counter() - began)

            worker = threading.Thread(target=run, daemon=True)
            worker.start()
            worker.join(timeout=seconds)
            if worker.is_alive():
                # The caller's actual wait: that is what a timeout cost it.
                _record(
                    "bound_runtime", function.__name__, "refused", "timeout",
                    _micros_since(started),
                )
                message = (
                    f"{function.__name__} exceeded its {seconds}s bound "
                    "(policy.tool.<name>.timeout_seconds); it may still be running "
                    "in the background"
                )
                raise GuardTimeoutError(message)
            # The guard's own cost, excluding the time the tool itself ran.
            own = _micros_since(started) - (spent[0] * 1_000_000 if spent else 0.0)
            if failure:
                _record("bound_runtime", function.__name__, "error", "tool_error", max(own, 0.0))
                raise failure[0]
            _record("bound_runtime", function.__name__, "allowed", "checked", max(own, 0.0))
            return outcome[0]

        return wrapper

    return decorate


# Parameter names a call is inspected under even when its value carries no
# "://" scheme - a bare hostname passed as `host="evil.example.com"` is just
# as much a declared destination as a full URL.
_HOST_LIKE_KEYS = frozenset({"url", "uri", "host", "hostname", "endpoint", "base_url", "address"})


def _named_host(value: str) -> str | None:
    """The host *value* names, if it looks like a URL or a bare hostname."""
    if "://" in value:
        return urlsplit(value).hostname
    if not value or " " in value or "/" in value:
        return None
    return value


def restrict_egress(
    allowed_hosts: Sequence[str],
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """P46/RESTRICT_EGRESS: refuse a call whose own arguments name a disallowed host.

    `policy.tool.<name>.egress_allow` in `toolseal.toml` forces this guard
    (see `translate/lower.py`). Every keyword argument passed to the wrapped
    call is inspected: a string value that is a URL (contains `://`), or is
    passed under a host-shaped parameter name (`url`, `host`, `endpoint`, ...)
    and looks like a bare hostname, is checked against *allowed_hosts*. A call
    naming a host outside that list is refused before it reaches the wrapped
    function.

    What this does not promise: this project deliberately ships no runtime
    interception gateway. A decorator sees only the arguments a caller passed
    to *this* function - it cannot see a socket the wrapped function opens
    internally, a redirect the far end issues, a host embedded in a request
    body rather than a top-level argument, or DNS resolution. Treat this as
    catching an egregious, argument-visible mistake or a misconfigured tool,
    never as a network firewall.
    """
    allowed = frozenset(host.lower() for host in allowed_hosts)

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            started = time.perf_counter()
            for name, value in kwargs.items():
                if not isinstance(value, str):
                    continue
                if "://" not in value and name.lower() not in _HOST_LIKE_KEYS:
                    continue
                host = _named_host(value)
                if host is not None and host.lower() not in allowed:
                    _record(
                        "restrict_egress", function.__name__, "refused", "egress",
                        _micros_since(started),
                    )
                    message = (
                        f"{function.__name__} would reach {host!r}, which is outside "
                        f"the allowed hosts {sorted(allowed)} (policy.tool.<name>.egress_allow)"
                    )
                    raise EgressPolicyError(message)
            _record(
                "restrict_egress", function.__name__, "allowed", "checked",
                _micros_since(started),
            )
            return function(*args, **kwargs)

        return wrapper

    return decorate


def guard_tool(
    policy: Mapping[str, Any] | None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Bind the guards a `[policy.tool.<name>]` table declares.

    Applied from the call outward: `timeout_seconds` bounds the call itself,
    `egress_allow` is checked before that, and `approval = "always"` is asked
    first of all - so a human is never asked about a call the egress rule would
    refuse anyway, and only the tool's own work is timed. An absent or empty
    policy returns the tool unchanged.

    `agent_config.TOOL_POLICIES` supplies *policy*; this module deliberately
    does not import it, so guards stay usable on their own.
    """

    def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
        if not policy:
            return function
        guarded = function
        timeout = policy.get("timeout_seconds")
        if timeout is not None:
            guarded = bound_runtime(timeout)(guarded)
        egress = policy.get("egress_allow")
        if egress is not None:
            guarded = restrict_egress(egress)(guarded)
        if policy.get("approval") == "always":
            guarded = require_approval("required by policy.tool: approval = 'always'")(guarded)
        return guarded

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
