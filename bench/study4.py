"""Study 4: translation fidelity at scale (RQ4).

Probe P0 asked one go/no-go question with three tools and two adapters, and
found that loss is adapter-dependent rather than inherent. This study is the
measurement P0 said it was not: the P0 method, unchanged, over every adapter
path this project could find between the five abstractions the evaluation
protocol names, against a fixture widened to the properties P0 did not exercise.

**Units.** Each ``(adapter, configuration, version)`` is one unit - an adapter
with a switch that changes what it emits (``openai-agents``' strict schemas,
``agent-framework``'s security labels) counts once per setting, because a
practitioner chooses one and gets that one's translation.

**Verdicts** are P0's four: ``preserved``, ``dropped``, ``mutated``,
``unknown``. Nothing is scored by reading an adapter's documentation; every
verdict comes from the object the adapter actually produced, or from what
happened when that object was called.

**Three things are measured per unit:**

1. *Declaration* - each annotation hint, each schema constraint (resolved
   through ``$ref``, ``anyOf`` and array ``items``), each object's ``required``
   set, each ``default``, and the description, against the fixture's own
   ``tools/list``.
2. *Behaviour* - every invalid call in :data:`VIOLATIONS` is made through the
   translated tool, and the fixture's call log says whether it left the client.
   Enforcement is ``preserved`` only when the adapter refused it locally. The
   error path is ``preserved`` only when an MCP ``isError`` result reaches the
   caller as a raised exception.
3. *Restoration* - for every unit whose target abstraction the lattice models,
   toolseal lowers each tool into that target and the generated binding is
   **executed** with its real guards, dispatching to the real translated tool.
   A guard is credited with restoring a property only if it is observed firing.

**Known limitation, from the protocol.** Annotation carriers are searched by
name (:data:`ANNOTATION_CARRIERS`). An adapter keeping them somewhere unusual
is scored as dropping them, so every ``dropped`` annotation verdict for an
adapter P0 did not test was confirmed against that adapter's source before
publication; the note on each unit records what was checked.

Run: ``uv sync --group research`` then ``uv run python -m bench s4``.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata as metadata
import io
import json
import logging
import os
import platform
import sys
import tempfile
import threading
import types
import warnings
from collections.abc import Awaitable, Callable, Iterator
from concurrent.futures import Future
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Final

HERE: Final = Path(__file__).resolve().parent
FIXTURE: Final = HERE / "s4_fixture_server.py"

PRESERVED: Final = "preserved"
DROPPED: Final = "dropped"
MUTATED: Final = "mutated"
UNKNOWN: Final = "unknown"
VERDICTS: Final = (PRESERVED, DROPPED, MUTATED, UNKNOWN)

ANNOTATION_HINTS: Final = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
    "title",
)

# P0's six, plus the array keywords the widened fixture exercises.
CONSTRAINT_KEYWORDS: Final = (
    "enum",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "minItems",
    "maxItems",
    "uniqueItems",
)

# Attribute names searched for annotation hints, grown from P0's list as
# adapters were added. `additional_properties` is agent-framework's carrier.
ANNOTATION_CARRIERS: Final = (
    "metadata",
    "annotations",
    "extras",
    "tags",
    "meta",
    "additional_properties",
)


@dataclass(frozen=True)
class Violation:
    """One call that breaks one declared constraint, and where it sits."""

    tool: str
    arguments: dict[str, Any]
    constraint: str


# Each breaks exactly one constraint; the rest of the call is valid. Nested,
# array and nullable cases are the ones P0 had no fixture for.
VIOLATIONS: Final = (
    Violation("delete_records", {"table": "secrets", "limit": 5}, "table.enum"),
    Violation("delete_records", {"table": "users", "limit": 500}, "limit.maximum"),
    Violation("read_document", {"path": "/etc/passwd"}, "path.pattern"),
    Violation("search_web", {"query": ""}, "query.minLength"),
    Violation(
        "create_ticket",
        {"reporter": {"email": "x@evil.test", "team": "security"}, "summary": "printer down"},
        "reporter.email.pattern",
    ),
    Violation(
        "create_ticket",
        {"reporter": {"email": "a@example.org", "team": "sales"}, "summary": "printer down"},
        "reporter.team.enum",
    ),
    Violation(
        "create_ticket",
        {
            "reporter": {"email": "a@example.org", "team": "security"},
            "summary": "printer down",
            "assignee": "x" * 40,
        },
        "assignee.maxLength",
    ),
    Violation("tag_items", {"tags": ["secret"]}, "tags[].enum"),
    Violation(
        "tag_items", {"tags": ["public", "internal", "restricted", "public"]}, "tags.maxItems"
    ),
    Violation("tag_items", {"tags": ["public", "public"]}, "tags.uniqueItems"),
)

# A valid call per tool. If one of these does not reach the server, the unit's
# invocation path is broken and its behaviour verdicts are `unknown`, not
# credited as enforcement.
VALID_CALLS: Final[dict[str, dict[str, Any]]] = {
    "delete_records": {"table": "users", "limit": 5},
    "read_document": {"path": "/docs/readme.md"},
    "search_web": {"query": "toolseal"},
    "create_ticket": {
        "reporter": {"email": "a@example.org", "team": "security"},
        "summary": "printer down",
    },
    "tag_items": {"tags": ["public"]},
}

ERROR_TOOL: Final = "fail_always"


@dataclass(frozen=True)
class Finding:
    unit: str
    tool: str
    prop: str
    verdict: str
    expected: Any = None
    observed: Any = None
    note: str = ""


@dataclass
class Translated:
    """An adapter's output, normalised so adapters can be compared."""

    name: str
    description: str
    schema: dict[str, Any]
    annotations: dict[str, Any]
    carrier: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Outcome:
    """What one call through a translated tool did."""

    raised: str | None
    output: str


Invoke = Callable[[str, dict[str, Any]], Outcome]


@dataclass(frozen=True)
class Unit:
    """One adapter configuration under test."""

    id: str
    route: str
    abstraction: str | None
    packages: tuple[str, ...]
    open: Callable[
        [list[str]], contextlib.AbstractContextManager[tuple[list[Translated], Invoke | None]]
    ]
    note: str = ""


# ---------------------------------------------------------------------------
# Plumbing: one long-lived task per async session
# ---------------------------------------------------------------------------


class _SessionActor:
    """Hold an async adapter session open on a background loop.

    The MCP stdio client is built on anyio task groups, which must be exited by
    the task that entered them. So one coroutine opens the session and then
    serves calls from a queue until told to stop, and every other part of this
    module talks to it synchronously - which is also what a generated binding's
    ``DISPATCH`` needs.
    """

    def __init__(
        self,
        opener: Callable[[], contextlib.AbstractAsyncContextManager[Any]],
        call: Callable[[Any, str, dict[str, Any]], Awaitable[Any]],
    ) -> None:
        self._opener = opener
        self._call = call
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._queue: asyncio.Queue[Any] | None = None
        self._ready: Future[Any] = Future()
        self._done: Future[None] = Future()

    async def _serve(self) -> None:
        self._queue = asyncio.Queue()
        try:
            async with self._opener() as handle:
                self._ready.set_result(handle)
                while True:
                    item = await self._queue.get()
                    if item is None:
                        break
                    name, arguments, reply = item
                    try:
                        reply.set_result(await self._call(handle, name, arguments))
                    # Broad by design: a failing call is an outcome to record.
                    except BaseException as exc:
                        reply.set_exception(exc)
        except BaseException as exc:
            if not self._ready.done():
                self._ready.set_exception(exc)
        finally:
            self._done.set_result(None)

    def __enter__(self) -> Any:
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._serve(), self._loop)
        return self._ready.result(timeout=120)

    def invoke(self, name: str, arguments: dict[str, Any]) -> Outcome:
        reply: Future[Any] = Future()
        queue = self._queue
        if queue is None:
            return Outcome(raised="RuntimeError: session not open", output="")
        self._loop.call_soon_threadsafe(queue.put_nowait, (name, arguments, reply))
        try:
            return Outcome(raised=None, output=_text(reply.result(timeout=60)))
        except Exception as exc:
            return Outcome(raised=f"{type(exc).__name__}: {exc}"[:300], output="")

    def __exit__(self, *exc: object) -> None:
        if self._queue is not None:
            self._loop.call_soon_threadsafe(self._queue.put_nowait, None)
        with contextlib.suppress(Exception):
            self._done.result(timeout=60)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=10)


def _text(result: Any) -> str:
    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, default=str)
    except (TypeError, ValueError):
        return repr(result)


def _schema_of(obj: object) -> dict[str, Any]:
    if isinstance(obj, dict):
        return obj
    builder = getattr(obj, "model_json_schema", None)
    if callable(builder):
        built = builder()
        if isinstance(built, dict):
            return built
    return {}


def _find_annotations(obj: object) -> tuple[dict[str, Any], str]:
    for carrier in ANNOTATION_CARRIERS:
        value = getattr(obj, carrier, None)
        if isinstance(value, dict) and any(hint in value for hint in ANNOTATION_HINTS):
            return dict(value), carrier
    return {}, ""


def _stdio(args: list[str]) -> Any:
    from mcp import StdioServerParameters

    return StdioServerParameters(command=sys.executable, args=args)


# ---------------------------------------------------------------------------
# Units
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _langchain_session(args: list[str]) -> Iterator[tuple[dict[str, Any], Invoke]]:
    """The LangChain tools themselves, with an invoke that goes through them."""
    from langchain_mcp_adapters.tools import load_mcp_tools
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    @contextlib.asynccontextmanager
    async def opener() -> Any:
        async with (
            stdio_client(_stdio(args)) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            yield {tool.name: tool for tool in await load_mcp_tools(session)}

    async def call(tools: dict[str, Any], name: str, arguments: dict[str, Any]) -> Any:
        return await tools[name].ainvoke(arguments)

    actor = _SessionActor(opener, call)
    tools = actor.__enter__()
    try:
        yield tools, actor.invoke
    finally:
        actor.__exit__()


@contextlib.contextmanager
def _open_langchain(args: list[str]) -> Iterator[tuple[list[Translated], Invoke | None]]:
    with _langchain_session(args) as (tools, invoke):
        translated = []
        for tool in tools.values():
            annotations, carrier = _find_annotations(tool)
            translated.append(
                Translated(
                    name=tool.name,
                    description=tool.description or "",
                    schema=_schema_of(getattr(tool, "args_schema", None)),
                    annotations=annotations,
                    carrier=carrier,
                )
            )
        yield translated, invoke


@contextlib.contextmanager
def _open_langchain_to_openai(args: list[str]) -> Iterator[tuple[list[Translated], Invoke | None]]:
    """MCP -> LangChain -> OpenAI function schema, as `bind_tools` sends it.

    A schema format, not a runtime: there is nothing to call, so this unit has
    declaration verdicts only.
    """
    from langchain_core.utils.function_calling import convert_to_openai_tool

    with _langchain_session(args) as (tools, _invoke):
        translated = []
        for tool in tools.values():
            function = convert_to_openai_tool(tool)["function"]
            translated.append(
                Translated(
                    name=function["name"],
                    description=function.get("description", ""),
                    schema=function.get("parameters", {}),
                    annotations={},
                )
            )
        yield translated, None


@contextlib.contextmanager
def _open_crewai(args: list[str]) -> Iterator[tuple[list[Translated], Invoke | None]]:
    from crewai_tools import MCPServerAdapter

    with MCPServerAdapter(_stdio(args)) as tools:
        by_name = {tool.name: tool for tool in tools}

        def invoke(name: str, arguments: dict[str, Any]) -> Outcome:
            try:
                return Outcome(raised=None, output=_text(by_name[name].run(**arguments)))
            except Exception as exc:
                return Outcome(raised=f"{type(exc).__name__}: {exc}"[:300], output="")

        translated = []
        for tool in tools:
            annotations, carrier = _find_annotations(tool)
            translated.append(
                Translated(
                    name=tool.name,
                    description=tool.description or "",
                    schema=_schema_of(getattr(tool, "args_schema", None)),
                    annotations=annotations,
                    carrier=carrier,
                )
            )
        yield translated, invoke


def _open_openai_agents(strict: bool) -> Callable[..., Any]:
    @contextlib.contextmanager
    def opener_cm(args: list[str]) -> Iterator[tuple[list[Translated], Invoke | None]]:
        from agents.mcp import MCPServerStdio, MCPUtil
        from agents.tool_context import ToolContext

        @contextlib.asynccontextmanager
        async def opener() -> Any:
            async with MCPServerStdio(
                {"command": sys.executable, "args": args}, client_session_timeout_seconds=30
            ) as server:
                listed = await server.list_tools()
                yield {
                    tool.name: (tool, MCPUtil.to_function_tool(tool, server, strict))
                    for tool in listed
                }

        async def call(tools: dict[str, Any], name: str, arguments: dict[str, Any]) -> Any:
            _mcp_tool, function_tool = tools[name]
            payload = json.dumps(arguments)
            context = ToolContext(
                context=None, tool_name=name, tool_call_id="s4", tool_arguments=payload
            )
            # The SDK's own entry point: what the runner calls for a model's
            # tool call, failure handling included.
            return await function_tool.on_invoke_tool(context, payload)

        actor = _SessionActor(opener, call)
        tools = actor.__enter__()
        try:
            translated = []
            for _mcp_tool, function_tool in tools.values():
                annotations: dict[str, Any] = {}
                carrier = ""
                title = getattr(function_tool, "_mcp_title", None)
                if title is not None:
                    annotations["title"] = title
                    carrier = "_mcp_title"
                translated.append(
                    Translated(
                        name=function_tool.name,
                        description=function_tool.description or "",
                        schema=dict(function_tool.params_json_schema),
                        annotations=annotations,
                        carrier=carrier,
                        extra={
                            "needs_approval": function_tool.needs_approval,
                            "strict_json_schema": function_tool.strict_json_schema,
                        },
                    )
                )
            yield translated, actor.invoke
        finally:
            actor.__exit__()

    return opener_cm


def _open_agent_framework(labels: bool) -> Callable[..., Any]:
    @contextlib.contextmanager
    def opener_cm(args: list[str]) -> Iterator[tuple[list[Translated], Invoke | None]]:
        from agent_framework import MCPStdioTool

        @contextlib.asynccontextmanager
        async def opener() -> Any:
            async with MCPStdioTool(
                name="s4", command=sys.executable, args=args, load_prompts=False
            ) as tool:
                if labels:
                    from agent_framework.security import apply_mcp_security_labels

                    await apply_mcp_security_labels(tool)
                yield {function.name: function for function in tool.functions}

        async def call(functions: dict[str, Any], name: str, arguments: dict[str, Any]) -> Any:
            return await functions[name].invoke(arguments=arguments)

        actor = _SessionActor(opener, call)
        functions = actor.__enter__()
        try:
            translated = []
            for function in functions.values():
                properties = dict(getattr(function, "additional_properties", None) or {})
                annotations, carrier = _find_annotations(function)
                label_keys = (
                    "source_integrity",
                    "max_allowed_confidentiality",
                    "accepts_untrusted",
                )
                translated.append(
                    Translated(
                        name=function.name,
                        description=function.description or "",
                        schema=_schema_of(function.parameters()),
                        annotations=annotations,
                        carrier=carrier,
                        extra={
                            "approval_mode": getattr(function, "approval_mode", None),
                            "labels": {k: properties[k] for k in label_keys if k in properties},
                        },
                    )
                )
            yield translated, actor.invoke
        finally:
            actor.__exit__()

    return opener_cm


UNITS: Final = (
    Unit(
        id="langchain-mcp-adapters",
        route="mcp -> langchain",
        abstraction="langchain",
        packages=("langchain-mcp-adapters", "langchain-core"),
        open=_open_langchain,
        note="P0's first adapter; carrier `metadata`.",
    ),
    Unit(
        id="crewai-tools",
        route="mcp -> crewai",
        abstraction="crewai",
        packages=("crewai-tools", "crewai"),
        open=_open_crewai,
        note="P0's second adapter. P0 confirmed against source that no carrier exists.",
    ),
    Unit(
        id="openai-agents",
        route="mcp -> openai function tool",
        abstraction="openai_fc",
        packages=("openai-agents",),
        open=_open_openai_agents(strict=False),
        note=(
            "Confirmed against agents/mcp/util.py (MCPUtil.to_function_tool): only the "
            "title is carried, on the private `_mcp_title`; `needs_approval` comes from "
            "the server's `require_approval` setting, never from destructiveHint."
        ),
    ),
    Unit(
        id="openai-agents (strict)",
        route="mcp -> openai function tool, strict schemas",
        abstraction="openai_fc",
        packages=("openai-agents",),
        open=_open_openai_agents(strict=True),
        note="The same adapter with convert_schemas_to_strict=True, which rewrites the schema.",
    ),
    Unit(
        id="langchain -> openai_fc",
        route="mcp -> langchain -> openai function schema",
        abstraction="openai_fc",
        packages=("langchain-core",),
        open=_open_langchain_to_openai,
        note=(
            "langchain_core convert_to_openai_tool: the schema `bind_tools` sends. A "
            "format with no runtime, so it has declaration verdicts only."
        ),
    ),
    Unit(
        id="agent-framework",
        route="mcp -> microsoft agent framework",
        abstraction=None,
        packages=("agent-framework-core",),
        open=_open_agent_framework(labels=False),
        note=(
            "Confirmed against agent_framework/_mcp.py: tools/list annotations are kept "
            "only to pass to an optional load callback, never onto the FunctionTool. "
            "Not modelled by the lattice, so no restoration row."
        ),
    ),
    Unit(
        id="agent-framework (FIDES labels)",
        route="mcp -> microsoft agent framework, apply_mcp_security_labels",
        abstraction=None,
        packages=("agent-framework-core",),
        open=_open_agent_framework(labels=True),
        note=(
            "Experimental (FIDES). agent_framework/security.py maps the hints onto "
            "restriction-only integrity/confidentiality labels in additional_properties; "
            "the hints themselves are not carried. Scored `mutated` where a label exists."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Ground truth and schema flattening
# ---------------------------------------------------------------------------


def ground_truth(call_log: Path) -> dict[str, dict[str, Any]]:
    from mcp import ClientSession
    from mcp.client.stdio import stdio_client

    async def collect() -> dict[str, dict[str, Any]]:
        args = [str(FIXTURE), "--call-log", str(call_log)]
        async with (
            stdio_client(_stdio(args)) as (read, write),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            listed = await session.list_tools()
            return {tool.name: tool.model_dump(mode="json") for tool in listed.tools}

    return asyncio.run(collect())


def _resolve(node: dict[str, Any], root: dict[str, Any]) -> dict[str, Any] | None:
    reference = node.get("$ref")
    if not isinstance(reference, str):
        return node
    if not reference.startswith("#/"):
        return None
    target: Any = root
    for part in reference[2:].split("/"):
        if not isinstance(target, dict) or part not in target:
            return None
        target = target[part]
    return target if isinstance(target, dict) else None


def flatten(schema: dict[str, Any]) -> dict[str, Any]:
    """Every security-relevant fact in a schema, keyed by where it sits.

    ``reporter.email.pattern``, ``tags[].enum``, ``required:reporter``,
    ``priority.default``. References are resolved against the schema's own
    root, ``anyOf``/``oneOf`` branches are read in place (a nullable field's
    constraint lives in its non-null branch), and an unresolvable ``$ref`` is
    recorded as such rather than silently skipped.
    """
    found: dict[str, Any] = {}

    def walk(node: dict[str, Any], path: str, depth: int) -> None:
        if depth > 8:
            return
        resolved = _resolve(node, schema)
        if resolved is None:
            found[f"{path or '<root>'}.$ref"] = "unresolvable"
            return
        for keyword in CONSTRAINT_KEYWORDS:
            if keyword in resolved and path:
                found[f"{path}.{keyword}"] = resolved[keyword]
        if "default" in resolved and path:
            found[f"{path}.default"] = resolved["default"]
        properties = resolved.get("properties")
        if isinstance(properties, dict):
            found[f"required:{path or '<root>'}"] = sorted(resolved.get("required") or [])
            for name, child in properties.items():
                if isinstance(child, dict):
                    walk(child, f"{path}.{name}" if path else name, depth + 1)
        items = resolved.get("items")
        if isinstance(items, dict):
            walk(items, f"{path}[]", depth + 1)
        for combinator in ("anyOf", "oneOf", "allOf"):
            for branch in resolved.get(combinator) or ():
                if isinstance(branch, dict):
                    walk(branch, path, depth + 1)

    walk(schema, "", 0)
    return found


def _family(key: str) -> str:
    if key.startswith("required:"):
        return "required"
    if key.endswith(".default"):
        return "default"
    return "constraint"


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def compare(
    unit: Unit, truth: dict[str, dict[str, Any]], translated: list[Translated]
) -> list[Finding]:
    """Declaration verdicts: what the translated tool carries, against truth."""
    findings: list[Finding] = []
    by_name = {tool.name: tool for tool in translated}
    labelled = unit.id.endswith("(FIDES labels)")

    for name, source in truth.items():
        actual = by_name.get(name)
        if actual is None:
            findings.append(
                Finding(unit.id, name, "tool", DROPPED, note="absent after translation")
            )
            continue

        for hint in ANNOTATION_HINTS:
            expected = (source.get("annotations") or {}).get(hint)
            if expected is None:
                continue
            prop = f"annotation.{hint}"
            if hint in actual.annotations:
                observed = actual.annotations[hint]
                verdict = PRESERVED if observed == expected else MUTATED
                findings.append(
                    Finding(
                        unit.id, name, prop, verdict, expected, observed, f"on .{actual.carrier}"
                    )
                )
            elif labelled and hint != "title" and actual.extra.get("labels"):
                findings.append(
                    Finding(
                        unit.id,
                        name,
                        prop,
                        MUTATED,
                        expected,
                        actual.extra["labels"],
                        "hint not carried; folded into restriction-only security labels",
                    )
                )
            else:
                findings.append(
                    Finding(unit.id, name, prop, DROPPED, expected, None, "no carrier holds it")
                )

        expected_facts = flatten(source.get("inputSchema") or {})
        observed_facts = flatten(actual.schema)
        for key, expected in expected_facts.items():
            prop = f"{_family(key)}.{key}"
            if key not in observed_facts:
                findings.append(Finding(unit.id, name, prop, DROPPED, expected))
            elif observed_facts[key] != expected:
                findings.append(
                    Finding(unit.id, name, prop, MUTATED, expected, observed_facts[key])
                )
            else:
                findings.append(Finding(unit.id, name, prop, PRESERVED, expected))
        # A requirement the adapter added is a mutation too: a field the author
        # made optional that the target now demands changes what a call means.
        for key, observed in observed_facts.items():
            if key.startswith("required:") and key not in expected_facts:
                findings.append(
                    Finding(unit.id, name, f"required.{key}", MUTATED, None, observed, "added")
                )

        expected_description = source.get("description") or ""
        if actual.description == expected_description:
            verdict, note = PRESERVED, ""
        elif expected_description and expected_description in actual.description:
            verdict, note = MUTATED, "author's text kept, adapter added content around it"
        else:
            verdict, note = DROPPED, "author's text not present verbatim"
        findings.append(
            Finding(
                unit.id,
                name,
                "description",
                verdict,
                expected_description,
                actual.description[:200],
                note,
            )
        )

    return findings


def _reached(call_log: Path, tool: str, before: int) -> bool:
    lines = call_log.read_text(encoding="utf-8").splitlines() if call_log.exists() else []
    return any(json.loads(line)["tool"] == tool for line in lines[before:])


def _log_length(call_log: Path) -> int:
    return len(call_log.read_text(encoding="utf-8").splitlines()) if call_log.exists() else 0


def behaviour(unit: Unit, invoke: Invoke, call_log: Path) -> tuple[list[Finding], set[str]]:
    """Enforcement and error-path verdicts, from calls actually made.

    Returns the findings and the tools whose valid call reached the server -
    the only tools whose enforcement verdicts mean anything.
    """
    findings: list[Finding] = []
    working: set[str] = set()

    for tool, arguments in VALID_CALLS.items():
        before = _log_length(call_log)
        outcome = invoke(tool, arguments)
        if _reached(call_log, tool, before):
            working.add(tool)
        else:
            findings.append(
                Finding(
                    unit.id,
                    tool,
                    "invocation",
                    UNKNOWN,
                    observed=outcome.raised or outcome.output[:200],
                    note="a valid call never reached the server; behaviour verdicts withheld",
                )
            )

    for violation in VIOLATIONS:
        prop = f"enforcement.{violation.constraint}"
        if violation.tool not in working:
            findings.append(
                Finding(unit.id, violation.tool, prop, UNKNOWN, note="invocation broken")
            )
            continue
        before = _log_length(call_log)
        outcome = invoke(violation.tool, violation.arguments)
        if not _reached(call_log, violation.tool, before):
            verdict = PRESERVED if outcome.raised else UNKNOWN
            note = (
                "refused client-side before the call left the adapter"
                if outcome.raised
                else "never reached the server, yet nothing was raised"
            )
        else:
            verdict, note = DROPPED, "the invalid call reached the server; only it refused"
        findings.append(
            Finding(
                unit.id,
                violation.tool,
                prop,
                verdict,
                observed=(outcome.raised or outcome.output)[:200],
                note=note,
            )
        )

    outcome = invoke(ERROR_TOOL, {})
    if outcome.raised:
        verdict, note = PRESERVED, "isError reached the caller as an exception"
    elif "refused by the fixture" in outcome.output or "error" in outcome.output.lower():
        verdict, note = MUTATED, "isError flattened into ordinary tool output"
    else:
        verdict, note = DROPPED, "the failure is not visible in what the caller received"
    findings.append(
        Finding(
            unit.id,
            ERROR_TOOL,
            "error.isError",
            verdict,
            True,
            (outcome.raised or outcome.output)[:200],
            note,
        )
    )
    return findings, working


# ---------------------------------------------------------------------------
# Restoration: execute the generated binding
# ---------------------------------------------------------------------------


def _guards_namespace() -> dict[str, Any]:
    from toolseal.templates.common import GUARDS_PY

    namespace: dict[str, Any] = {}
    source = GUARDS_PY.substitute(project_name="s4", package_name="s4")
    exec(compile(source, "guards.py", "exec"), namespace)  # noqa: S102 - our own template
    return namespace


@contextlib.contextmanager
def _binding_environment() -> Iterator[dict[str, Any]]:
    """Install the generated guards as `guards`, and stub the `@tool` decorator.

    The stub is what tests/test_executable_guards.py uses too: what is under
    test is whether a guard fires, not how a framework registers a function.
    Approval runs with no override and no terminal, so it must refuse.
    """
    namespace = _guards_namespace()
    guards = types.ModuleType("guards")
    guards.__dict__.update(namespace)
    tools_module = types.ModuleType("langchain_core.tools")
    tools_module.tool = lambda function: function  # type: ignore[attr-defined]

    saved_modules = {name: sys.modules.get(name) for name in ("guards", "langchain_core.tools")}
    saved_env = {
        name: os.environ.get(name) for name in ("TOOLSEAL_ASSUME_YES", "TOOLSEAL_EVIDENCE")
    }
    saved_stdin = sys.stdin
    sys.modules["guards"] = guards
    sys.modules["langchain_core.tools"] = tools_module
    os.environ.pop("TOOLSEAL_ASSUME_YES", None)
    os.environ["TOOLSEAL_EVIDENCE"] = "off"
    sys.stdin = io.StringIO()
    try:
        yield namespace
    finally:
        sys.stdin = saved_stdin
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def restoration(
    unit: Unit,
    truth: dict[str, dict[str, Any]],
    invoke: Invoke,
    working: set[str],
    call_log: Path,
) -> list[Finding]:
    """Lower every tool into the unit's target and run the binding for real."""
    from toolseal.core.translate.lattice import GuardKind
    from toolseal.core.translate.lift import from_mcp
    from toolseal.core.translate.lower import identifier, lower

    if unit.abstraction is None:
        return []
    findings: list[Finding] = []
    rid = f"{unit.id} + toolseal guards"

    with _binding_environment():
        for name, source in truth.items():
            lowering = lower(from_mcp(source).descriptor, unit.abstraction)
            kinds = {guard.kind for guard in lowering.guards}
            module: dict[str, Any] = {}
            exec(compile(lowering.source, "binding.py", "exec"), module)  # noqa: S102
            module["DISPATCH"] = lambda tool, arguments: _dispatch(invoke, tool, arguments)
            bound = module[identifier(name)]

            if GuardKind.PRESERVE_DESCRIPTION in kinds:
                kept = module["SOURCE_DESCRIPTION"] == (source.get("description") or "")
                findings.append(
                    Finding(rid, name, "restore.description", PRESERVED if kept else DROPPED)
                )

            if GuardKind.REQUIRE_APPROVAL in kinds and name in working:
                before = _log_length(call_log)
                raised = _call(bound, VALID_CALLS[name])
                stopped = raised is not None and not _reached(call_log, name, before)
                findings.append(
                    Finding(
                        rid,
                        name,
                        "restore.destructiveHint",
                        PRESERVED if stopped else DROPPED,
                        observed=raised,
                        note="approval withheld, no terminal: the call must not leave",
                    )
                )

            violations = [v for v in VIOLATIONS if v.tool == name and name in working]
            if GuardKind.VALIDATE_INPUT in kinds:
                for violation in violations:
                    before = _log_length(call_log)
                    raised = _call(bound, violation.arguments)
                    stopped = not _reached(call_log, name, before)
                    findings.append(
                        Finding(
                            rid,
                            name,
                            f"restore.enforcement.{violation.constraint}",
                            PRESERVED if stopped else DROPPED,
                            observed=raised,
                            note="" if stopped else "the guard let it through to the server",
                        )
                    )
            elif violations:
                # Found on the first run: lower() emits VALIDATE_INPUT only for a
                # tool declaring clientValidation, which an MCP tool never does.
                findings.append(
                    Finding(
                        rid,
                        name,
                        "restore.validate_input.emitted",
                        DROPPED,
                        note="lower() generated no validation guard for this tool",
                    )
                )
                findings += _validate_directly(unit, name, source, invoke, violations, call_log)

            if GuardKind.MAP_ERROR_CHANNEL in kinds and name == ERROR_TOOL:
                raised = _call(bound, {})
                findings.append(
                    Finding(
                        rid,
                        name,
                        "restore.error.isError",
                        PRESERVED if raised else DROPPED,
                        observed=raised,
                    )
                )

            if GuardKind.ANNOTATE_SIDECAR in kinds:
                entry = lowering.record
                findings.append(
                    Finding(
                        rid,
                        name,
                        "restore.sidecar",
                        PRESERVED if entry is not None else DROPPED,
                        note="hints recorded in the compensation manifest, no behaviour to run",
                    )
                )
    return findings


def _validate_directly(
    unit: Unit,
    name: str,
    source: dict[str, Any],
    invoke: Invoke,
    violations: list[Violation],
    call_log: Path,
) -> list[Finding]:
    """The validation guard applied by hand, because lower() never emits it.

    Measures what the guard would do if it were generated, so the gap is sized
    rather than only named. Labelled `direct.` so it cannot be read as
    something toolseal actually ships into a binding.
    """
    # Installed by _binding_environment for the duration of restoration().
    validate_against_schema = sys.modules["guards"].validate_against_schema
    guarded = validate_against_schema(source.get("inputSchema") or {})(
        lambda **arguments: _dispatch(invoke, name, arguments)
    )
    findings = []
    for violation in violations:
        before = _log_length(call_log)
        raised = _call(guarded, violation.arguments)
        stopped = not _reached(call_log, name, before)
        findings.append(
            Finding(
                f"{unit.id} + validate_against_schema, applied by hand",
                name,
                f"direct.enforcement.{violation.constraint}",
                PRESERVED if stopped else DROPPED,
                observed=raised,
                note="" if stopped else "the guard does not descend into $ref, anyOf or items",
            )
        )
    return findings


def _dispatch(invoke: Invoke, tool: str, arguments: dict[str, Any]) -> str:
    outcome = invoke(tool, arguments)
    if outcome.raised:
        raise RuntimeError(outcome.raised)
    return outcome.output


def _call(bound: Callable[..., Any], arguments: dict[str, Any]) -> str | None:
    try:
        bound(**arguments)
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"[:200]
    return None


# ---------------------------------------------------------------------------
# Lattice agreement
# ---------------------------------------------------------------------------

_PROPERTY_FAMILIES: Final = {
    "readOnlyHint": ("annotation.readOnlyHint",),
    "destructiveHint": ("annotation.destructiveHint",),
    "idempotentHint": ("annotation.idempotentHint",),
    "openWorldHint": ("annotation.openWorldHint",),
    # A field made required that the author left optional changes what a call
    # means, so a `required` set counts here as well as the constraint keywords.
    "inputConstraints": ("constraint.", "required."),
    "clientValidation": ("enforcement.",),
    "errorChannel": ("error.",),
    "descriptionIntegrity": ("description",),
}


def lattice_agreement(unit: Unit, findings: list[Finding]) -> list[dict[str, Any]]:
    """Does the lattice's claim about this target match what was measured?"""
    from toolseal.core.properties import SecurityProperty
    from toolseal.core.translate.lattice import PROFILES

    if unit.abstraction is None or unit.abstraction not in PROFILES:
        return []
    profile = PROFILES[unit.abstraction]
    rows = []
    for prop in SecurityProperty:
        prefixes = _PROPERTY_FAMILIES[prop.value]
        relevant = [f for f in findings if f.unit == unit.id and f.prop.startswith(prefixes)]
        decided = [f for f in relevant if f.verdict != UNKNOWN]
        measured = all(f.verdict == PRESERVED for f in decided) if decided else None
        claimed = profile.expresses(prop)
        rows.append(
            {
                "property": prop.value,
                "lattice_says_expressible": claimed,
                "measured_preserved": measured,
                "agrees": None if measured is None else measured == claimed,
                "evidence": profile.evidence.value,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Running and reporting
# ---------------------------------------------------------------------------


def _version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not installed"


def run_unit(unit: Unit, truth: dict[str, dict[str, Any]], workdir: Path) -> dict[str, Any]:
    call_log = workdir / f"{abs(hash(unit.id))}.log"
    args = [str(FIXTURE), "--call-log", str(call_log)]
    findings: list[Finding] = []
    agreement: list[dict[str, Any]] = []
    error = ""
    try:
        with unit.open(args) as (translated, invoke):
            findings += compare(unit, truth, translated)
            extras = {tool.name: tool.extra for tool in translated if tool.extra}
            if invoke is not None:
                behaviour_findings, working = behaviour(unit, invoke, call_log)
                findings += behaviour_findings
                agreement = lattice_agreement(unit, findings)
                if unit.abstraction is not None:
                    findings += restoration(unit, truth, invoke, working, call_log)
            else:
                agreement = lattice_agreement(unit, findings)
    # Broad by design: a unit that cannot be evaluated is itself a result.
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"[:300]
        extras = {}
        findings.append(Finding(unit.id, "*", "adapter", UNKNOWN, note=f"not evaluated: {error}"))

    return {
        "id": unit.id,
        "route": unit.route,
        "abstraction": unit.abstraction,
        "versions": {name: _version(name) for name in unit.packages},
        "note": unit.note,
        "error": error,
        "extras": extras,
        "findings": [asdict(finding) for finding in findings],
        "lattice_agreement": agreement,
    }


def summarise(units: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    """Verdict counts per unit per property family."""
    table: dict[str, dict[str, int]] = {}
    for unit in units:
        for finding in unit["findings"]:
            prop = finding["prop"]
            head, _, rest = prop.partition(".")
            family = f"{head}.{rest.split('.')[0]}" if head in ("restore", "direct") else head
            key = f"{finding['unit']} / {family}"
            table.setdefault(key, dict.fromkeys(VERDICTS, 0))
            table[key][finding["verdict"]] += 1
    return dict(sorted(table.items()))


def loss_rates(units: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The protocol's headline metric: loss rate per property family per unit.

    Loss is ``dropped`` plus ``mutated`` over every decided verdict; ``unknown``
    leaves the denominator rather than counting either way.
    """
    rows = []
    for unit in units:
        families: dict[str, list[str]] = {}
        for finding in unit["findings"]:
            if finding["prop"].startswith(("restore.", "direct.")):
                continue
            family = finding["prop"].split(".")[0]
            families.setdefault(family, []).append(finding["verdict"])
        for family, verdicts in sorted(families.items()):
            decided = [v for v in verdicts if v != UNKNOWN]
            lost = sum(1 for v in decided if v in (DROPPED, MUTATED))
            rows.append(
                {
                    "unit": unit["id"],
                    "family": family,
                    "decided": len(decided),
                    "lost": lost,
                    "loss_rate": round(lost / len(decided), 3) if decided else None,
                }
            )
    return rows


def run() -> dict[str, Any]:
    logging.disable(logging.WARNING)
    warnings.simplefilter("ignore")
    with tempfile.TemporaryDirectory(prefix="toolseal-s4-") as tmp:
        workdir = Path(tmp)
        truth = ground_truth(workdir / "truth.log")
        units = [run_unit(unit, truth, workdir) for unit in UNITS]
    logging.disable(logging.NOTSET)

    return {
        "study": "S4 translation fidelity at scale",
        "platform": {
            "os": platform.system(),
            "python": platform.python_version(),
            "mcp": _version("mcp"),
            "pydantic": _version("pydantic"),
            "toolseal": _version("toolseal"),
        },
        "fixture": "bench/s4_fixture_server.py",
        "ground_truth": truth,
        "violations": [asdict(v) for v in VIOLATIONS],
        "units": units,
        "summary": summarise(units),
        "loss_rates": loss_rates(units),
    }


def to_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Study 4 - translation fidelity at scale",
        "",
        "Generated by `uv run python -m bench s4` (needs `uv sync --group research`).",
        f"Platform: {payload['platform']['os']}, Python {payload['platform']['python']}, "
        f"`mcp` {payload['platform']['mcp']}, `pydantic` {payload['platform']['pydantic']}.",
        "",
        "Verdicts are P0's: `preserved`, `dropped`, `mutated`, `unknown`. Every one is",
        "taken from the object an adapter produced or from a call actually made through it.",
        "",
        "## Units",
        "",
        "| unit | route | versions | note |",
        "| --- | --- | --- | --- |",
    ]
    for unit in payload["units"]:
        versions = ", ".join(f"`{k}` {v}" for k, v in unit["versions"].items())
        note = (unit["error"] or unit["note"]).replace("|", "/")
        lines.append(f"| `{unit['id']}` | {unit['route']} | {versions} | {note} |")

    lines += [
        "",
        "## Loss rate per property family",
        "",
        "Loss is `dropped` + `mutated` over decided verdicts; `unknown` leaves the",
        "denominator. Families: `annotation` hints, schema `constraint`s, `required`",
        "sets, `default`s, `description`, client-side `enforcement`, the `error` path.",
        "",
        "| unit | family | lost / decided | loss rate |",
        "| --- | --- | ---: | ---: |",
    ]
    for row in payload["loss_rates"]:
        rate = "-" if row["loss_rate"] is None else f"{row['loss_rate']:.0%}"
        lines.append(
            f"| `{row['unit']}` | {row['family']} | {row['lost']} / {row['decided']} | {rate} |"
        )

    lines += [
        "",
        "## Does the lattice match what was measured?",
        "",
        "`toolseal`'s translation lattice decides which guards to generate from what it",
        "believes each target can express. A disagreement means it would generate the",
        "wrong guards for that target.",
        "",
        "| unit | property | lattice says | measured | agrees | lattice evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for unit in payload["units"]:
        for row in unit["lattice_agreement"]:
            measured = {True: "preserved", False: "lost", None: "not measured"}[
                row["measured_preserved"]
            ]
            agrees = {True: "yes", False: "**no**", None: "-"}[row["agrees"]]
            claim = "expressible" if row["lattice_says_expressible"] else "not expressible"
            lines.append(
                f"| `{unit['id']}` | `{row['property']}` | {claim} | {measured} | {agrees} "
                f"| {row['evidence']} |"
            )

    lines += [
        "",
        "## Do the generated guards restore what was lost?",
        "",
        "Each tool was lowered into the unit's target and the generated binding executed",
        "with its real guards, dispatching to the real translated tool. `preserved` here",
        "means the guard was observed firing; `dropped` means the call got through anyway.",
        "",
        "| unit | property | restored | not restored |",
        "| --- | --- | ---: | ---: |",
    ]
    restored: dict[tuple[str, str], list[int]] = {}
    for unit in payload["units"]:
        for finding in unit["findings"]:
            if not finding["prop"].startswith(("restore.", "direct.")):
                continue
            family = finding["prop"].split(".")[1]
            bucket = restored.setdefault((finding["unit"], family), [0, 0])
            bucket[0 if finding["verdict"] == PRESERVED else 1] += 1
    for (unit_id, family), (good, bad) in sorted(restored.items()):
        lines.append(f"| `{unit_id}` | {family} | {good} | {bad} |")

    lines += [
        "",
        "## Every loss, mutation and unrestored guard",
        "",
        "| unit | tool | property | verdict | note |",
        "| --- | --- | --- | --- | --- |",
    ]
    for unit in payload["units"]:
        for finding in unit["findings"]:
            if finding["verdict"] == PRESERVED:
                continue
            note = (finding["note"] or "").replace("|", "/")
            lines.append(
                f"| `{finding['unit']}` | `{finding['tool']}` | `{finding['prop']}` "
                f"| **{finding['verdict']}** | {note} |"
            )

    lines += [
        "",
        "## Known limitations",
        "",
        "- One fixture server, one platform, one version of each adapter. Versions are",
        "  recorded above; a different version is a different unit.",
        "- Annotation carriers are searched by name. Every `dropped` annotation verdict for",
        "  an adapter P0 did not test was confirmed against that adapter's source; each",
        "  unit's note says where.",
        "- Restoration stubs the target framework's `@tool` decorator, as the project's own",
        "  executable-guard tests do: what is measured is whether the guard fires.",
        "- `agent-framework` is not modelled by the lattice, so it has no restoration rows.",
    ]
    return "\n".join(lines) + "\n"


def write(payload: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str),
        encoding="utf-8",
        newline="\n",
    )
    (out_dir / "RESULTS.md").write_text(to_markdown(payload), encoding="utf-8", newline="\n")
