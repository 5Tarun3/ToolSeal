"""Compensating guards, executed rather than inspected.

Contribution C5 claims a property a target cannot express is restored as
behaviour. Until now that was asserted by reading generated source: the binding
imported guards the template never defined, and called an undefined
`call_upstream`. It would have failed on the first import.

So these tests run the generated code. A guard that is emitted but never fires
compensates for nothing, and the difference is invisible to any test that only
reads the text.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from toolseal.core.properties import SecurityProperty
from toolseal.core.registry.utd import (
    SecurityAnnotations,
    ToolSource,
    UnifiedToolDescriptor,
)
from toolseal.core.translate.lower import lower
from toolseal.templates.common import GUARDS_PY


def guards_module() -> dict[str, Any]:
    namespace: dict[str, Any] = {}
    source = GUARDS_PY.substitute(project_name="bench", package_name="bench")
    exec(compile(source, "guards.py", "exec"), namespace)  # noqa: S102
    return namespace


@pytest.fixture
def wired(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a fake `guards` module and a stub `@tool`, then load a binding."""
    monkeypatch.setenv("TOOLSEAL_ASSUME_YES", "1")

    namespace = guards_module()
    guards = types.ModuleType("guards")
    guards.__dict__.update(namespace)
    monkeypatch.setitem(sys.modules, "guards", guards)

    tools = types.ModuleType("langchain_core.tools")
    tools.tool = lambda function: function  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langchain_core", types.ModuleType("langchain_core"))
    monkeypatch.setitem(sys.modules, "langchain_core.tools", tools)

    def load(descriptor: UnifiedToolDescriptor, target: str) -> dict[str, Any]:
        module: dict[str, Any] = {}
        exec(compile(lower(descriptor, target).source, "binding.py", "exec"), module)  # noqa: S102
        return module

    return load


def descriptor(**overrides: Any) -> UnifiedToolDescriptor:
    defaults: dict[str, Any] = {
        "id": "mcp/fs@1#delete",
        "name": "delete_records",
        "description": "Permanently delete rows.",
        "source": ToolSource("mcp", "npm", "@example/fs", "1.0.0"),
        "input_schema": {
            "properties": {"table": {"enum": ["users", "orders"]}, "limit": {"maximum": 100}}
        },
        "annotations": SecurityAnnotations(destructive=True),
    }
    return UnifiedToolDescriptor(**{**defaults, **overrides})


# --- the guards exist at all -----------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["require_approval", "validate_against_schema", "raise_on_tool_error", "minimal_environment"],
)
def test_every_emitted_guard_is_defined(name: str) -> None:
    # Lowering emits `from guards import ...` for each of these. Two of them did
    # not exist, so the binding would have failed on import.
    assert callable(guards_module()[name])


def test_every_guard_the_lowering_imports_can_be_imported() -> None:
    # The general form: whatever a guard declares as its import must resolve.
    from toolseal.core.translate.lower import _GUARD_CODE

    available = guards_module()
    for code in _GUARD_CODE.values():
        for line in code.imports:
            symbol = line.rsplit(" import ", 1)[-1].strip()
            assert symbol in available, f"{symbol} is imported but never defined"


# --- the binding runs ------------------------------------------------------


def test_binding_raises_until_it_is_wired(wired: Any) -> None:
    # Silently returning nothing would make a guarded tool look like it worked.
    module = wired(descriptor(), "crewai")

    with pytest.raises(NotImplementedError, match="not wired"):
        module["delete_records"](table="users")


def test_wired_binding_reaches_dispatch(wired: Any) -> None:
    module = wired(descriptor(), "crewai")
    seen: list[tuple[str, dict[str, Any]]] = []

    def dispatch(name: str, arguments: dict[str, Any]) -> str:
        seen.append((name, arguments))
        return "deleted"

    module["DISPATCH"] = dispatch

    result = module["delete_records"](table="users")

    assert result == "deleted"
    assert seen == [("delete_records", {"table": "users"})]


def test_approval_guard_is_actually_applied(wired: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    # The C5 claim, executed. With approval withheld and no terminal attached,
    # the call must be refused rather than reaching dispatch.
    monkeypatch.delenv("TOOLSEAL_ASSUME_YES", raising=False)
    module = wired(descriptor(), "crewai")
    module["DISPATCH"] = lambda name, arguments: "should not run"

    with pytest.raises(PermissionError):
        module["delete_records"](table="users")


def test_author_description_survives_a_target_that_rewrites_it(wired: Any) -> None:
    module = wired(descriptor(), "crewai")

    assert module["SOURCE_DESCRIPTION"] == "Permanently delete rows."


def test_a_lossless_target_emits_no_guards(wired: Any) -> None:
    # claude-code expresses destructiveHint natively, so the binding is plain.
    module = wired(descriptor(), "claude-code")
    module["DISPATCH"] = lambda name, arguments: "ok"

    assert module["delete_records"](table="users") == "ok"


# --- the validation guard --------------------------------------------------


def test_validation_rejects_what_the_schema_forbids() -> None:
    namespace = guards_module()
    guard = namespace["validate_against_schema"](
        {"properties": {"table": {"enum": ["users", "orders"]}, "limit": {"maximum": 100}}}
    )
    call = guard(lambda **kwargs: "ran")

    assert call(table="users", limit=10) == "ran"
    for bad in ({"table": "secrets"}, {"limit": 99999}):
        with pytest.raises(namespace["SchemaViolationError"]):
            call(**bad)


def test_validation_ignores_fields_the_schema_does_not_constrain() -> None:
    namespace = guards_module()
    call = namespace["validate_against_schema"]({"properties": {}})(lambda **kwargs: "ran")

    assert call(anything="at all") == "ran"


@pytest.mark.parametrize(
    ("rules", "value"),
    [
        ({"pattern": r"^/docs/"}, "/etc/passwd"),
        ({"maxLength": 3}, "toolong"),
        ({"minLength": 5}, "abc"),
        ({"minimum": 10}, 1),
    ],
)
def test_each_constraint_keyword_is_enforced(rules: dict[str, Any], value: Any) -> None:
    namespace = guards_module()
    call = namespace["validate_against_schema"]({"properties": {"x": rules}})(
        lambda **kwargs: "ran"
    )

    with pytest.raises(namespace["SchemaViolationError"]):
        call(x=value)


# --- the error-channel guard -----------------------------------------------


def test_error_shaped_result_becomes_an_exception() -> None:
    # G3: the adapter has already flattened isError into content by the time
    # this sees it, so failure has to be recognised from the text.
    namespace = guards_module()
    call = namespace["raise_on_tool_error"](
        lambda: "Error executing tool read_document: validation error"
    )

    with pytest.raises(namespace["ToolCallError"]):
        call()


def test_ordinary_output_passes_through() -> None:
    namespace = guards_module()

    assert namespace["raise_on_tool_error"](lambda: "42 rows")() == "42 rows"


# --- the import cycle ------------------------------------------------------


def test_the_vocabulary_module_depends_on_nothing() -> None:
    # registry.utd and translate.lattice both need SecurityProperty. Owning it
    # in either made them import each other, and the cycle only surfaced
    # depending on which a caller touched first.
    from pathlib import Path

    source = Path("src/toolseal/core/properties.py").read_text(encoding="utf-8")

    assert "from toolseal" not in source
    assert SecurityProperty.DESTRUCTIVE in frozenset(SecurityProperty)
