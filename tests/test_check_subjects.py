"""`Finding.subject`: which findings name one entity, and what that name is.

Per-tool relaxation (`[policy.relax.<ID>].tools`) matches on `Finding.subject`,
so a check whose finding is about one named tool, server or dependency must
populate it - and a check whose finding is anchored to a file path, or to the
project as a whole, must not invent one.

`location` already carries these same strings for many checks (that is the
family modules' existing display field); `subject` is the machine-matchable
form and both are asserted together so a future edit cannot quietly drop one
while keeping the other.
"""

from __future__ import annotations

from pathlib import Path

from toolseal.core.model import (
    AgentBinding,
    Dependency,
    DependencySet,
    MCPServerBinding,
    ProjectModel,
    ProviderBinding,
    ToolBinding,
    ToolKind,
    TranslationRecord,
    Transport,
)
from toolseal.core.policy.family_b import _b1, _b2, _b3, _b4, _b5
from toolseal.core.policy.family_c import _c1
from toolseal.core.policy.family_def import _d1, _d3, _e1, _f2
from toolseal.core.policy.family_g import _g1


def test_b1_subject_is_the_agent_name() -> None:
    model = ProjectModel(
        root=Path(),
        agents=(AgentBinding(name="planner", framework_id="langgraph", binds_all_tools=True),),
    )
    (finding,) = _b1(model)
    assert finding.subject == "planner"
    assert finding.location == "planner"


def test_b2_subject_is_the_tool_name() -> None:
    model = ProjectModel(
        root=Path(),
        tools=(ToolBinding(name="ci_shell", kind=ToolKind.SHELL, origin="native"),),
    )
    (finding,) = _b2(model)
    assert finding.subject == "ci_shell"
    assert finding.location == "ci_shell"


def test_b3_subject_is_the_tool_name() -> None:
    model = ProjectModel(
        root=Path(),
        tools=(
            ToolBinding(
                name="fs", kind=ToolKind.FILESYSTEM, origin="native", filesystem_roots=("/",)
            ),
        ),
    )
    (finding,) = _b3(model)
    assert finding.subject == "fs"


def test_b4_subject_is_the_server_name() -> None:
    model = ProjectModel(
        root=Path(),
        mcp_servers=(
            MCPServerBinding(
                name="db",
                transport=Transport.STDIO,
                declared_scope=frozenset({"read"}),
                advertised_scope=frozenset({"read", "write"}),
            ),
        ),
    )
    (finding,) = _b4(model)
    assert finding.subject == "db"


def test_b5_subject_is_the_agent_name() -> None:
    model = ProjectModel(
        root=Path(),
        agents=(AgentBinding(name="researcher", framework_id="crewai", allowlist_pinned=False),),
    )
    (finding,) = _b5(model)
    assert finding.subject == "researcher"


def test_d1_subject_is_the_server_name() -> None:
    model = ProjectModel(
        root=Path(),
        mcp_servers=(MCPServerBinding(name="mcp1", transport=Transport.SSE, url="http://x"),),
    )
    (finding,) = _d1(model)
    assert finding.subject == "mcp1"


def test_d3_subject_is_the_provider_id() -> None:
    model = ProjectModel(
        root=Path(),
        providers=(ProviderBinding("openai", base_url="https://proxy.internal"),),
    )
    (finding,) = _d3(model)
    assert finding.subject == "openai"


def test_e1_subject_is_the_tool_name() -> None:
    model = ProjectModel(
        root=Path(),
        tools=(ToolBinding(name="runner", kind=ToolKind.CODE_EXECUTION, origin="native"),),
    )
    (finding,) = _e1(model)
    assert finding.subject == "runner"


def test_f2_subject_is_the_tool_name() -> None:
    model = ProjectModel(
        root=Path(),
        tools=(
            ToolBinding(name="delete_all", kind=ToolKind.OTHER, origin="native", destructive=True),
        ),
    )
    (finding,) = _f2(model)
    assert finding.subject == "delete_all"


def test_g1_subject_is_the_translation_tool_name() -> None:
    record = TranslationRecord(
        tool_name="delete_records",
        source_abstraction="mcp",
        target_abstraction="crewai",
        dropped_properties=frozenset({"destructiveHint"}),
    )
    model = ProjectModel(root=Path(), translations=(record,))
    (finding,) = _g1(model)
    assert finding.subject == "delete_records"


def test_c1_unpinned_dependency_subject_is_the_dependency_name() -> None:
    model = ProjectModel(
        root=Path(),
        dependencies=DependencySet(declared=(Dependency(name="requests", specifier=">=2"),)),
    )
    findings = _c1(model)
    unpinned = next(f for f in findings if f.title == "Unpinned dependency")
    assert unpinned.subject == "requests"


def test_c1_no_lockfile_finding_carries_no_subject() -> None:
    # Project-wide - no single dependency, tool or server to name.
    model = ProjectModel(
        root=Path(),
        dependencies=DependencySet(declared=(Dependency(name="requests", specifier=">=2"),)),
    )
    (no_lockfile,) = [f for f in _c1(model) if f.title == "No lockfile"]
    assert no_lockfile.subject is None
