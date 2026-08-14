"""Family B - capability overprovisioning.

AgentWarden measures 15x overprovisioning in default agent runtimes and spends a
learned policy plus roughly 800 ms per call correcting it at runtime. That
overprovisioning is a *default*, and defaults are written at setup. This family
exists to delete the problem where it is created rather than fight it where it
is observed.

`B2` is the family's centre of gravity, and the only check in the taxonomy that
consults the project manifest for *intent*. Whether a shell tool is acceptable
cannot be decided from code: a build agent legitimately needs one, a
summarisation agent does not. Requiring the reason to be written down converts
an unanswerable question into an answerable one.
"""

from __future__ import annotations

from collections.abc import Sequence

from toolseal.core.manifest import Manifest
from toolseal.core.model import ProjectModel
from toolseal.core.policy.controls import ControlRef
from toolseal.core.policy.model import Check, Finding, Severity, register


def _manifest(model: ProjectModel) -> Manifest | None:
    try:
        return Manifest.load(model.root)
    except Exception:
        return None


def _b1(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="B1",
            severity=Severity.HIGH,
            title="Agent is bound to every available tool",
            detail=(
                f"{agent.name} receives the whole tool collection rather than a task-scoped "
                "subset, which is the overprovisioning default"
            ),
            location=agent.name,
            remediation="Bind an explicit list of the tools this agent actually needs.",
        )
        for agent in model.agents
        if agent.binds_all_tools
    ]


def _b2(model: ProjectModel) -> Sequence[Finding]:
    manifest = _manifest(model)
    return [
        Finding(
            check_id="B2",
            severity=Severity.CRITICAL,
            title="Code-execution tool with no recorded justification",
            detail=(
                f"{tool.name} can execute arbitrary code and no reason is recorded in "
                "toolseal.toml, so nobody has said why the agent needs it"
            ),
            location=tool.name,
            remediation=(
                f"Remove the tool, or record why it is needed under [justifications] as "
                f'{tool.name} = "reason".'
            ),
        )
        for tool in model.tools
        if tool.is_executor
        and not tool.justification
        and (manifest is None or manifest.justification_for(tool.name) is None)
    ]


def _b3(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="B3",
            severity=Severity.HIGH,
            title="Filesystem access is not confined",
            detail=f"{tool.name} is rooted at {', '.join(tool.filesystem_roots)}",
            location=tool.name,
            remediation="Root filesystem access at the project workspace and resolve before use.",
        )
        for tool in model.tools
        if tool.has_unbounded_root
    ]


def _b4(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="B4",
            severity=Severity.MEDIUM,
            title="MCP server is scoped wider than its declared purpose",
            detail=(
                f"{server.name} advertises {', '.join(sorted(server.scope_excess))} beyond "
                "what the project declared it for"
            ),
            location=server.name,
            remediation="Narrow the launch configuration, or widen the declared scope knowingly.",
        )
        for server in model.mcp_servers
        if server.scope_excess
    ]


def _b5(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="B5",
            severity=Severity.MEDIUM,
            title="Tool set is resolved at runtime with no pinned allowlist",
            detail=(
                f"{agent.name} discovers its tools dynamically, so the available set can "
                "change without any change to this project"
            ),
            location=agent.name,
            remediation="Pin the resolved tool list so a change to it shows up as a diff.",
        )
        for agent in model.agents
        if not agent.allowlist_pinned
    ]


B1 = register(
    Check(
        id="B1",
        family="B",
        title="All tools bound to every agent or session unconditionally",
        severity=Severity.HIGH,
        remediation="Bind an explicit, task-scoped tool list.",
        run=_b1,
        applies=lambda model: bool(model.agents),
        controls=(
            ControlRef("owasp-llm-top10", "LLM06"),
            ControlRef("owasp-agentic-threats", "T2"),
            ControlRef("owasp-agentic-top10", "ASI02"),
        ),
    )
)

B2 = register(
    Check(
        id="B2",
        family="B",
        title="Shell or code-execution capability without declared justification",
        severity=Severity.CRITICAL,
        remediation="Remove the tool, or record why it is needed.",
        run=_b2,
        applies=lambda model: bool(model.tools),
        controls=(
            ControlRef("owasp-llm-top10", "LLM06"),
            ControlRef("owasp-agentic-threats", "T11"),
            ControlRef("owasp-agentic-top10", "ASI05"),
        ),
    )
)

B3 = register(
    Check(
        id="B3",
        family="B",
        title="Filesystem capability with unbounded or home-directory root",
        severity=Severity.HIGH,
        remediation="Confine filesystem access to the workspace.",
        run=_b3,
        applies=lambda model: bool(model.tools),
        controls=(
            ControlRef("owasp-llm-top10", "LLM06"),
            ControlRef("owasp-agentic-threats", "T3"),
            ControlRef("owasp-agentic-top10", "ASI03"),
        ),
    )
)

B4 = register(
    Check(
        id="B4",
        family="B",
        title="MCP server granted scope wider than the declared task",
        severity=Severity.MEDIUM,
        remediation="Narrow the launch configuration to the declared scope.",
        run=_b4,
        applies=lambda model: bool(model.mcp_servers),
        controls=(
            ControlRef("owasp-llm-top10", "LLM06"),
            ControlRef("owasp-agentic-threats", "T3"),
            ControlRef("owasp-agentic-top10", "ASI02"),
        ),
    )
)

B5 = register(
    Check(
        id="B5",
        family="B",
        title="Tool set resolved dynamically with no allowlist",
        severity=Severity.MEDIUM,
        remediation="Pin the resolved tool list.",
        run=_b5,
        applies=lambda model: bool(model.agents),
        controls=(
            ControlRef("owasp-llm-top10", "LLM03"),
            ControlRef("owasp-agentic-threats", "T2"),
            ControlRef("nist-ai-rmf", "GOVERN-6.1"),
            ControlRef("owasp-agentic-top10", "ASI04"),
        ),
    )
)
