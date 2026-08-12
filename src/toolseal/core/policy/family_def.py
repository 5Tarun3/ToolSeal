"""Families D, E and F - transport, containment, and accountability.

Grouped in one module because each is small and they share a property worth
stating once: these are **configuration** checks, not runtime enforcement. They
ask whether isolation is configured, whether logging is configured, whether an
approval step exists - not whether any of it fires. Runtime enforcement is out
of scope and covered by published work; the contribution here is asking at the
moment the answer gets written down.
"""

from __future__ import annotations

from collections.abc import Sequence

from toolseal.core.model import ProjectModel
from toolseal.core.policy.model import Check, Finding, Severity, register


def _remote(model: ProjectModel) -> bool:
    return model.has_remote_endpoint


def _d1(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="D1",
            severity=Severity.CRITICAL,
            title="Remote MCP endpoint is not TLS-protected",
            detail=f"{server.name} is reached over {server.url}, in the clear",
            location=server.name,
            remediation="Use an https endpoint; anything on the path can read and rewrite calls.",
        )
        for server in model.mcp_servers
        if server.is_remote and not server.uses_tls
    ]


def _d2(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="D2",
            severity=Severity.HIGH,
            title="Remote MCP server is reached without authentication",
            detail=f"{server.name} is remote and no authentication is configured",
            location=server.name,
            remediation="Configure authentication, or use a local server instead.",
        )
        for server in model.mcp_servers
        if server.is_remote and not server.authenticated
    ]


def _d3(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="D3",
            severity=Severity.HIGH,
            title="Provider endpoint is overridden",
            detail=(
                f"{provider.provider_id} is pointed at {provider.base_url} rather than the "
                "vendor default, which is the mechanism by which traffic and credentials "
                "get silently proxied"
            ),
            location=provider.provider_id,
            remediation="Use the vendor default, or record why the override is intended.",
        )
        for provider in model.providers
        if provider.overrides_endpoint
    ]


def _e1(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="E1",
            severity=Severity.CRITICAL,
            title="Code execution with no configured isolation",
            detail=f"{tool.name} runs arbitrary code with no sandbox or container configured",
            location=tool.name,
            remediation="Configure isolation for the tool, or remove it.",
        )
        for tool in model.tools
        if tool.is_executor and not tool.isolation
    ]


def _e2(model: ProjectModel) -> Sequence[Finding]:
    if not model.runtime.inherits_host_environment:
        return []
    return [
        Finding(
            check_id="E2",
            severity=Severity.HIGH,
            title="Agent inherits the full host environment",
            detail=(
                "Cloud CLI profiles, SSH agent sockets and every exported secret are visible "
                "to the agent and to any tool it calls"
            ),
            remediation="Launch with an explicit, minimal environment.",
        )
    ]


def _e3(model: ProjectModel) -> Sequence[Finding]:
    findings = [
        Finding(
            check_id="E3",
            severity=Severity.MEDIUM,
            title="Tool call has no timeout",
            detail=f"{tool.name} can block indefinitely",
            location=tool.name,
            remediation="Set a timeout on the tool call.",
        )
        for tool in model.tools
        if tool.timeout_seconds is None
    ]

    if not model.tools and model.runtime.default_timeout_seconds is None:
        findings.append(
            Finding(
                check_id="E3",
                severity=Severity.MEDIUM,
                title="No default timeout configured",
                detail="Nothing bounds how long a call may take",
                remediation="Set a default timeout for the project.",
            )
        )
    return findings


def _f1(model: ProjectModel) -> Sequence[Finding]:
    if model.runtime.logs_tool_invocations:
        return []
    return [
        Finding(
            check_id="F1",
            severity=Severity.MEDIUM,
            title="Tool invocations are not logged",
            detail="There is no record of what the agent did, so an incident cannot be reviewed",
            remediation="Configure structured logging of tool calls, with redaction applied.",
        )
    ]


def _f2(model: ProjectModel) -> Sequence[Finding]:
    if model.runtime.approval_required_for_destructive:
        return []
    return [
        Finding(
            check_id="F2",
            severity=Severity.HIGH,
            title="Destructive tool has no approval gate",
            detail=f"{tool.name} is declared destructive and can run without confirmation",
            location=tool.name,
            remediation="Wrap the tool in an approval step.",
        )
        for tool in model.tools
        if tool.destructive and not tool.requires_approval
    ]


D1 = register(
    Check(
        id="D1",
        family="D",
        title="Remote MCP endpoint over a non-TLS transport",
        severity=Severity.CRITICAL,
        remediation="Use an https endpoint.",
        run=_d1,
        applies=_remote,
    )
)

D2 = register(
    Check(
        id="D2",
        family="D",
        title="Remote MCP server reached without authentication",
        severity=Severity.HIGH,
        remediation="Configure authentication for the remote server.",
        run=_d2,
        applies=_remote,
    )
)

D3 = register(
    Check(
        id="D3",
        family="D",
        title="Provider base URL overridden to a non-default host",
        severity=Severity.HIGH,
        remediation="Use the vendor default, or declare the override.",
        run=_d3,
        applies=_remote,
    )
)

E1 = register(
    Check(
        id="E1",
        family="E",
        title="Code-execution capability with no configured isolation",
        severity=Severity.CRITICAL,
        remediation="Configure isolation, or remove the tool.",
        run=_e1,
        applies=lambda model: bool(model.tools),
    )
)

E2 = register(
    Check(
        id="E2",
        family="E",
        title="Agent inherits ambient host credentials",
        severity=Severity.HIGH,
        remediation="Launch with an explicit, minimal environment.",
        run=_e2,
    )
)

E3 = register(
    Check(
        id="E3",
        family="E",
        title="No timeout or resource bound on tool calls",
        severity=Severity.MEDIUM,
        remediation="Set timeouts on tool calls.",
        run=_e3,
    )
)

F1 = register(
    Check(
        id="F1",
        family="F",
        title="No audit log of tool invocations",
        severity=Severity.MEDIUM,
        remediation="Configure structured invocation logging.",
        run=_f1,
    )
)

F2 = register(
    Check(
        id="F2",
        family="F",
        title="No approval gate on destructive operations",
        severity=Severity.HIGH,
        remediation="Wrap destructive tools in an approval step.",
        run=_f2,
        applies=lambda model: bool(model.tools),
    )
)
