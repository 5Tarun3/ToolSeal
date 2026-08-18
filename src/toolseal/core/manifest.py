"""The project manifest: what a project declares about itself.

Several checks cannot be answered from code alone. Whether a shell tool is
justified (``B2``), or whether an MCP server's scope matches the job it was
added for (``B4``), depends on *intent* - and intent has to be written down
somewhere or the check degenerates into guessing.

``toolseal.toml`` is that place. Its absence is meaningful rather than fatal:
`audit` still runs on projects toolseal did not create, and a project with no
declared justification for its shell tool fails ``B2`` correctly, because an
undeclared justification is exactly what that check looks for.

Read with the standard library's ``tomllib``; written by hand. A TOML writer
would be a dependency bought for one small, entirely predictable document.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from toolseal.errors import ConfigError

MANIFEST_NAME: Final = "toolseal.toml"

# The only value `approval` may take today. A typo here should fail loudly at
# load time rather than silently doing nothing - an unrecognised value is not
# the same as "no approval policy declared".
_VALID_APPROVAL_VALUES: Final = frozenset({"always"})


def _quote(value: str) -> str:
    """Escape a string for a TOML basic string."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _parse_tool_policies(raw: Any) -> dict[str, ToolPolicy]:
    """Parse every ``[policy.tool.<name>]`` block, refusing anything malformed.

    A malformed policy is refused rather than ignored, the same discipline
    ``relax.py`` applies to ``[policy.relax.<ID>]``: a mistyped `approval`
    value or a non-numeric `timeout_seconds` failing loudly at load time beats
    the guard it was meant to produce quietly never appearing.
    """
    if not isinstance(raw, dict):
        return {}

    policies: dict[str, ToolPolicy] = {}
    for name, block in raw.items():
        if not isinstance(block, dict):
            message = f"[policy.tool.{name}] must be a table"
            raise ConfigError(message)

        approval = block.get("approval")
        if approval is not None and (
            not isinstance(approval, str) or approval not in _VALID_APPROVAL_VALUES
        ):
            valid = ", ".join(sorted(_VALID_APPROVAL_VALUES))
            message = f"[policy.tool.{name}] approval must be one of {valid}, found {approval!r}"
            raise ConfigError(message)

        timeout = block.get("timeout_seconds")
        if timeout is not None and (
            isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0
        ):
            message = (
                f"[policy.tool.{name}] timeout_seconds must be a positive number, found {timeout!r}"
            )
            raise ConfigError(message)

        raw_egress = block.get("egress_allow")
        egress_allow: tuple[str, ...] | None = None
        if raw_egress is not None:
            if not isinstance(raw_egress, list) or not all(
                isinstance(item, str) for item in raw_egress
            ):
                message = f"[policy.tool.{name}] egress_allow must be a list of strings"
                raise ConfigError(message)
            egress_allow = tuple(raw_egress)

        policies[str(name)] = ToolPolicy(
            approval=approval,
            timeout_seconds=float(timeout) if timeout is not None else None,
            egress_allow=egress_allow,
        )
    return policies


@dataclass(frozen=True)
class ToolPolicy:
    """Fine-grained rules for one tool, declared under ``[policy.tool.<name>]``.

    §7 of the standards-compliance-policy spec: each field feeds two
    consumers. The audit reads it as declared intent, the same role
    ``justifications`` and ``declared_scopes`` already play for ``B2`` and
    ``B4`` (an ``egress_allow`` narrower than what the tool's descriptor
    declares it needs is a finding under ``B4``, not a silent override).
    Lowering reads it as behaviour to emit: ``approval = "always"`` forces
    ``GuardKind.REQUIRE_APPROVAL`` even when nothing declared the tool
    destructive; ``timeout_seconds`` forces ``GuardKind.BOUND_RUNTIME``;
    declaring ``egress_allow`` forces ``GuardKind.RESTRICT_EGRESS``.
    """

    approval: str | None = None
    """``"always"`` forces approval regardless of any destructive annotation.

    No other value is defined today; an unrecognised one is rejected when the
    manifest is parsed rather than silently ignored.
    """

    timeout_seconds: float | None = None
    """Forces ``GuardKind.BOUND_RUNTIME``. Must be a positive number."""

    egress_allow: tuple[str, ...] | None = None
    """Forces ``GuardKind.RESTRICT_EGRESS``. ``None`` means the policy says
    nothing about egress for this tool; an explicit (possibly empty) tuple
    means egress is restricted to exactly these hosts."""


@dataclass(frozen=True)
class Manifest:
    """What the project says about its own stack and policy."""

    project_name: str
    provider_id: str
    framework_id: str
    model: str
    approval_required_for_destructive: bool = True
    justifications: dict[str, str] = field(default_factory=dict)
    declared_scopes: dict[str, tuple[str, ...]] = field(default_factory=dict)
    tool_policies: dict[str, ToolPolicy] = field(default_factory=dict)
    """Per-tool policy declared under ``[policy.tool.<name>]`` (P46, spec §7)."""

    base_url: str = ""
    """Endpoint override, or ``""`` to mean "use the provider's default".

    Recorded so a generated `agent_config.py` can read the same override
    every other toolseal command sees, rather than a value baked into one
    framework's source at scaffold time and frozen there.
    """

    tools: tuple[str, ...] = ()
    """Names of the tools this project's entrypoints bind, in one place.

    A project with more than one framework entrypoint (LangGraph and CrewAI in
    the same directory, say) would otherwise need this list kept in sync by
    hand in each `tools.py`. Read once here, both frameworks' generated tool
    modules filter their own tool objects down to these names instead.
    """

    def justification_for(self, tool_name: str) -> str | None:
        """Why *tool_name* is allowed its capability, if anyone said."""
        reason = self.justifications.get(tool_name, "").strip()
        return reason or None

    def policy_for(self, tool_name: str) -> ToolPolicy | None:
        """The per-tool policy declared for *tool_name*, if any."""
        return self.tool_policies.get(tool_name)

    def to_toml(self) -> str:
        approval = str(self.approval_required_for_destructive).lower()
        lines = [
            "# Written by toolseal. `toolseal audit` reads this file.",
            "",
            "[project]",
            f"name = {_quote(self.project_name)}",
            "",
            "[stack]",
            f"provider = {_quote(self.provider_id)}",
            f"framework = {_quote(self.framework_id)}",
            f"model = {_quote(self.model)}",
            # D3: an overridden endpoint is where traffic and credentials get
            # redirected, so it is recorded rather than left implicit.
            f"base_url = {_quote(self.base_url)}",
            "",
            "[policy]",
            "# F2: destructive tools require confirmation before they run.",
            f"approval_required_for_destructive = {approval}",
            "",
            "[justifications]",
            "# B2: a shell or code-execution tool needs a reason recorded here,",
            "# otherwise the audit reports it as unjustified.",
        ]
        lines += [
            f"{name} = {_quote(reason)}" for name, reason in sorted(self.justifications.items())
        ]

        lines += ["", "[scopes]", "# B4: what each MCP server was added to do."]
        lines += [
            f"{name} = [{', '.join(_quote(item) for item in scope)}]"
            for name, scope in sorted(self.declared_scopes.items())
        ]

        for name, tool_policy in sorted(self.tool_policies.items()):
            lines += ["", f"[policy.tool.{name}]"]
            if tool_policy.approval is not None:
                lines.append(f"approval = {_quote(tool_policy.approval)}")
            if tool_policy.timeout_seconds is not None:
                lines.append(f"timeout_seconds = {tool_policy.timeout_seconds!r}")
            if tool_policy.egress_allow is not None:
                hosts = ", ".join(_quote(host) for host in tool_policy.egress_allow)
                lines.append(f"egress_allow = [{hosts}]")

        lines += [
            "",
            "[tools]",
            "# B1: the explicit tool list every framework entrypoint in this",
            "# project binds from. `agent_config.py` reads it so LangGraph and",
            "# CrewAI entrypoints in the same project never disagree about it.",
            f"enabled = [{', '.join(_quote(item) for item in self.tools)}]",
        ]
        return "\n".join(lines) + "\n"

    @classmethod
    def from_toml(cls, text: str) -> Manifest:
        """Parse a manifest, naming precisely what is wrong when it is malformed."""
        try:
            data: dict[str, Any] = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            message = f"{MANIFEST_NAME} is not valid TOML: {exc}"
            raise ConfigError(message) from None

        project = data.get("project") or {}
        stack = data.get("stack") or {}
        policy = data.get("policy") or {}

        missing = [
            key
            for key, section in (("name", project), ("provider", stack), ("framework", stack))
            if not isinstance(section, dict) or not section.get(key)
        ]
        if missing:
            message = f"{MANIFEST_NAME} is missing required keys: {', '.join(missing)}"
            raise ConfigError(message)

        raw_scopes = data.get("scopes") or {}
        scopes = {
            name: tuple(str(item) for item in value)
            for name, value in raw_scopes.items()
            if isinstance(value, list)
        }

        raw_tools = data.get("tools") or {}
        enabled_tools = raw_tools.get("enabled") if isinstance(raw_tools, dict) else None
        tools = (
            tuple(str(item) for item in enabled_tools) if isinstance(enabled_tools, list) else ()
        )

        return cls(
            project_name=str(project["name"]),
            provider_id=str(stack["provider"]),
            framework_id=str(stack["framework"]),
            model=str(stack.get("model", "")),
            approval_required_for_destructive=bool(
                policy.get("approval_required_for_destructive", True)
            ),
            justifications={str(k): str(v) for k, v in (data.get("justifications") or {}).items()},
            declared_scopes=scopes,
            tool_policies=_parse_tool_policies(policy.get("tool")),
            base_url=str(stack.get("base_url", "")),
            tools=tools,
        )

    @classmethod
    def load(cls, root: Path) -> Manifest | None:
        """Read the manifest from *root*, or ``None`` when there is none.

        Absence is a normal state: most audited projects were never scaffolded.
        """
        path = root / MANIFEST_NAME
        if not path.is_file():
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            message = f"cannot read {MANIFEST_NAME}: {exc.strerror}"
            raise ConfigError(message) from None
        return cls.from_toml(text)
