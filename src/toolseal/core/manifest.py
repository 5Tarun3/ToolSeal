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


def _quote(value: str) -> str:
    """Escape a string for a TOML basic string."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


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

    def justification_for(self, tool_name: str) -> str | None:
        """Why *tool_name* is allowed its capability, if anyone said."""
        reason = self.justifications.get(tool_name, "").strip()
        return reason or None

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
