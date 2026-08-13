"""Claude Code: a framework whose entire security posture is configuration.

The odd one out, and the most useful cell in the matrix for the argument this
project makes. A Claude Code project has **no application code at all** - no
`agent.py`, no tool bindings, no model construction. What it has is
`.claude/settings.json`, an MCP config and a `CLAUDE.md`. Every property the
taxonomy checks is therefore a configuration property by construction, which
makes this the purest instance of the thesis rather than an awkward fit for it.

It is also the first target that can express a security property **natively**
where the others cannot. LangGraph can carry `destructiveHint` but nothing acts
on it; CrewAI drops it entirely; Claude Code turns it into an `ask` permission
rule that fires before the tool runs. So this is the case where lowering emits
*no guard*, which is the control condition the lattice previously lacked - with
two targets, every non-trivial translation needed compensation and "lossless"
was never actually exercised against a real framework.

Because it configures a directory that already exists rather than creating one,
everything it writes goes through :mod:`toolseal.core.injection` and is
reversible with `toolseal revert`.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any, Final

from toolseal.core.adapters.base import Provider as ProviderProtocol
from toolseal.core.adapters.base import RenderedFile, ScaffoldSpec
from toolseal.core.translate.lattice import profile
from toolseal.templates import claudecode as tpl

SETTINGS_PATH: Final = ".claude/settings.json"
INSTRUCTIONS_PATH: Final = "CLAUDE.md"

# Claude Code needs no Python dependencies: it is a separate runtime, not a
# library the project imports. An empty requirement set is the honest answer
# rather than a placeholder.
FRAMEWORK_PACKAGES: Final[tuple[str, ...]] = ()

# Tool rules the scaffold writes. Deny beats allow, and both are explicit.
#
# B1: an allowlist rather than a wildcard, so the tool set is a decision.
# B2: no bare Bash rule - only named, narrow commands.
# B3: reads are permitted inside the project and denied outside it.
# F2: destructive operations land in `ask`, which is the native expression of
#     destructiveHint and the reason this target needs no compensating guard.
DEFAULT_ALLOW: Final[tuple[str, ...]] = (
    "Read(./**)",
    "Grep",
    "Glob",
    "Bash(git status)",
    "Bash(git diff:*)",
    "Bash(git log:*)",
)

DEFAULT_ASK: Final[tuple[str, ...]] = (
    "Edit",
    "Write",
    "Bash(git commit:*)",
    "Bash(git push:*)",
)

DEFAULT_DENY: Final[tuple[str, ...]] = (
    # A1/A2: the agent cannot read credential material even by accident.
    "Read(./.env)",
    "Read(./.env.*)",
    "Read(**/*.pem)",
    "Read(**/id_rsa*)",
    "Read(**/.aws/**)",
    "Read(**/.ssh/**)",
    # B3: reads stay inside the project.
    "Read(/**)",
    "Read(~/**)",
    # B2/E1: no arbitrary execution, however it is spelled.
    "Bash(curl:*)",
    "Bash(wget:*)",
    "Bash(rm -rf:*)",
)


def build_settings(spec: ScaffoldSpec) -> dict[str, Any]:
    """The settings document, assembled so each rule maps to a stated check."""
    return {
        "permissions": {
            "allow": list(DEFAULT_ALLOW),
            "ask": list(DEFAULT_ASK),
            "deny": list(DEFAULT_DENY),
            # E2: the agent's tools do not inherit the whole environment.
            "defaultMode": "acceptEdits" if spec.extras.get("accept_edits") else "default",
        },
        # F1: a record of what ran, which is the only way an incident can be
        # reviewed afterwards.
        "env": {"TOOLSEAL_MANAGED": "1"},
    }


class ClaudeCodeFramework:
    """Configures an existing directory for Claude Code, reversibly."""

    id: Final = "claude-code"
    display_name: Final = "Claude Code"

    #: Unlike every other framework, this one configures rather than creates.
    #: `init` would imply a new project; the CLI routes it through `add`.
    configures_in_place: Final = True

    def packages(self, provider: ProviderProtocol) -> tuple[str, ...]:
        """None. Claude Code is a runtime, not a library the project imports."""
        return FRAMEWORK_PACKAGES

    def expressible_properties(self) -> frozenset[str]:
        """Taken from the lattice. The widest set of any target so far.

        Permission rules are evaluated before a tool runs, which makes
        client-side validation and the consequence of `destructiveHint` both
        natively expressible - the only target where that is true.
        """
        return frozenset(str(prop) for prop in profile("claude-code").expressible)

    def render(self, spec: ScaffoldSpec, provider: ProviderProtocol) -> tuple[RenderedFile, ...]:
        """Produce the configuration files. Touches no filesystem."""
        settings = json.dumps(build_settings(spec), indent=2, sort_keys=True) + "\n"

        return (
            RenderedFile(PurePosixPath(SETTINGS_PATH), settings),
            RenderedFile(
                PurePosixPath(INSTRUCTIONS_PATH),
                tpl.INSTRUCTIONS.substitute(
                    project_name=spec.project_name,
                    provider_name=provider.display_name,
                ),
            ),
        )
