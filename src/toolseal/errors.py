"""Error hierarchy and the process exit-code contract.

Every failure path raises a subclass of :class:`ToolsealError`. Library code
never calls :func:`sys.exit` and never swallows an exception it cannot handle;
converting an exception into an exit code happens once, at the CLI boundary.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Process exit codes.

    This is a stable public contract. CI pipelines and the evaluation harness
    branch on these values, so they must not be renumbered.
    """

    OK = 0
    """Completed with nothing to report."""

    FINDINGS = 1
    """Completed successfully, but reported findings. Not an error."""

    USAGE = 2
    """The command was invoked incorrectly. Matches Click's convention."""

    INTERNAL = 3
    """An unexpected failure. Always a bug worth reporting."""


class ToolsealError(Exception):
    """Base class for every error raised by toolseal."""

    exit_code: ExitCode = ExitCode.INTERNAL


class UsageError(ToolsealError):
    """The command was invoked with arguments that cannot be acted on."""

    exit_code = ExitCode.USAGE


class ConfigError(ToolsealError):
    """A project or tool configuration file is missing, malformed or inconsistent."""


class ResolutionError(ToolsealError):
    """A package or MCP server name could not be resolved, or failed verification."""


class RegistryError(ToolsealError):
    """The registry index could not be fetched, parsed or validated."""


class PolicyViolationError(ToolsealError):
    """A configuration violates a policy that cannot be automatically repaired."""
