"""Family A - credential exposure.

The detection problem here is asymmetric. A missed credential is a disclosure; a
false positive is an annoyance that gets the tool switched off. Both matter, so
the patterns below are anchored on *known credential shapes* rather than on
entropy alone. Entropy scoring finds more secrets and also flags every base64
blob, UUID and minified asset in the tree, and a check nobody trusts is a check
nobody runs.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Final

from toolseal.core.model import ProjectModel
from toolseal.core.policy.controls import ControlRef
from toolseal.core.policy.model import Check, Finding, Severity, register
from toolseal.core.policy.suppress import is_suppressed

# Shapes published by the providers themselves. Each is specific enough that a
# match is a credential rather than a coincidence.
CREDENTIAL_SHAPES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}")),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
)

# A credential-named variable assigned a non-empty, non-placeholder literal.
ASSIGNMENT: Final = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?)[A-Za-z0-9_]*)"
    r"\s*[:=]\s*"
    r"[\"']([^\"'\n]{8,})[\"']"
)

# Values that are obviously not credentials, so an example file does not light
# up the report and train people to ignore it.
_INERT: Final = re.compile(
    r"^\s*(|<.*>|\$\{.*\}|your[-_ ]?.*|xxx+|change[-_ ]?me|todo|example|placeholder|"
    r"\.\.\.|None|null|true|false|\d+)\s*$",
    re.IGNORECASE,
)

# An environment variable's name. Case-sensitive, and at least one underscore
# is required: that is what keeps all-caps credential formats such as an AWS
# access key id outside the exemption.
_ENV_VAR_NAME: Final = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")

# Files that exist to show the shape of a credential.
EXAMPLE_FILENAMES: Final = frozenset({".env.example", ".env.sample", ".env.template"})

# Extensions worth reading. Binary and vendored trees are skipped: the cost of
# scanning them is high and the yield is near zero.
SCANNED_SUFFIXES: Final = frozenset(
    {".py", ".toml", ".json", ".yaml", ".yml", ".env", ".ini", ".cfg", ".sh", ".ps1", ".md", ".txt"}
)
SKIPPED_DIRECTORIES: Final = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache", "dist"}
)

MAX_SCANNED_BYTES: Final = 2 * 1024 * 1024


def _is_env_file(name: str) -> bool:
    """Whether *name* is a dotenv file of any flavour."""
    return name == ".env" or name.startswith(".env.")


def is_env_var_name(value: str) -> bool:
    """Whether *value* is the *name* of an environment variable rather than a secret.

    ``A1``'s own remediation is that configuration should reference a credential
    **by name rather than by value**. A scanner that reports the name as a secret
    therefore penalises the exact pattern this check prescribes, and would make a
    toolseal-scaffolded project fail its own audit.

    Matched case-sensitively, and an underscore is required. Real credentials are
    mixed-case or hyphenated, and the underscore requirement is what keeps
    all-caps key formats - an AWS access key id such as ``AKIA...`` - outside
    this exemption.
    """
    return _ENV_VAR_NAME.match(value) is not None


def is_inert(value: str) -> bool:
    """Whether a matched value is a placeholder rather than a credential."""
    return _INERT.match(value) is not None or is_env_var_name(value)


def scannable_files(model: ProjectModel) -> Iterator[tuple[Path, str]]:
    """Yield readable text files worth scanning, with their contents."""
    for entry in model.files:
        if entry.ignored:
            continue
        path = Path(entry.path)
        if any(part in SKIPPED_DIRECTORIES for part in path.parts):
            continue
        # Matched by name as well as extension: `.env.example` has the suffix
        # ".example", so a suffix-only test skips exactly the files most likely
        # to carry a pasted credential.
        if path.suffix.lower() not in SCANNED_SUFFIXES and not _is_env_file(path.name):
            continue

        absolute = model.root / path
        try:
            if absolute.stat().st_size > MAX_SCANNED_BYTES:
                continue
            yield path, absolute.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # An unreadable file is not a finding; it is a file we cannot judge.
            continue


def _a1(model: ProjectModel) -> Sequence[Finding]:
    findings: list[Finding] = []

    for path, content in scannable_files(model):
        is_example = path.name in EXAMPLE_FILENAMES

        for number, line in enumerate(content.splitlines(), start=1):
            # A deliberate fixture says so on the line itself; see suppress.py.
            if is_suppressed(line, "A1"):
                continue

            for label, pattern in CREDENTIAL_SHAPES:
                if pattern.search(line):
                    findings.append(
                        Finding(
                            check_id="A1",
                            severity=Severity.CRITICAL,
                            title="Credential literal in project file",
                            detail=f"{label} found in {path}",
                            location=str(path),
                            line=number,
                            remediation=(
                                "Move the value into the OS keychain and revoke the exposed "
                                "credential; it must be treated as compromised."
                            ),
                        )
                    )

            # An example file is allowed to name variables; it is not allowed to
            # give them values.
            match = ASSIGNMENT.search(line)
            if match and not is_inert(match.group(2)):
                findings.append(
                    Finding(
                        check_id="A1",
                        severity=Severity.CRITICAL,
                        title="Credential-named variable assigned a literal value",
                        detail=(
                            f"{match.group(1)} is assigned a literal in {path}"
                            + (" (an example file must contain names only)" if is_example else "")
                        ),
                        location=str(path),
                        line=number,
                        remediation="Assign nothing in the file; store the value in the keychain.",
                    )
                )

    return findings


def _a2(model: ProjectModel) -> Sequence[Finding]:
    findings: list[Finding] = []

    gitignore = model.root / ".gitignore"
    rules = set()
    if gitignore.is_file():
        rules = {line.strip() for line in gitignore.read_text(encoding="utf-8").splitlines()}

    for entry in model.files:
        name = Path(entry.path).name
        if name in EXAMPLE_FILENAMES or not _is_env_file(name):
            continue

        if entry.tracked:
            findings.append(
                Finding(
                    check_id="A2",
                    severity=Severity.HIGH,
                    title="Credential file is tracked by version control",
                    detail=f"{entry.path} is committed, so its history is permanent",
                    location=str(entry.path),
                    remediation=(
                        "Remove it from the index with `git rm --cached`, rotate anything it "
                        "held, and add it to .gitignore."
                    ),
                )
            )
        elif ".env" not in rules:
            findings.append(
                Finding(
                    check_id="A2",
                    severity=Severity.HIGH,
                    title="Credential file is not ignored",
                    detail=f"{entry.path} exists but .gitignore has no rule covering it",
                    location=str(entry.path),
                    remediation="Add `.env` and `.env.*` to .gitignore.",
                )
            )

    return findings


def _a3(model: ProjectModel) -> Sequence[Finding]:
    names: dict[str, list[str]] = {}
    for provider in model.providers:
        if provider.credential is None:
            continue
        names.setdefault(provider.credential.name, []).append(provider.provider_id)

    return [
        Finding(
            check_id="A3",
            severity=Severity.MEDIUM,
            title="One credential shared across providers",
            detail=f"{name} is used by {', '.join(sorted(users))}",
            remediation="Give each provider its own keychain entry so a leak has one blast radius.",
        )
        for name, users in sorted(names.items())
        if len(set(users)) > 1
    ]


def _a4(model: ProjectModel) -> Sequence[Finding]:
    if model.runtime.redacts_credentials:
        return []
    return [
        Finding(
            check_id="A4",
            severity=Severity.HIGH,
            title="Logging has no credential redaction",
            detail=(
                "No redaction filter was found, so a debug log or traceback can carry a "
                "credential into a file or a support ticket"
            ),
            remediation="Install a redacting logging filter; `toolseal init` emits one.",
        )
    ]


def _a5(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="A5",
            severity=Severity.HIGH,
            title="Credential embedded in an MCP server's environment",
            detail=f"{server.name} declares {reference.name} with a literal value",
            location=str(reference.location) if reference.location else None,
            line=reference.line,
            remediation=(
                "Reference the credential by name and resolve it from the keychain when the "
                "server launches."
            ),
        )
        for server in model.mcp_servers
        for reference in server.child_environment
        if reference.is_exposed
    ]


A1 = register(
    Check(
        id="A1",
        family="A",
        title="Credential literal in tracked source or configuration",
        severity=Severity.CRITICAL,
        remediation="Store credentials in the OS keychain; keep only names in files.",
        run=_a1,
        controls=(
            ControlRef("owasp-llm-top10", "LLM02"),
            ControlRef("owasp-agentic-threats", "T3"),
            ControlRef("owasp-agentic-top10", "ASI03"),
        ),
    )
)

A2 = register(
    Check(
        id="A2",
        family="A",
        title="Secret-bearing file tracked, or missing ignore rule",
        severity=Severity.HIGH,
        remediation="Ignore .env and friends; untrack anything already committed.",
        run=_a2,
        controls=(
            ControlRef("owasp-llm-top10", "LLM02"),
            ControlRef("owasp-agentic-top10", "ASI03"),
        ),
    )
)

A3 = register(
    Check(
        id="A3",
        family="A",
        title="One credential shared across providers or environments",
        severity=Severity.MEDIUM,
        remediation="Separate credentials per provider and per environment.",
        run=_a3,
        applies=lambda model: len(model.providers) > 1,
        controls=(
            ControlRef("owasp-llm-top10", "LLM02"),
            ControlRef("owasp-agentic-threats", "T3"),
            ControlRef("owasp-agentic-top10", "ASI03"),
        ),
    )
)

A4 = register(
    Check(
        id="A4",
        family="A",
        title="Credential reachable in logs or error output",
        severity=Severity.HIGH,
        remediation="Add a redacting logging filter.",
        run=_a4,
        controls=(
            ControlRef("owasp-llm-top10", "LLM02"),
            ControlRef("owasp-agentic-top10", "ASI03"),
        ),
    )
)

A5 = register(
    Check(
        id="A5",
        family="A",
        title="Credential embedded in a child process's declared environment",
        severity=Severity.HIGH,
        remediation="Resolve the value at launch instead of writing it into config.",
        run=_a5,
        applies=lambda model: bool(model.mcp_servers),
        controls=(
            ControlRef("owasp-llm-top10", "LLM02"),
            ControlRef("owasp-agentic-threats", "T3"),
            ControlRef("owasp-agentic-top10", "ASI03"),
        ),
    )
)
