"""Family C - supply-chain integrity (the parts the vertical slice needs).

C1 and C2 are deliberately thin wrappers over work the ecosystem already does
well. The contribution is not better advisory data; it is that the question gets
asked at configuration time, where the dependency is chosen, rather than weeks
later in a scheduled scan.

C2 talks to OSV over the network. When it cannot, it reports ``unknown`` rather
than ``pass``: "we did not look" and "we looked and it was fine" must never
render the same way.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
import urllib.error
import urllib.request
from collections.abc import Sequence
from functools import cache
from importlib import resources
from typing import Any, Final

from toolseal.core.model import Dependency, MCPServerBinding, ProjectModel
from toolseal.core.policy.controls import ControlRef
from toolseal.core.policy.model import Check, Finding, Severity, register
from toolseal.core.registry.resolve import Channel, Resolution, ResolutionResult, resolve
from toolseal.errors import ConfigError

log = logging.getLogger(__name__)

OSV_BATCH_URL: Final = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SECONDS: Final = 20.0
OSV_MAX_BATCH: Final = 100

# A specifier that pins to exactly one version.
PINNED: Final = re.compile(r"^\s*==\s*[^,\s]+\s*$")

KNOWN_PACKAGES_PACKAGE: Final = "toolseal.data"
KNOWN_PACKAGES_FILE: Final = "known_packages.toml"


class AdvisoryLookupError(RuntimeError):
    """OSV could not be reached or did not answer usefully."""


def is_pinned(specifier: str) -> bool:
    """Whether *specifier* admits exactly one version."""
    return bool(specifier) and PINNED.match(specifier) is not None


def query_osv(dependencies: Sequence[Dependency], ecosystem: str = "PyPI") -> dict[str, list[str]]:
    """Return ``{dependency name: [advisory ids]}`` for anything affected.

    Only dependencies with a resolved version are queried; OSV cannot answer for
    a range, and guessing which version a range would install would produce
    findings about software the project may never run.
    """
    resolvable = [d for d in dependencies if d.resolved_version]
    if not resolvable:
        return {}

    queries = [
        {"package": {"name": d.name, "ecosystem": ecosystem}, "version": d.resolved_version}
        for d in resolvable[:OSV_MAX_BATCH]
    ]
    # urlopen honours file: and custom schemes. The URL is a constant today,
    # but asserting the scheme keeps that true if it ever becomes configurable.
    if not OSV_BATCH_URL.startswith("https://"):
        message = "advisory endpoint must be https"
        raise AdvisoryLookupError(message)

    payload = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=OSV_TIMEOUT_SECONDS) as response:  # noqa: S310 - scheme asserted above
            body: dict[str, Any] = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        message = f"OSV was unreachable ({type(exc).__name__})"
        raise AdvisoryLookupError(message) from None

    results = body.get("results") or []
    affected: dict[str, list[str]] = {}
    for dependency, result in zip(resolvable, results, strict=False):
        ids = [v.get("id", "") for v in (result or {}).get("vulns") or []]
        if ids:
            affected[dependency.name] = sorted(filter(None, ids))
    return affected


def _c1(model: ProjectModel) -> Sequence[Finding]:
    findings: list[Finding] = []

    declared = model.dependencies.declared
    fully_pinned = bool(declared) and all(d.pinned for d in declared)

    # A fully `==`-pinned dependency set reproduces the direct dependency graph
    # without a separate lockfile, which is what the lockfile requirement is for.
    # It is weaker than hash pinning, because transitive versions still float -
    # so the recommendation stays, but it is not a finding on its own.
    if model.dependencies.lockfile is None and not fully_pinned:
        findings.append(
            Finding(
                check_id="C1",
                severity=Severity.HIGH,
                title="No lockfile",
                detail=(
                    "Without a lockfile the resolved dependency set differs between machines "
                    "and over time, so an audit result does not describe what actually installs"
                ),
                remediation="Generate and commit a lockfile.",
            )
        )

    unpinned = [d for d in model.dependencies.declared if not d.pinned]
    findings.extend(
        Finding(
            check_id="C1",
            severity=Severity.HIGH,
            title="Unpinned dependency",
            detail=f"{dependency.name} is declared as {dependency.specifier or 'any version'}",
            remediation=f"Pin {dependency.name} to an exact version.",
        )
        for dependency in unpinned
    )
    return findings


def _c2(model: ProjectModel) -> Sequence[Finding]:
    affected = query_osv(model.dependencies.declared)
    by_name = {d.name: d for d in model.dependencies.declared}

    return [
        Finding(
            check_id="C2",
            severity=Severity.HIGH,
            title="Dependency carries a known advisory",
            detail=(
                f"{name} {by_name[name].resolved_version} is affected by {', '.join(advisories)}"
            ),
            remediation=f"Upgrade {name} to a version outside the affected range.",
        )
        for name, advisories in sorted(affected.items())
        if name in by_name
    ]


C1 = register(
    Check(
        id="C1",
        family="C",
        title="Dependencies unpinned, or no lockfile",
        severity=Severity.HIGH,
        remediation="Pin dependencies and commit a lockfile.",
        run=_c1,
        controls=(
            ControlRef("owasp-llm-top10", "LLM03"),
            ControlRef("nist-ai-rmf", "GOVERN-6.1"),
            ControlRef("owasp-agentic-top10", "ASI04"),
        ),
    )
)

C2 = register(
    Check(
        id="C2",
        family="C",
        title="Dependency carrying a known advisory",
        severity=Severity.HIGH,
        remediation="Upgrade past the advisory, or record an accepted risk.",
        run=_c2,
        applies=lambda model: any(d.resolved_version for d in model.dependencies.declared),
        controls=(
            ControlRef("owasp-llm-top10", "LLM03"),
            ControlRef("nist-ai-rmf", "MAP-4.1"),
            ControlRef("owasp-agentic-top10", "ASI04"),
        ),
    )
)


def known_package_names() -> frozenset[str]:
    """Established package names, for C3's lookalike detection.

    Read through `importlib.resources` from the `toolseal.data` package, the
    same mechanism `controls.load_catalogues()` uses, so this works from an
    installed wheel as well as from a checkout.
    """
    resource = resources.files(KNOWN_PACKAGES_PACKAGE) / KNOWN_PACKAGES_FILE
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:
        message = f"known-package list {KNOWN_PACKAGES_FILE!r} is missing: {exc}"
        raise ConfigError(message) from None

    try:
        data: dict[str, Any] = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        message = f"known-package list is not valid TOML: {exc}"
        raise ConfigError(message) from None

    names = data.get("names")
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        message = "known-package list field 'names' must be a list of strings"
        raise ConfigError(message)

    return frozenset(names)


# The argument that carries the package name in an npx-style invocation
# (`npx -y <package>`, or `npx --package <package> <bin>`). This is the one
# reliable general form; anything else (a bare command, a shell wrapper, a
# non-npx launcher) has no convention this can extract without guessing.
_PACKAGE_NAME_FLAGS: Final = frozenset({"-y", "--package"})


def _without_version(token: str) -> str:
    """Strip a trailing ``@version`` from an npm package spec.

    A scoped name already carries a leading ``@`` (``@scope/pkg``), so only a
    *second* ``@`` - one that appears after position 0 - is a version
    separator; an unscoped name's only ``@``, if any, is the version
    separator. `rfind`/`find` both return ``-1`` when the character is
    absent, and ``-1 > 0`` is false, so an unsuffixed name of either shape
    passes through unchanged.
    """
    at_index = token.rfind("@") if token.startswith("@") else token.find("@")
    return token[:at_index] if at_index > 0 else token


def mcp_package_name(server: MCPServerBinding) -> str | None:
    """The registry package *server* actually installs, if it can be told.

    ``MCPServerBinding.name`` is the local alias under which a server is keyed
    in ``mcpServers`` - the JSON object key a project or `toolseal add mcp`
    chose for convenience - not necessarily the package that gets installed.
    The package name lives in ``args``, after ``-y`` or ``--package`` for an
    npx-style launch, and a version pin (``@upstash/context7-mcp@latest``,
    ``pkg@1.2.3``) - the shape those projects' own READMEs ship - is stripped
    before resolving, since neither the npm registry lookup nor PyPI's takes
    one.

    Returns ``None``, rather than a guess, when no such flag is present. A
    wrong guess here would resolve the wrong name and report it as either
    verified or squattable when it is neither.
    """
    args = server.args
    for index, token in enumerate(args):
        if token in _PACKAGE_NAME_FLAGS and index + 1 < len(args):
            return _without_version(args[index + 1])
    return None


@cache
def _resolve_cached(
    name: str, channels: tuple[Channel, ...], known: frozenset[str]
) -> ResolutionResult:
    """`resolve`, memoised for the life of the process.

    A name declared twice in one project, or shared between the dependency and
    MCP server lists, must cost one registry lookup, not two - and a batch of
    audits run in one process (the evaluation harness, for instance) should not
    re-resolve a name it has already settled. Exceptions are not cached:
    `ResolutionError` must keep propagating on every call, not just the first.
    """
    return resolve(name, channels=channels, known=known)


def _findings_for(
    names: Sequence[str], *, channels: tuple[Channel, ...], known: frozenset[str]
) -> list[Finding]:
    findings: list[Finding] = []
    for name in names:
        # ResolutionError propagates on purpose. An unreachable registry must
        # reach the engine and be recorded as UNKNOWN; swallowing it here would
        # report "we could not look" as "we looked and it was fine".
        result = _resolve_cached(name, channels, known)
        if result.resolution is Resolution.EXISTS:
            continue

        findings.append(
            Finding(
                check_id="C3",
                severity=Severity.CRITICAL,
                title=(
                    "Package name resembles an established one"
                    if result.resolution is Resolution.LOOKALIKE
                    else "Package name resolves nowhere"
                ),
                detail=f"{name}: {result.detail}",
                location=name,
                remediation=(
                    f"Confirm {name!r} is the package intended"
                    + (f", not {result.resembles!r}" if result.resembles else "")
                    + "; unverified names must not be installed."
                ),
            )
        )
    return findings


def _c3(model: ProjectModel) -> Sequence[Finding]:
    known = known_package_names()

    # Dependencies extracted from requirements.txt / pyproject.toml are always
    # Python packages. Checking npm first (resolve()'s default) would let a
    # hallucinated name that happens to exist in npm's much larger namespace
    # come back "verified" - the exact slopsquatting case this check exists
    # for. So dependencies are resolved against PyPI only.
    dependency_names = sorted({dependency.name for dependency in model.dependencies.declared})

    # MCP servers are resolved by the package their args actually install, not
    # by the config key. A server whose package cannot be extracted from its
    # args contributes no finding - but that is a decision, not a silent
    # drop, so it is logged at a level visible on a plain `toolseal audit`
    # (WARNING is the default root level; INFO is not).
    server_packages: set[str] = set()
    for server in model.mcp_servers:
        if server.is_remote:
            # A remote/SSE server has no launch args by construction - it has
            # a URL, not a package to install. Reporting "no extractable
            # package name" against it would misname what is actually a
            # not-applicable case, not an extraction failure.
            continue

        package = mcp_package_name(server)
        if package is None:
            log.warning(
                "C3: %s's launch args carry no extractable package name "
                "(no -y/--package token in %r); not resolved",
                server.name,
                server.args,
            )
            continue
        server_packages.add(package)

    return [
        *_findings_for(dependency_names, channels=(Channel.PYPI,), known=known),
        *_findings_for(sorted(server_packages), channels=(Channel.NPM,), known=known),
    ]


C3 = register(
    Check(
        id="C3",
        family="C",
        title="Unverified package or MCP server name",
        severity=Severity.CRITICAL,
        remediation="Verify the name against its registry before installing it.",
        run=_c3,
        applies=lambda model: bool(model.dependencies.declared) or bool(model.mcp_servers),
        controls=(
            ControlRef("owasp-llm-top10", "LLM03"),
            ControlRef("owasp-agentic-threats", "T9"),
            ControlRef("nist-ai-rmf", "GOVERN-6.1"),
            ControlRef("owasp-agentic-top10", "ASI04"),
        ),
    )
)


def _c4(model: ProjectModel) -> Sequence[Finding]:
    return [
        Finding(
            check_id="C4",
            severity=Severity.HIGH,
            title="Install source cannot be verified",
            detail=(
                f"{dependency.name} comes from {dependency.source.kind} "
                f"{dependency.source.reference!r}, which is neither pinned nor integrity-checked"
            ),
            remediation="Install from an indexed registry with a pinned version and a checksum.",
        )
        for dependency in model.dependencies.declared
        if dependency.source is not None and not dependency.source.is_verified
    ]


def _c5(model: ProjectModel) -> Sequence[Finding]:
    if model.dependencies.sbom is not None:
        return []
    return [
        Finding(
            check_id="C5",
            severity=Severity.LOW,
            title="No SBOM",
            detail=(
                "Without a component inventory, a newly disclosed advisory cannot be matched "
                "against this project without re-resolving it"
            ),
            remediation="Generate a CycloneDX or SPDX document, refreshed on dependency change.",
        )
    ]


C4 = register(
    Check(
        id="C4",
        family="C",
        title="Install from an unverified source",
        severity=Severity.HIGH,
        remediation="Install from an indexed, integrity-checked source.",
        run=_c4,
        applies=lambda model: any(d.source is not None for d in model.dependencies.declared),
        controls=(
            ControlRef("owasp-llm-top10", "LLM03"),
            ControlRef("nist-ai-rmf", "GOVERN-6.1"),
            ControlRef("owasp-agentic-top10", "ASI04"),
        ),
    )
)

C5 = register(
    Check(
        id="C5",
        family="C",
        title="No SBOM",
        severity=Severity.LOW,
        remediation="Generate an SBOM at scaffold time.",
        run=_c5,
        applies=lambda model: bool(model.dependencies.declared),
        controls=(
            ControlRef("owasp-llm-top10", "LLM03"),
            ControlRef("iso-42001", "A.10.3"),
            ControlRef("owasp-agentic-top10", "ASI04"),
        ),
    )
)
