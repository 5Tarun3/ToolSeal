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
import re
import urllib.error
import urllib.request
from collections.abc import Sequence
from typing import Any, Final

from toolseal.core.model import Dependency, ProjectModel
from toolseal.core.policy.model import Check, Finding, Severity, register

OSV_BATCH_URL: Final = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT_SECONDS: Final = 20.0
OSV_MAX_BATCH: Final = 100

# A specifier that pins to exactly one version.
PINNED: Final = re.compile(r"^\s*==\s*[^,\s]+\s*$")


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
    )
)
