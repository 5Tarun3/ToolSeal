"""C3 at audit time: phantom and lookalike names in a project we did not build.

C3 was enforced at `add` time from the start and never evaluated by `audit`, so
every third-party project scanned was scored as though its dependency names had
been verified. This closes that gap.

The load-bearing test is the offline one. An unreachable registry must produce
UNKNOWN, never PASS: "we could not look" and "we looked and it was fine" are
different states, and a network blip that silently reported the second would
make the check worse than not having it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from toolseal.core.model import Dependency, DependencySet, ProjectModel
from toolseal.core.policy import all_checks
from toolseal.core.policy.model import Verdict
from toolseal.core.registry.resolve import Resolution, ResolutionResult
from toolseal.errors import ResolutionError

MIN_KNOWN_NAMES = 20


def model_with(*names: str) -> ProjectModel:
    return ProjectModel(
        root=Path(),
        dependencies=DependencySet(
            declared=tuple(Dependency(name=n, specifier="==1.0.0", pinned=True) for n in names)
        ),
    )


def c3() -> Any:
    return next(check for check in all_checks() if check.id == "C3")


@pytest.fixture
def resolves(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Install a fake resolver keyed by name."""

    def install(outcomes: dict[str, ResolutionResult | Exception]) -> None:
        def fake(name: str, **kwargs: Any) -> ResolutionResult:
            outcome = outcomes[name]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)

    return install


def test_c3_is_registered() -> None:
    assert c3().id == "C3"


def test_a_resolving_name_is_clean(resolves: Any) -> None:
    resolves({"langchain": ResolutionResult("langchain", Resolution.EXISTS)})

    assert c3().evaluate(model_with("langchain")).verdict is Verdict.PASS


def test_a_phantom_name_is_a_critical_finding(resolves: Any) -> None:
    resolves({"langchain-helper": ResolutionResult("langchain-helper", Resolution.PHANTOM)})

    result = c3().evaluate(model_with("langchain-helper"))

    assert result.verdict is Verdict.FAIL
    assert "langchain-helper" in result.findings[0].detail


def test_a_lookalike_names_what_it_resembles(resolves: Any) -> None:
    resolves(
        {"langchian": ResolutionResult("langchian", Resolution.LOOKALIKE, resembles="langchain")}
    )

    finding = c3().evaluate(model_with("langchian")).findings[0]

    assert "langchain" in finding.remediation


def test_an_unreachable_registry_is_not_a_pass(resolves: Any) -> None:
    # The whole point. The error must escape so the engine records UNKNOWN.
    resolves({"langchain": ResolutionError("no registry could be reached")})

    with pytest.raises(ResolutionError):
        c3().evaluate(model_with("langchain"))


def test_each_name_is_resolved_once(monkeypatch: pytest.MonkeyPatch) -> None:
    # A project can declare the same name twice. One audit must not mean two
    # requests to a registry that may rate-limit us.
    calls: list[str] = []

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        calls.append(name)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    c3().evaluate(model_with("langchain", "langchain", "crewai"))

    assert sorted(calls) == ["crewai", "langchain"]


def test_c3_does_not_apply_to_a_project_with_no_names() -> None:
    assert c3().evaluate(ProjectModel(root=Path())).verdict is Verdict.NOT_APPLICABLE


def test_known_packages_ship_and_are_non_empty() -> None:
    from toolseal.core.policy.family_c import known_package_names

    names = known_package_names()

    assert "langchain" in names
    assert len(names) >= MIN_KNOWN_NAMES
