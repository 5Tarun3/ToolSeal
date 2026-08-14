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

import logging
from pathlib import Path
from typing import Any

import pytest

from toolseal.core.model import Dependency, DependencySet, MCPServerBinding, ProjectModel, Transport
from toolseal.core.policy import all_checks
from toolseal.core.policy.family_c import mcp_package_name
from toolseal.core.policy.model import Verdict
from toolseal.core.registry.resolve import Channel, Resolution, ResolutionResult
from toolseal.errors import ResolutionError

MIN_KNOWN_NAMES = 20


def model_with(*names: str) -> ProjectModel:
    return ProjectModel(
        root=Path(),
        dependencies=DependencySet(
            declared=tuple(Dependency(name=n, specifier="==1.0.0", pinned=True) for n in names)
        ),
    )


def model_with_servers(*servers: MCPServerBinding) -> ProjectModel:
    return ProjectModel(root=Path(), mcp_servers=tuple(servers))


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


# --- memoisation persists beyond one audit ----------------------------------


def test_resolution_is_memoised_across_audits_in_one_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # "the life of a process", not "the life of one evaluate() call": a batch
    # of audits sharing a process must not re-resolve a name they already
    # settled.
    calls: list[str] = []

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        calls.append(name)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    c3().evaluate(model_with("langchain"))
    c3().evaluate(model_with("langchain"))

    assert calls == ["langchain"]


# --- MCP servers: the package installed, not the config key ----------------


def test_mcp_package_name_is_extracted_from_a_dash_y_npx_invocation() -> None:
    server = MCPServerBinding(
        name="filesystem",
        transport=Transport.STDIO,
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
    )

    assert mcp_package_name(server) == "@modelcontextprotocol/server-filesystem"


def test_mcp_package_name_is_extracted_after_a_package_flag() -> None:
    server = MCPServerBinding(
        name="fs",
        transport=Transport.STDIO,
        command="npx",
        args=("--package", "@modelcontextprotocol/server-filesystem", "server-filesystem"),
    )

    assert mcp_package_name(server) == "@modelcontextprotocol/server-filesystem"


def test_mcp_package_name_is_none_with_no_recognisable_flag() -> None:
    server = MCPServerBinding(
        name="custom",
        transport=Transport.STDIO,
        command="./run-my-server.sh",
        args=("--port", "8080"),
    )

    assert mcp_package_name(server) is None


def test_a_scoped_npx_package_is_resolved_from_args(monkeypatch: pytest.MonkeyPatch) -> None:
    # The verified live case: name is a local alias ("filesystem"), the real
    # package sits in args. Only the args-derived name may be looked up - if
    # the check queried `server.name` instead, this fake would raise KeyError.
    outcomes = {
        "@modelcontextprotocol/server-filesystem": ResolutionResult(
            "@modelcontextprotocol/server-filesystem", Resolution.EXISTS
        )
    }

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        return outcomes[name]

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    server = MCPServerBinding(
        name="filesystem",
        transport=Transport.STDIO,
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
    )

    result = c3().evaluate(model_with_servers(server))

    assert result.verdict is Verdict.PASS


def test_a_config_key_that_is_not_the_real_package_is_never_queried(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `toolseal add mcp` writes the config key as name.split("/")[-1] -
    # "server-filesystem" for the real package
    # "@modelcontextprotocol/server-filesystem". Resolving the key would 404
    # and produce a false CRITICAL against toolseal's own scaffold.
    calls: list[str] = []

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        calls.append(name)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    server = MCPServerBinding(
        name="server-filesystem",
        transport=Transport.STDIO,
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
    )

    c3().evaluate(model_with_servers(server))

    assert calls == ["@modelcontextprotocol/server-filesystem"]


def test_a_server_whose_args_yield_no_package_contributes_no_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        calls.append(name)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    server = MCPServerBinding(
        name="custom",
        transport=Transport.STDIO,
        command="./run-my-server.sh",
        args=("--port", "8080"),
    )

    result = c3().evaluate(model_with_servers(server))

    assert calls == []
    assert result.verdict is Verdict.PASS
    assert result.findings == ()


# --- channel selection: PyPI for dependencies, npm for MCP packages ---------


def test_a_dependency_is_resolved_against_pypi_only(monkeypatch: pytest.MonkeyPatch) -> None:
    # A hallucinated Python name that happens to collide with an npm package
    # must not be marked verified. Pinning this proves the express/PyPI-404
    # vs npm-200 collision from the review can no longer pass.
    seen: list[tuple[Channel, ...]] = []

    def fake(name: str, *, channels: tuple[Channel, ...], **kwargs: Any) -> ResolutionResult:
        seen.append(channels)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    c3().evaluate(model_with("express"))

    assert seen == [(Channel.PYPI,)]


def test_an_mcp_server_package_is_resolved_against_npm_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[tuple[Channel, ...]] = []

    def fake(name: str, *, channels: tuple[Channel, ...], **kwargs: Any) -> ResolutionResult:
        seen.append(channels)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    server = MCPServerBinding(
        name="filesystem",
        transport=Transport.STDIO,
        command="npx",
        args=("-y", "@modelcontextprotocol/server-filesystem"),
    )

    c3().evaluate(model_with_servers(server))

    assert seen == [(Channel.NPM,)]


# --- version-pinned npx specs: strip before resolving -----------------------


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("@upstash/context7-mcp@latest", "@upstash/context7-mcp"),
        ("@upstash/context7-mcp@1.2.3", "@upstash/context7-mcp"),
        ("@playwright/mcp@latest", "@playwright/mcp"),
        ("pkg@1.2.3", "pkg"),
        ("pkg@latest", "pkg"),
        # unsuffixed forms must pass through unchanged.
        ("@upstash/context7-mcp", "@upstash/context7-mcp"),
        ("pkg", "pkg"),
    ],
)
def test_mcp_package_name_strips_a_version_suffix(token: str, expected: str) -> None:
    server = MCPServerBinding(
        name="ctx7", transport=Transport.STDIO, command="npx", args=("-y", token)
    )

    assert mcp_package_name(server) == expected


def test_a_version_pinned_npx_spec_no_longer_produces_a_false_critical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Reproduces the review's exact failure shape: "@upstash/context7-mcp@latest"
    # is what that project's own README tells users to run. Resolving the spec
    # with the version tail still attached 404s against npm and would flip
    # report.blocking - the same false-blocking-CRITICAL bug class the
    # config-key fix above closed, re-entering through a different input.
    outcomes = {
        "@upstash/context7-mcp": ResolutionResult("@upstash/context7-mcp", Resolution.EXISTS)
    }

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        # KeyError if the version tail were still attached - proves the spec
        # actually reaching the resolver is the stripped form.
        return outcomes[name]

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    server = MCPServerBinding(
        name="context7",
        transport=Transport.STDIO,
        command="npx",
        args=("-y", "@upstash/context7-mcp@latest"),
    )

    result = c3().evaluate(model_with_servers(server))

    assert result.verdict is Verdict.PASS
    assert result.findings == ()


# --- unextractable packages: visible by default, remote servers exempt -----


def test_an_unextractable_local_server_logs_at_warning_not_info(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # `configure_logging` pins the root logger to WARNING unless --verbose, so
    # an INFO-level log is invisible on a plain `toolseal audit` - that is a
    # silent skip with a log line nobody sees. Must be WARNING to actually
    # satisfy "not a silent skip".
    monkeypatch.setattr(
        "toolseal.core.policy.family_c.resolve",
        lambda name, **kwargs: ResolutionResult(name, Resolution.EXISTS),
    )
    server = MCPServerBinding(
        name="custom",
        transport=Transport.STDIO,
        command="./run-my-server.sh",
        args=("--port", "8080"),
    )

    with caplog.at_level(logging.WARNING, logger="toolseal.core.policy.family_c"):
        result = c3().evaluate(model_with_servers(server))

    assert result.verdict is Verdict.PASS
    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.WARNING
    assert "custom" in caplog.text


def test_a_remote_server_is_skipped_rather_than_reported_as_unextractable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # A remote/SSE server has args=() and a url by construction - it has no
    # package to install, so it must not be logged as an extraction failure.
    calls: list[str] = []

    def fake(name: str, **kwargs: Any) -> ResolutionResult:
        calls.append(name)
        return ResolutionResult(name, Resolution.EXISTS)

    monkeypatch.setattr("toolseal.core.policy.family_c.resolve", fake)
    server = MCPServerBinding(
        name="remote-tool",
        transport=Transport.STREAMABLE_HTTP,
        url="https://example.invalid/mcp",
    )

    with caplog.at_level(logging.WARNING, logger="toolseal.core.policy.family_c"):
        result = c3().evaluate(model_with_servers(server))

    assert calls == []
    assert result.verdict is Verdict.PASS
    assert result.findings == ()
    assert caplog.records == []
