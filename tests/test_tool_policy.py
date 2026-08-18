"""Per-tool policy (§7 of the standards-compliance-policy spec, ReWOO step P46).

`[policy.tool.<name>]` in `toolseal.toml` feeds two consumers, and both are
pinned here:

* **the audit**, as declared intent - the same role `justifications` and
  `declared_scopes` already play for `B2` and `B4`. An `egress_allow`
  narrower than what the tool's descriptor declares it needs is a finding
  under `B4`, not a silent override (`family_b._b4_tool_egress`).
* **lowering**, as emitted behaviour - `Manifest.policy_for(name)` feeds
  `translate.lower.lower(..., tool_policy=...)`, which forces guard kinds on
  top of whatever translation loss already required. The guards themselves
  are executed, not merely asserted on their text, in
  `tests/test_executable_guards.py`; this file covers the manifest parsing
  and the audit-side finding, plus the *choice* of guard kinds lowering
  makes (without re-deriving what running them proves).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from toolseal.core.manifest import Manifest, ToolPolicy
from toolseal.core.model import ProjectModel, ToolBinding, ToolKind
from toolseal.core.policy.family_b import _b4
from toolseal.core.registry.utd import SecurityAnnotations, ToolSource, UnifiedToolDescriptor
from toolseal.core.translate.lattice import GuardKind
from toolseal.core.translate.lower import lower, ungeneratable_guard_kinds
from toolseal.errors import ConfigError

BASE = """
[project]
name = "demo"

[stack]
provider = "ollama"
framework = "langgraph"
"""


# --- Manifest parsing --------------------------------------------------------


def test_a_tool_policy_parses_every_field() -> None:
    text = (
        BASE
        + """
[policy.tool.query_postgres]
approval = "always"
timeout_seconds = 30
egress_allow = ["db.internal"]
"""
    )
    manifest = Manifest.from_toml(text)

    policy = manifest.policy_for("query_postgres")
    assert policy is not None
    assert policy.approval == "always"
    assert policy.timeout_seconds == 30.0
    assert policy.egress_allow == ("db.internal",)


def test_a_tool_with_no_policy_returns_none() -> None:
    manifest = Manifest.from_toml(BASE)

    assert manifest.policy_for("anything") is None


def test_a_tool_policy_may_declare_only_some_fields() -> None:
    text = BASE + "\n[policy.tool.reader]\ntimeout_seconds = 5\n"
    policy = Manifest.from_toml(text).policy_for("reader")

    assert policy is not None
    assert policy.approval is None
    assert policy.timeout_seconds == 5.0
    assert policy.egress_allow is None


def test_an_unrecognised_approval_value_is_refused() -> None:
    text = BASE + '\n[policy.tool.reader]\napproval = "sometimes"\n'

    with pytest.raises(ConfigError, match="approval"):
        Manifest.from_toml(text)


@pytest.mark.parametrize("bad", [0, -5, "thirty"])
def test_a_non_positive_or_non_numeric_timeout_is_refused(bad: object) -> None:
    text = BASE + f"\n[policy.tool.reader]\ntimeout_seconds = {bad!r}\n"

    with pytest.raises(ConfigError, match="timeout_seconds"):
        Manifest.from_toml(text)


def test_a_non_list_egress_allow_is_refused() -> None:
    text = BASE + '\n[policy.tool.reader]\negress_allow = "db.internal"\n'

    with pytest.raises(ConfigError, match="egress_allow"):
        Manifest.from_toml(text)


def test_round_trips_through_to_toml() -> None:
    manifest = Manifest(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        model="",
        tool_policies={
            "query_postgres": ToolPolicy(
                approval="always", timeout_seconds=30.0, egress_allow=("db.internal",)
            )
        },
    )

    reparsed = Manifest.from_toml(manifest.to_toml())

    assert reparsed.policy_for("query_postgres") == manifest.policy_for("query_postgres")


# --- the audit: declared intent, and the one finding --------------------------


def _manifest_file(tmp_path: Path, text: str) -> Path:
    root = tmp_path / "demo"
    root.mkdir()
    (root / "toolseal.toml").write_text(BASE + text, encoding="utf-8")
    return root


def test_egress_allow_narrower_than_the_descriptor_is_a_b4_finding(tmp_path: Path) -> None:
    root = _manifest_file(
        tmp_path,
        '\n[policy.tool.query_postgres]\negress_allow = ["db.internal"]\n',
    )
    model = ProjectModel(
        root=root,
        tools=(
            ToolBinding(
                name="query_postgres",
                kind=ToolKind.DATABASE,
                origin="mcp",
                egress_hosts=("db.internal", "telemetry.example.com"),
            ),
        ),
    )

    (finding,) = _b4(model)

    assert finding.check_id == "B4"
    assert finding.subject == "query_postgres"
    assert "telemetry.example.com" in finding.detail
    # db.internal *is* allowed, so only the host outside the allowlist is named.
    assert "db.internal" not in finding.detail


def test_egress_allow_covering_every_declared_host_is_not_a_finding(tmp_path: Path) -> None:
    root = _manifest_file(
        tmp_path,
        '\n[policy.tool.query_postgres]\negress_allow = ["db.internal", "telemetry.example.com"]\n',
    )
    model = ProjectModel(
        root=root,
        tools=(
            ToolBinding(
                name="query_postgres",
                kind=ToolKind.DATABASE,
                origin="mcp",
                egress_hosts=("db.internal", "telemetry.example.com"),
            ),
        ),
    )

    assert _b4(model) == []


def test_a_tool_with_no_egress_policy_is_not_a_finding(tmp_path: Path) -> None:
    root = _manifest_file(tmp_path, "")
    model = ProjectModel(
        root=root,
        tools=(
            ToolBinding(
                name="query_postgres",
                kind=ToolKind.DATABASE,
                origin="mcp",
                egress_hosts=("db.internal",),
            ),
        ),
    )

    assert _b4(model) == []


def test_the_finding_is_not_a_silent_override_of_the_narrower_policy(tmp_path: Path) -> None:
    # The policy still wins at guard-synthesis time (RESTRICT_EGRESS is built
    # from exactly `egress_allow`, proven in test_executable_guards.py) - the
    # point of this finding is that narrowing it is visible, not that it is
    # refused.
    root = _manifest_file(
        tmp_path,
        '\n[policy.tool.query_postgres]\negress_allow = ["db.internal"]\n',
    )
    model = ProjectModel(
        root=root,
        tools=(
            ToolBinding(
                name="query_postgres",
                kind=ToolKind.DATABASE,
                origin="mcp",
                egress_hosts=("evil.example.com",),
            ),
        ),
    )

    (finding,) = _b4(model)
    assert finding.remediation


# --- lowering: which guard kinds a policy forces -------------------------------


def _descriptor(**overrides: object) -> UnifiedToolDescriptor:
    defaults: dict[str, object] = {
        "id": "mcp/db@1#query",
        "name": "query_postgres",
        "description": "Run a read-only SQL query.",
        "source": ToolSource("mcp", "npm", "@example/db", "1.0.0"),
        "annotations": SecurityAnnotations(destructive=False, read_only=True),
    }
    return UnifiedToolDescriptor(**{**defaults, **overrides})  # type: ignore[arg-type]


def test_ungeneratable_guard_kinds_is_still_empty() -> None:
    # The two new kinds must ship with generator support or not at all.
    assert ungeneratable_guard_kinds() == frozenset()


def test_approval_always_forces_require_approval_on_a_non_destructive_tool() -> None:
    # Undeclared destructiveness would normally mean no REQUIRE_APPROVAL guard
    # at all on a lossless target - policy overrides that.
    result = lower(_descriptor(), "langchain", tool_policy=ToolPolicy(approval="always"))

    assert GuardKind.REQUIRE_APPROVAL in {guard.kind for guard in result.guards}
    assert "require_approval" in result.source


def test_timeout_seconds_forces_bound_runtime() -> None:
    result = lower(_descriptor(), "langchain", tool_policy=ToolPolicy(timeout_seconds=30.0))

    assert GuardKind.BOUND_RUNTIME in {guard.kind for guard in result.guards}
    assert "bound_runtime" in result.source
    assert "TIMEOUT_SECONDS = 30.0" in result.source


def test_egress_allow_forces_restrict_egress() -> None:
    result = lower(
        _descriptor(), "langchain", tool_policy=ToolPolicy(egress_allow=("db.internal",))
    )

    assert GuardKind.RESTRICT_EGRESS in {guard.kind for guard in result.guards}
    assert "restrict_egress" in result.source
    assert "EGRESS_ALLOW = ('db.internal',)" in result.source


def test_no_policy_forces_no_extra_guard() -> None:
    result = lower(_descriptor(), "langchain")

    assert result.guards == ()
    assert "TIMEOUT_SECONDS = None" in result.source
    assert "EGRESS_ALLOW = ()" in result.source


def test_a_policy_approval_does_not_duplicate_an_already_compensated_guard() -> None:
    # crewai already needs REQUIRE_APPROVAL to compensate destructiveHint;
    # `approval = "always"` on top of that must not decorate the binding
    # twice.
    destructive = _descriptor(annotations=SecurityAnnotations(destructive=True))

    result = lower(destructive, "crewai", tool_policy=ToolPolicy(approval="always"))

    assert result.source.count("@require_approval(") == 1
