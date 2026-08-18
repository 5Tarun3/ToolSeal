"""`toolseal policy` - the half of this feature an operator actually touches.

The control mapping exists so that a failing check can explain itself. A
developer who hits B3 should learn what the rule is, which obligations it
serves and what to run, without opening a standards document. These tests
assert that output, because an explanation nobody can read is not one.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolseal.cli import app, policy_command
from toolseal.core.manifest import MANIFEST_NAME, Manifest
from toolseal.core.policy import coverage as coverage_module
from toolseal.core.policy.controls import load_catalogues
from toolseal.core.policy.relax import parse_relaxations
from toolseal.errors import ExitCode

runner = CliRunner()


def _init(tmp_path: Path, *, profile: str | None = None) -> Path:
    """Scaffold a project through the real `init` command, for CLI-level tests
    that need a project `policy show`/`apply`/`check`/`relax` can act on."""
    root = tmp_path / "demo"
    args = ["init", "demo", "--directory", str(root)]
    if profile is not None:
        args += ["--profile", profile]
    result = runner.invoke(app, args)
    assert result.exit_code == ExitCode.OK, result.output
    return root


def _catalogue_lines(stdout: str) -> dict[str, str]:
    """Map each catalogue id in `policy list` output to its full line.

    The legend below the table also starts with `*`, so it is excluded by
    skipping lines that do not open with an identifier.
    """
    lines: dict[str, str] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("*"):
            continue
        lines[stripped.split()[0]] = line
    return lines


def test_list_names_every_shipped_catalogue() -> None:
    result = runner.invoke(app, ["policy", "list"])

    assert result.exit_code == 0
    for standard in (
        "owasp-llm-top10",
        "nist-ai-rmf",
        "owasp-agentic-threats",
        "owasp-agentic-top10",
        "iso-42001",
    ):
        assert standard in result.stdout


def test_list_shows_coverage_of_each_standard() -> None:
    result = runner.invoke(app, ["policy", "list"])

    assert "%" in result.stdout


def test_list_is_headed_and_aligned() -> None:
    result = runner.invoke(app, ["policy", "list"])
    lines = result.stdout.splitlines()

    header = lines[0]
    assert header.split()[:3] == ["standard", "coverage", "checkable"]

    # A column boundary is a literal two-space separator between fixed-width
    # blocks. If a heading lost the width comparison against its data (or won
    # it unnecessarily), that separator would land in a different place on a
    # data row than it does on the header.
    checkable_column = header.index("checkable")
    trailer = lines[1:]
    data_lines = trailer[: trailer.index("")] if "" in trailer else trailer
    assert data_lines
    for line in data_lines:
        assert line[checkable_column - 2 : checkable_column] == "  "


def test_list_marks_the_curated_subsets() -> None:
    # iso-42001 (4 of ~36 controls) and nist-ai-rmf (7 of ~70) are shortlists
    # drawn up before any check mapping existed. Their rows must carry a
    # visible marker so a reader never mistakes "100% of our selection" for
    # "100% of the standard".
    result = runner.invoke(app, ["policy", "list"])
    lines = _catalogue_lines(result.stdout)

    for partial in ("iso-42001", "nist-ai-rmf"):
        assert "*" in lines[partial]


def test_list_does_not_mark_the_fully_enumerated_catalogues() -> None:
    result = runner.invoke(app, ["policy", "list"])
    lines = _catalogue_lines(result.stdout)

    for complete in ("owasp-llm-top10", "owasp-agentic-threats", "owasp-agentic-top10"):
        assert "*" not in lines[complete]


def test_list_legend_names_the_limitation_when_a_catalogue_is_partial() -> None:
    result = runner.invoke(app, ["policy", "list"])

    assert "curated subset" in result.stdout
    assert "measures our selection" in result.stdout


def test_list_omits_the_legend_when_nothing_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Filter to only the fully-enumerated catalogues rather than deleting a
    # data file, so this does not depend on which catalogues happen to ship.
    complete_only = {
        key: catalogue
        for key, catalogue in load_catalogues().items()
        if catalogue.complete_enumeration
    }
    assert complete_only, "expected at least one fully-enumerated catalogue to filter to"

    monkeypatch.setattr(policy_command, "load_catalogues", lambda: complete_only)
    monkeypatch.setattr(coverage_module, "load_catalogues", lambda: complete_only)

    result = runner.invoke(app, ["policy", "list"])

    assert result.exit_code == 0
    assert "*" not in result.stdout
    assert "curated subset" not in result.stdout


def test_explain_a_check_states_the_rule_and_the_fix() -> None:
    result = runner.invoke(app, ["policy", "explain", "B3"])

    assert result.exit_code == 0
    assert "B3" in result.stdout
    assert "Filesystem" in result.stdout
    assert "workspace" in result.stdout.lower()  # the remediation


def test_explain_a_check_names_its_obligations() -> None:
    result = runner.invoke(app, ["policy", "explain", "B3"])

    assert "LLM06" in result.stdout
    assert "Excessive Agency" in result.stdout


def test_explain_is_case_insensitive() -> None:
    assert runner.invoke(app, ["policy", "explain", "b3"]).exit_code == 0


def test_explain_a_control_lists_the_checks_that_serve_it() -> None:
    result = runner.invoke(app, ["policy", "explain", "owasp-llm-top10:LLM02"])

    assert result.exit_code == 0
    assert "A1" in result.stdout


def test_explain_an_unknown_subject_fails_usefully() -> None:
    result = runner.invoke(app, ["policy", "explain", "Z99"])

    assert result.exit_code != 0
    assert "Z99" in result.output


def test_explain_a_control_nobody_checks_says_so() -> None:
    # LLM01 is not a configuration property. Saying "no checks" is the honest
    # answer; an empty list with no explanation would read as a bug.
    result = runner.invoke(app, ["policy", "explain", "owasp-llm-top10:LLM01"])

    assert result.exit_code == 0
    assert "not assessable" in result.stdout.lower()


def test_explain_a_malformed_control_subject_is_a_usage_error() -> None:
    # A typo in the standard name ("bogus:LLM01") is the caller's mistake, not
    # an internal failure - it must exit USAGE (2), matching every other bad
    # argument, not INTERNAL (3).
    from toolseal.errors import ExitCode

    result = runner.invoke(app, ["policy", "explain", "bogus:LLM01"])

    assert result.exit_code == ExitCode.USAGE
    assert "bogus" in result.output


def test_explain_a_broken_shipped_catalogue_is_still_internal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A malformed *shipped* catalogue (a packaging fault) must not be
    # relabelled as the user's mistake just because loading it also raises
    # ConfigError - only the reference lookup itself, on an already-loaded
    # catalogue set, is a usage error. This is what distinguishes it from
    # test_explain_a_malformed_control_subject_is_a_usage_error above.
    from toolseal.errors import ConfigError, ExitCode

    def broken() -> dict[str, object]:
        message = "catalogue is not valid TOML"
        raise ConfigError(message)

    monkeypatch.setattr(policy_command, "load_catalogues", broken)

    result = runner.invoke(app, ["policy", "explain", "owasp-llm-top10:LLM01"])

    assert result.exit_code == ExitCode.INTERNAL


# --- show: attributes each rule to its source (P47, spec §10) -----------------


def test_show_lists_every_check_at_its_baseline_source(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "show", "--directory", str(root)])

    assert result.exit_code == 0
    assert "none declared" in result.stdout
    assert "B2" in result.stdout
    assert "baseline" in result.stdout


def test_show_names_the_profile_that_raised_a_severity(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(root), "--yes"])

    result = runner.invoke(app, ["policy", "show", "--directory", str(root)])

    assert result.exit_code == 0
    assert "hipaa" in result.stdout
    # D2 is raised to critical by hipaa (tests/test_regimes.py pins this).
    lines = {line.split()[0]: line for line in result.stdout.splitlines() if line.strip()}
    assert "profile:hipaa" in lines["D2"]


def test_show_marks_a_relaxed_check(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "needs shell",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    result = runner.invoke(app, ["policy", "show", "--directory", str(root)])

    assert result.exit_code == 0
    assert "relaxed" in result.stdout.lower()
    assert "B2  expires 2026-12-31" in result.stdout


def test_show_tool_reports_the_declared_per_tool_policy(tmp_path: Path) -> None:
    root = _init(tmp_path)
    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    text += '\n[policy.tool.query_postgres]\napproval = "always"\ntimeout_seconds = 30\n'
    (root / MANIFEST_NAME).write_text(text, encoding="utf-8")

    result = runner.invoke(app, ["policy", "show", "query_postgres", "--directory", str(root)])

    assert result.exit_code == 0
    assert "query_postgres" in result.stdout
    assert "always" in result.stdout
    assert "30" in result.stdout


def test_show_tool_with_no_policy_says_so(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "show", "nonexistent_tool", "--directory", str(root)])

    assert result.exit_code == 0
    assert "no [policy.tool.nonexistent_tool]" in result.stdout


def test_show_tool_reports_a_relaxation_scoped_to_it(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "ci needs shell",
            "--expires",
            "2026-12-31",
            "--tools",
            "ci_shell",
            "--directory",
            str(root),
        ],
    )

    covered = runner.invoke(app, ["policy", "show", "ci_shell", "--directory", str(root)])
    uncovered = runner.invoke(app, ["policy", "show", "other_tool", "--directory", str(root)])

    assert "covering ci_shell" in covered.stdout
    assert "no relaxation covers other_tool" in uncovered.stdout


# --- apply: prints a diff, does not write until confirmed ---------------------


def test_apply_prints_the_severity_and_scope_diff(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(root)], input="n\n")

    assert result.exit_code == 0
    assert "severity changes" in result.stdout
    assert "D2" in result.stdout
    assert "high -> critical" in result.stdout
    assert "scope this regime does not reach" in result.stdout
    assert "administrative safeguards" in result.stdout


def test_apply_does_not_write_until_confirmed(tmp_path: Path) -> None:
    root = _init(tmp_path)
    before = (root / MANIFEST_NAME).read_text(encoding="utf-8")

    result = runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(root)], input="n\n")

    assert result.exit_code == 0
    assert "Not applied" in result.stdout
    assert (root / MANIFEST_NAME).read_text(encoding="utf-8") == before
    assert Manifest.load(root) is not None
    assert Manifest.load(root).profiles == ()  # type: ignore[union-attr]


def test_apply_writes_on_confirmation(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(root)], input="y\n")

    assert result.exit_code == 0
    assert "Applied hipaa" in result.stdout
    manifest = Manifest.load(root)
    assert manifest is not None
    assert manifest.profiles == ("hipaa",)


def test_apply_yes_flag_skips_the_prompt(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(root), "--yes"])

    assert result.exit_code == 0
    manifest = Manifest.load(root)
    assert manifest is not None
    assert manifest.profiles == ("hipaa",)


def test_apply_an_unknown_regime_is_a_usage_error(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "apply", "bogus-regime", "--directory", str(root)])

    assert result.exit_code == ExitCode.USAGE
    assert "bogus-regime" in result.output


def test_apply_without_a_manifest_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(tmp_path)])

    assert result.exit_code == ExitCode.USAGE
    assert "toolseal init" in result.output


def test_apply_already_applied_is_a_noop(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")

    result = runner.invoke(app, ["policy", "apply", "hipaa", "--directory", str(root)])

    assert result.exit_code == 0
    assert "already applied" in result.stdout


# --- check: coverage of the checkable, never a verdict (spec §5) --------------


def test_check_contains_not_assessed_and_the_mandated_sentence(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")

    result = runner.invoke(app, ["policy", "check", "--profile", "hipaa", "--directory", str(root)])

    assert result.exit_code == 0
    assert "not_assessed" in result.stdout
    assert "administrative safeguards" in result.stdout
    assert "This is evidence toward an assessment. It is not one." in result.stdout


def test_check_never_prints_an_overall_pass_fail_verdict(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")

    result = runner.invoke(app, ["policy", "check", "--profile", "hipaa", "--directory", str(root)])

    assert result.exit_code == 0
    # No line claims an overall regime verdict ("hipaa: PASS", "HIPAA: PASS",
    # "overall: pass", etc). Per-check "pass"/"fail" counts in the coverage
    # table are fine - that is evidence, not a verdict for the regime.
    forbidden = ("PASS", "FAIL", "hipaa: pass", "hipaa: fail")
    for word in forbidden:
        assert word not in result.stdout


def test_check_with_no_declared_profile_still_ends_with_the_disclaimer(
    tmp_path: Path,
) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "check", "--directory", str(root)])

    assert result.exit_code == 0
    assert "This is evidence toward an assessment. It is not one." in result.stdout
    assert "none declared" in result.stdout


def test_check_falls_back_to_the_manifest_declared_profile(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")

    result = runner.invoke(app, ["policy", "check", "--directory", str(root)])

    assert result.exit_code == 0
    assert "profile: hipaa" in result.stdout


def test_check_reports_an_expired_relaxation_by_name(tmp_path: Path) -> None:
    root = _init(tmp_path)
    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    text += '\n[policy.relax.B2]\nreason = "old"\nexpires = "2000-01-01"\n'
    (root / MANIFEST_NAME).write_text(text, encoding="utf-8")

    result = runner.invoke(app, ["policy", "check", "--directory", str(root)])

    assert result.exit_code == 0
    assert "expired" in result.stdout.lower()


# --- relax: writes correct TOML, never hand-editing (spec §6) -----------------


def test_relax_refuses_a_missing_reason(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        ["policy", "relax", "B2", "--expires", "2026-12-31", "--directory", str(root)],
    )

    assert result.exit_code != 0
    assert "reason" in result.output.lower()


def test_relax_refuses_a_missing_expiry(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        ["policy", "relax", "B2", "--reason", "needs shell", "--directory", str(root)],
    )

    assert result.exit_code != 0
    assert "expires" in result.output.lower()


def test_relax_refuses_an_unknown_check_id(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "Z99",
            "--reason",
            "whatever",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == ExitCode.USAGE
    assert "Z99" in result.output


def test_relax_refuses_a_malformed_expiry(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "needs shell",
            "--expires",
            "not-a-date",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == ExitCode.USAGE
    assert "expires" in result.output.lower()


def test_relax_writes_a_block_that_relax_py_parses_back(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "CI runner needs shell; container-isolated",
            "--expires",
            "2026-12-31",
            "--tools",
            "ci_shell",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == 0

    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    (relaxation,) = parse_relaxations(text)
    assert relaxation.check_id == "B2"
    assert relaxation.reason == "CI runner needs shell; container-isolated"
    assert relaxation.expires.isoformat() == "2026-12-31"
    assert relaxation.tools == ("ci_shell",)


def test_relax_omitting_tools_is_project_wide(tmp_path: Path) -> None:
    root = _init(tmp_path)

    runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "project-wide reason",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    (relaxation,) = parse_relaxations(text)
    assert relaxation.tools == ()


def test_relax_refuses_a_duplicate_declaration_for_the_same_check(tmp_path: Path) -> None:
    root = _init(tmp_path)
    args = [
        "policy",
        "relax",
        "B2",
        "--reason",
        "first",
        "--expires",
        "2026-12-31",
        "--directory",
        str(root),
    ]
    runner.invoke(app, args)

    second = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "second",
            "--expires",
            "2027-01-01",
            "--directory",
            str(root),
        ],
    )

    assert second.exit_code == ExitCode.USAGE
    assert "already has a relaxation" in second.output


def test_relax_without_a_manifest_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "x",
            "--expires",
            "2026-12-31",
            "--directory",
            str(tmp_path),
        ],
    )

    assert result.exit_code == ExitCode.USAGE
    assert "toolseal init" in result.output


def test_relax_is_case_insensitive_on_the_check_id(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "b2",
            "--reason",
            "lowercase id",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == 0
    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    (relaxation,) = parse_relaxations(text)
    assert relaxation.check_id == "B2"


# --- audit: picks up a manifest-declared profile with no flag (spec §10) ------


def test_audit_honours_a_manifest_declared_profile_with_no_flag(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")

    result = runner.invoke(app, ["audit", str(root)])

    assert result.exit_code == 0
    assert "profile: hipaa" in result.stdout


def test_audit_json_reports_the_active_profile(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")

    result = runner.invoke(app, ["audit", str(root), "--json"])
    payload = json.loads(result.stdout)

    assert payload["profiles"] == ["hipaa"]


def test_audit_without_a_declared_profile_says_nothing_about_one(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["audit", str(root)])

    assert result.exit_code == 0
    assert "profile:" not in result.stdout


# --- init --profile: scaffolds under a regime from the start (spec §10) -------


def test_init_profile_declares_it_in_the_manifest(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    result = runner.invoke(app, ["init", "demo", "--directory", str(root), "--profile", "hipaa"])

    assert result.exit_code == 0
    manifest = Manifest.load(root)
    assert manifest is not None
    assert manifest.profiles == ("hipaa",)


def test_init_with_an_unknown_profile_is_a_usage_error_before_writing(tmp_path: Path) -> None:
    root = tmp_path / "demo"
    result = runner.invoke(
        app, ["init", "demo", "--directory", str(root), "--profile", "bogus-regime"]
    )

    assert result.exit_code == ExitCode.USAGE
    assert "bogus-regime" in result.output
    assert not root.exists()


def test_init_without_profile_declares_no_profiles(tmp_path: Path) -> None:
    root = _init(tmp_path)

    manifest = Manifest.load(root)
    assert manifest is not None
    assert manifest.profiles == ()


# --- enforce / verify: the policy lock (spec §8) -------------------------------


def test_enforce_seals_and_reports_the_hash(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    assert result.exit_code == ExitCode.OK, result.output
    assert (root / ".toolseal" / "policy.lock").is_file()
    assert "hash:" in result.stdout


def test_enforce_output_includes_a_copy_pasteable_ci_step(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    assert "toolseal policy verify" in result.stdout
    assert "run:" in result.stdout


def test_enforce_output_never_claims_tamper_proof(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    lowered = result.stdout.lower()
    assert "tamper-proof" not in lowered
    assert "tamperproof" not in lowered
    assert "immutable" not in lowered
    assert "detectable and attributable" in lowered


def test_enforce_twice_without_release_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    result = runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    assert result.exit_code == ExitCode.USAGE
    assert "--release" in result.output


def test_enforce_without_a_manifest_is_a_usage_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["policy", "enforce", "--directory", str(tmp_path)])

    assert result.exit_code == ExitCode.USAGE
    assert "toolseal init" in result.output


def test_enforce_release_unseals(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    result = runner.invoke(app, ["policy", "enforce", "--release", "--directory", str(root)])

    assert result.exit_code == ExitCode.OK, result.output
    assert not (root / ".toolseal" / "policy.lock").exists()


def test_enforce_release_without_a_lock_is_a_usage_error(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "enforce", "--release", "--directory", str(root)])

    assert result.exit_code == ExitCode.USAGE
    assert "nothing to release" in result.output


def test_verify_with_no_lock_exits_clean(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(app, ["policy", "verify", "--directory", str(root)])

    assert result.exit_code == ExitCode.OK
    assert "nothing sealed" in result.stdout.lower()


def test_verify_after_enforce_on_an_unchanged_project_reports_no_drift(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    first = runner.invoke(app, ["policy", "verify", "--directory", str(root)])
    second = runner.invoke(app, ["policy", "verify", "--directory", str(root)])

    assert first.exit_code == ExitCode.OK, first.output
    assert second.exit_code == ExitCode.OK, second.output
    assert "no drift" in first.stdout.lower()
    assert "no drift" in second.stdout.lower()


def test_verify_detects_a_hand_edited_lock_file_and_names_the_check(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    # Enact the documented threat actor (spec §8): the read-only bit is not a
    # security boundary - "anyone who can run the agent can clear the
    # read-only bit" - so clear it, hand-edit the JSON, then reinstate it.
    # `S_IWRITE` alone (0o200) unlocks the file on Windows (chmod there only
    # toggles the read-only attribute; owner reads go through the ACL), but on
    # Linux it grants write without read, so the following `read_text` would
    # raise `PermissionError` before the tamper is even applied. Or'ing in
    # `S_IREAD` keeps it readable on both platforms.
    lock_path = root / ".toolseal" / "policy.lock"
    lock_path.chmod(stat.S_IREAD | stat.S_IWRITE)
    data = json.loads(lock_path.read_text(encoding="utf-8"))
    data["severities"]["B2"] = "low"
    lock_path.write_text(json.dumps(data), encoding="utf-8")
    lock_path.chmod(stat.S_IREAD)

    result = runner.invoke(app, ["policy", "verify", "--directory", str(root)])

    assert result.exit_code != ExitCode.OK
    assert "B2" in result.stdout
    assert "Drift detected" in result.stdout


def test_verify_detects_a_hand_edited_manifest_and_names_the_profile(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    edited = text.replace('profiles = ["hipaa"]', "profiles = []")
    (root / MANIFEST_NAME).write_text(edited, encoding="utf-8")

    result = runner.invoke(app, ["policy", "verify", "--directory", str(root)])

    assert result.exit_code != ExitCode.OK
    assert "profiles" in result.stdout.lower()


def test_relax_on_a_sealed_check_is_refused_and_names_the_lock(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "needs shell",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == ExitCode.USAGE
    assert "policy.lock" in result.output
    assert "enforce --release" in result.output


def test_relax_on_an_unsealed_check_still_works(tmp_path: Path) -> None:
    root = _init(tmp_path)

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "needs shell",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output


def test_relax_works_again_after_enforce_release(tmp_path: Path) -> None:
    root = _init(tmp_path)
    runner.invoke(app, ["policy", "enforce", "--directory", str(root)])
    runner.invoke(app, ["policy", "enforce", "--release", "--directory", str(root)])

    result = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "needs shell after release",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )

    assert result.exit_code == ExitCode.OK, result.output
