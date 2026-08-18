"""P50 - the Phase 6 gate (design spec §13).

Three assertions, each written so it cannot pass vacuously:

1. Every check maps to a control, or is explicitly marked unmapped with a
   reason (`Check.unmapped_reason`). `tests/test_control_mapping.py` already
   asserts this against the real registry; this gate adds a companion that
   proves the predicate can actually fail, against a check built specifically
   to violate it - not a check that happens to already satisfy the rule.

2. A sealed policy refuses relaxation. P48 (`tests/test_policy_cli.py`)
   already has a unit test for this; the spec asks the gate to prove it "end
   to end rather than trusting the unit test". This runs the full sequence
   through the CLI - relax while unsealed (proving the mechanism is live),
   seal, relax again (proving the seal is what changed the outcome) - and
   then removes the one line that makes sealing matter and shows the exact
   same sealed project accepts the relax it just refused.

3. The coverage report is reproducible. "Running it twice" is taken
   literally: the CLI is invoked as two independent OS processes and their
   stdout compared byte for byte, which is a stronger claim than calling the
   same Python function twice in one process. A companion test targets the
   specific nondeterminism vector `load_catalogues()` is exposed to -
   `importlib.resources` directory iteration order is not guaranteed - and
   proves the printed report does not depend on it.

Follows the precedent of `tests/test_gate_vertical_slice.py`: one file, named
for the milestone, run unconditionally (no Ollama dependency here).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolseal.cli import app, policy_command
from toolseal.core.policy import coverage as coverage_module
from toolseal.core.policy import lock as policy_lock
from toolseal.core.policy.controls import ControlRef, load_catalogues
from toolseal.core.policy.model import Check, Severity, all_checks
from toolseal.errors import ExitCode

runner = CliRunner()


# --- assertion 1: every check is mapped, or says why not -----------------


def _is_compliant(check: Check) -> bool:
    """The gate's own predicate - the same rule `Check.unmapped_reason`'s
    docstring and spec §13 state, factored out so the companion test below
    exercises this exact rule rather than a paraphrase of it."""
    return bool(check.controls) or bool(check.unmapped_reason)


def test_gate_every_registered_check_is_mapped_or_marked_unmapped() -> None:
    offenders = [check.id for check in all_checks() if not _is_compliant(check)]
    assert offenders == []


def test_gate_the_mapped_or_unmapped_predicate_can_actually_fail() -> None:
    # Built directly, never registered - `register()` refuses duplicate ids
    # and nothing here should touch the shared registry other tests read.
    naked = Check(
        id="Z00-gate-fixture",
        family="Z",
        title="deliberately violates the P50 rule",
        severity=Severity.LOW,
        remediation="",
        run=lambda _model: (),
    )
    assert not _is_compliant(naked), "a check with neither a mapping nor a reason must fail"

    reasoned = Check(
        id="Z01-gate-fixture",
        family="Z",
        title="unmapped, with a reason",
        severity=Severity.LOW,
        remediation="",
        run=lambda _model: (),
        unmapped_reason="ahead of the standards",
    )
    assert _is_compliant(reasoned)

    mapped = Check(
        id="Z02-gate-fixture",
        family="Z",
        title="mapped",
        severity=Severity.LOW,
        remediation="",
        run=lambda _model: (),
        controls=(ControlRef("owasp-llm-top10", "LLM02"),),
    )
    assert _is_compliant(mapped)


# --- assertion 2: a sealed policy refuses relaxation, end to end ---------


def _init_via_cli(tmp_path: Path) -> Path:
    root = tmp_path / "gate-project"
    result = runner.invoke(app, ["init", "gate-project", "--directory", str(root)])
    assert result.exit_code == ExitCode.OK, result.output
    return root


def test_gate_relax_works_before_enforce_and_is_refused_after(tmp_path: Path) -> None:
    root = _init_via_cli(tmp_path)

    # Unsealed: the mechanism is live. Proven first so a later refusal cannot
    # be mistaken for `relax` simply being broken.
    before = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B4",
            "--reason",
            "before sealing",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )
    assert before.exit_code == ExitCode.OK, before.output

    sealed = runner.invoke(app, ["policy", "enforce", "--directory", str(root)])
    assert sealed.exit_code == ExitCode.OK, sealed.output
    assert policy_lock.is_sealed(root)

    # A different check, sealed, refused - naming the lock and the check.
    after = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "after sealing",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )
    assert after.exit_code == ExitCode.USAGE
    assert "B2" in after.output
    assert "policy.lock" in after.output
    assert "enforce --release" in after.output


def test_gate_the_refusal_is_actually_caused_by_the_seal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gate that cannot fail is not a gate: remove the one lookup `relax`
    uses to consult the lock, and the exact same sealed project that just
    refused a relaxation above must accept one - proving the refusal in the
    previous test is caused by the seal, not by some unrelated validation."""
    root = _init_via_cli(tmp_path)
    enforce_result = runner.invoke(app, ["policy", "enforce", "--directory", str(root)])
    assert enforce_result.exit_code == ExitCode.OK, enforce_result.output

    still_refused = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "control case",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )
    assert still_refused.exit_code == ExitCode.USAGE

    monkeypatch.setattr(policy_lock, "sealed_check", lambda *_a, **_kw: None)

    bypassed = runner.invoke(
        app,
        [
            "policy",
            "relax",
            "B2",
            "--reason",
            "bypass with the lock check disabled",
            "--expires",
            "2026-12-31",
            "--directory",
            str(root),
        ],
    )
    assert bypassed.exit_code == ExitCode.OK, bypassed.output


# --- assertion 3: the coverage report is reproducible ---------------------


def _invoke_cli_subprocess(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-c",
            "import sys\nfrom toolseal.cli import main\nsys.exit(main())\n",
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_gate_coverage_report_is_byte_identical_across_two_processes() -> None:
    # Two independent OS processes, not two calls in one - a real test of
    # cross-run reproducibility rather than of object identity within a
    # single Python process. If PYTHONHASHSEED-driven set ordering or
    # filesystem iteration order ever leaked into the printed report, this
    # is the test that would catch it, not one that reuses process state.
    first = _invoke_cli_subprocess("policy", "list")
    second = _invoke_cli_subprocess("policy", "list")

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout
    assert first.stdout  # not vacuously identical because both are empty


def test_gate_coverage_report_does_not_depend_on_catalogue_load_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`load_catalogues()` walks a directory listing via `importlib.resources`,
    whose OS-level order is not guaranteed to be stable. `policy list` sorts
    before printing (`policy_command.list_standards`); this proves that sort
    is actually what makes the report order-independent, by feeding it the
    catalogues in two different orders and requiring identical output."""
    catalogues = load_catalogues()
    forward = dict(catalogues)
    backward = dict(reversed(list(catalogues.items())))
    assert list(forward) != list(backward), "the two orderings must actually differ"

    monkeypatch.setattr(policy_command, "load_catalogues", lambda: forward)
    monkeypatch.setattr(coverage_module, "load_catalogues", lambda: forward)
    first = runner.invoke(app, ["policy", "list"])

    monkeypatch.setattr(policy_command, "load_catalogues", lambda: backward)
    monkeypatch.setattr(coverage_module, "load_catalogues", lambda: backward)
    second = runner.invoke(app, ["policy", "list"])

    assert first.exit_code == 0
    assert second.exit_code == 0
    assert first.stdout == second.stdout


def test_gate_coverage_for_every_catalogue_is_stable_across_repeated_calls() -> None:
    # The underlying data, not just the rendered CLI text: every catalogue's
    # CoverageReport must compare equal to itself on a second computation.
    from toolseal.core.policy.coverage import coverage_for

    for standard in load_catalogues():
        first = coverage_for(standard)
        second = coverage_for(standard)
        assert first == second
