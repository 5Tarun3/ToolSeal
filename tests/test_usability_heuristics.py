"""Nielsen's usability heuristics, enforced against the whole command tree.

This is a sweep, not a spot check. Every test below walks the live Typer app
and asserts a property of *each* command, so a heuristic cannot be satisfied by
the commands that existed when it was written and quietly broken by the next
one. That is the difference between a usability review, which is a snapshot,
and a usability *contract*, which is what this file is.

Only the mechanisable heuristics are here. "Match between system and the real
world" and "aesthetic and minimalist design" are judgements about wording and
density that a test cannot make; they are audited by hand in
`docs/superpowers/specs/2026-09-13-cli-usability-heuristics.md` and the
findings recorded there. What a test *can* pin down is structural: that a
short flag means one thing everywhere, that a user's mistake never reports
itself as a bug in this tool, that every command explains itself.

Each test names the heuristic it enforces, because a failure here is a
usability regression and the message should say which one.
"""

from __future__ import annotations

import inspect
import pkgutil
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import typer
from typer.testing import CliRunner

import toolseal
from toolseal.cli import app
from toolseal.errors import ExitCode, ToolsealError

runner = CliRunner()

Command = Any


def _walk(
    command: Command, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Command]]:
    """Every leaf command in the app, with the argv path that reaches it."""
    subcommands = getattr(command, "commands", None)
    if subcommands:
        for name, sub in subcommands.items():
            yield from _walk(sub, (*path, name))
    else:
        yield path, command


def _groups(
    command: Command, path: tuple[str, ...] = ()
) -> Iterator[tuple[tuple[str, ...], Command]]:
    """Every command *group*, including the root app."""
    if getattr(command, "commands", None):
        yield path, command
        for name, sub in command.commands.items():
            yield from _groups(sub, (*path, name))


def _leaves() -> list[tuple[tuple[str, ...], Command]]:
    return sorted(_walk(typer.main.get_command(app)), key=lambda item: item[0])


def _leaf_ids() -> list[str]:
    return [" ".join(path) for path, _ in _leaves()]


def test_the_sweep_actually_reaches_every_command() -> None:
    """Guard against a vacuous sweep.

    Every parametrised test below is driven by `_leaves()`. If that returned an
    empty list, or silently stopped descending into `policy` and `registry`,
    each of those tests would pass by iterating over nothing - which is the
    failure mode a conformance suite has to rule out before its own results
    mean anything.
    """
    found = _leaf_ids()
    assert len(found) >= 15, f"only {len(found)} commands discovered: {found}"
    for expected in ("init", "audit", "revert", "doctor", "policy check", "registry search"):
        assert expected in found, f"{expected!r} missing from the sweep"


# --- Heuristic 4: consistency and standards ---------------------------------


def test_one_short_flag_never_means_two_different_things() -> None:
    """Heuristic 4. A letter learned once must not change meaning elsewhere.

    `-p` is `--provider` in `init` and `add framework`. If some other command
    spends `-p` on `--page` or `--profile`, a user who has learned the first
    meaning types it and gets the second - silently, because both are valid
    options that simply do different things. This caught exactly that:
    `registry search` had taken `-p` for `--page`.
    """
    meanings: dict[str, set[str]] = defaultdict(set)
    where: dict[str, set[str]] = defaultdict(set)

    for path, command in _leaves():
        for param in command.params:
            options = getattr(param, "opts", [])
            short = [opt for opt in options if len(opt) == 2 and opt.startswith("-")]
            long = [opt for opt in options if len(opt) > 2]
            for alias in short:
                meanings[alias].add(long[0] if long else alias)
                where[alias].add(" ".join(path) or "toolseal")

    collisions = {
        alias: (sorted(names), sorted(where[alias]))
        for alias, names in meanings.items()
        if len(names) > 1
    }
    assert not collisions, f"short flags with more than one meaning: {collisions}"


@pytest.mark.parametrize(("path", "command"), _leaves(), ids=_leaf_ids())
def test_every_command_explains_itself(path: tuple[str, ...], command: Command) -> None:
    """Heuristics 4 and 10. No command is left to be guessed at from its name."""
    help_text = (command.help or "").strip()
    assert help_text, f"`toolseal {' '.join(path)}` has no help text"
    assert help_text[0].isupper(), f"`toolseal {' '.join(path)}` help does not start with a capital"


@pytest.mark.parametrize(("path", "command"), _leaves(), ids=_leaf_ids())
def test_every_option_explains_itself(path: tuple[str, ...], command: Command) -> None:
    """Heuristic 10. An option a user can type is an option they can read about."""
    for param in command.params:
        if not getattr(param, "opts", None) or param.name == "help":
            continue
        described = (getattr(param, "help", "") or "").strip()
        assert described, f"`toolseal {' '.join(path)}` option {param.opts} has no help"


def test_every_command_group_points_somewhere_useful() -> None:
    """Heuristic 10. A group listing subcommands says where to go next.

    `add` is exempt: its two panels are self-describing and it has no
    catalogue to point at, unlike `policy` (28 checks) and the root app.
    """
    exempt = {("add",)}
    for path, group in _groups(typer.main.get_command(app)):
        if path in exempt:
            continue
        epilog = (getattr(group, "epilog", "") or "").strip()
        assert epilog, f"group `toolseal {' '.join(path)}` has no epilog pointing onward"


# --- Heuristic 9: recognise, diagnose and recover from errors ---------------


def _error_classes() -> list[type[ToolsealError]]:
    return [
        value
        for value in vars(toolseal.errors).values()
        if inspect.isclass(value) and issubclass(value, ToolsealError)
    ]


def test_no_user_facing_error_class_reports_itself_as_an_internal_bug() -> None:
    """Heuristic 9. A mistake the user can fix must not ask for a bug report.

    `ExitCode.INTERNAL` is documented in `errors.py` as "always a bug worth
    reporting", and the error line prints that word to the user. Any error
    raised because of something the *user* typed or wrote therefore has to
    carry `USAGE` instead - otherwise the tool blames itself for a typo, and
    invites a bug report nobody should file.

    `ConfigError` and its remaining siblings stay on `INTERNAL` deliberately:
    a malformed catalogue, profile or known-package list is a packaging fault
    in this tool, and for those the advice to report it is correct.
    """
    user_caused = {"UsageError", "ProjectConfigError"}
    for cls in _error_classes():
        if cls.__name__ in user_caused:
            assert cls.exit_code == ExitCode.USAGE, (
                f"{cls.__name__} describes a user mistake but exits "
                f"{int(cls.exit_code)} ({cls.exit_code.name.lower()})"
            )


USER_INPUT_MODULES = (
    "toolseal.core.manifest",
    "toolseal.core.policy.relax",
)
"""Modules that exist to parse a file the *user* wrote (`toolseal.toml`).

Every failure they raise is a defect in someone's own configuration, so none
of them may raise the base `ConfigError` - that would exit `INTERNAL` and tell
the user their typo is a bug in this tool.
"""


@pytest.mark.parametrize("module_name", USER_INPUT_MODULES)
def test_modules_parsing_user_config_never_raise_an_internal_error(module_name: str) -> None:
    """Heuristic 9, enforced at the source rather than at one call site.

    Checking behaviour through the CLI would only cover the paths a test
    happens to invoke. Reading the source covers every raise in the module,
    including ones no test reaches yet.
    """
    source = Path(inspect.getfile(__import__(module_name, fromlist=["_"]))).read_text(
        encoding="utf-8"
    )
    offenders = [
        line.strip()
        for line in source.splitlines()
        if "raise ConfigError(" in line and "ProjectConfigError" not in line
    ]
    assert not offenders, (
        f"{module_name} parses user-authored config but raises ConfigError "
        f"(exit 3, 'internal'); use ProjectConfigError: {offenders}"
    )


def test_the_user_config_scan_would_catch_a_regression() -> None:
    """The scan above is a string search; prove it is not vacuous."""
    synthetic = "        raise ConfigError(message)\n"
    offenders = [
        line.strip()
        for line in synthetic.splitlines()
        if "raise ConfigError(" in line and "ProjectConfigError" not in line
    ]
    assert offenders, "the offender scan failed to flag a synthetic ConfigError raise"


def test_a_mistyped_path_is_a_usage_error_not_an_internal_one(tmp_path: Path) -> None:
    """Heuristic 9, end to end: the single most likely user mistake."""
    result = runner.invoke(app, ["audit", str(tmp_path / "does-not-exist")])
    assert result.exit_code == ExitCode.USAGE, result.output


def test_a_malformed_user_manifest_is_a_usage_error(tmp_path: Path) -> None:
    """Heuristic 9, end to end: a typo in the user's own `toolseal.toml`."""
    (tmp_path / "toolseal.toml").write_text("not = valid [[[\n", encoding="utf-8")
    result = runner.invoke(app, ["audit", str(tmp_path)])
    assert result.exit_code == ExitCode.USAGE, result.output
    assert "internal" not in result.output.lower()


# --- Heuristic 3 and 5: control, freedom, and error prevention ---------------

WRITES_TO_AN_EXISTING_PROJECT = (
    ("add", "framework"),
    ("add", "mcp"),
    ("add", "tool"),
)


@pytest.mark.parametrize("path", WRITES_TO_AN_EXISTING_PROJECT, ids=lambda p: " ".join(p))
def test_writing_into_someone_elses_project_is_reversible(path: tuple[str, ...]) -> None:
    """Heuristic 3. Every `add` records an injection, so `revert` can undo it.

    `init` needs no such record - it owns the directory it creates, and is
    undone by deleting it. These commands write into a tree the user already
    had, which is the case where an exit must exist.
    """
    from toolseal.cli import configure_command

    source = Path(inspect.getfile(configure_command)).read_text(encoding="utf-8")
    assert "inject(" in source, "add commands no longer route writes through the injection recorder"


def test_revert_exists_and_can_preview() -> None:
    """Heuristic 3 and 5. The way back is itself previewable before it runs."""
    rendered = runner.invoke(app, ["revert", "--help"]).stdout
    assert "--dry-run" in rendered
    assert "--force" in rendered


def test_init_refuses_to_clobber_without_an_explicit_second_decision() -> None:
    """Heuristic 5. Overwriting is never the default."""
    rendered = runner.invoke(app, ["init", "--help"]).stdout
    assert "--force" in rendered
    assert "--dry-run" in rendered


def test_applying_a_regime_can_be_previewed_and_confirmed() -> None:
    """Heuristic 5. A change to policy is shown before it is written."""
    rendered = " ".join(runner.invoke(app, ["policy", "apply", "--help"]).stdout.split())
    assert "--yes" in rendered, "policy apply must confirm by default, with --yes to skip"


# --- Heuristic 4 again: machine output is uniformly available ----------------

HUMAN_ONLY_COMMANDS = {
    "policy list": "a prose catalogue of standards; consumers want `policy check`",
    "policy explain": "long-form explanatory text, not a data structure",
    "policy show": "attributes each rule to a source for a human reader",
    "policy apply": "an interactive confirmation flow",
    "policy relax": "writes a TOML block into the user's manifest",
    "policy enforce": "seals a lockfile; the lockfile is the machine artefact",
    "policy verify": "a pass/fail whose machine contract is its exit code",
}
"""Commands that deliberately have no `--json`, each with the reason.

Recorded as data rather than left implicit so that adding a command without
`--json` is a decision someone has to write down, not an omission.
"""


@pytest.mark.parametrize(("path", "command"), _leaves(), ids=_leaf_ids())
def test_every_reporting_command_can_be_read_by_a_machine(
    path: tuple[str, ...], command: Command
) -> None:
    """Heuristic 4. `--json` is available everywhere it is not deliberately absent."""
    name = " ".join(path)
    options = {opt for param in command.params for opt in getattr(param, "opts", [])}
    if name in HUMAN_ONLY_COMMANDS:
        assert "--json" not in options, (
            f"`toolseal {name}` gained --json; remove it from HUMAN_ONLY_COMMANDS"
        )
        return
    assert "--json" in options, (
        f"`toolseal {name}` has no --json. Add it, or record why not in HUMAN_ONLY_COMMANDS"
    )


def test_the_human_only_list_names_only_real_commands() -> None:
    """A stale exemption is how a sweep quietly stops covering something."""
    known = set(_leaf_ids())
    unknown = sorted(set(HUMAN_ONLY_COMMANDS) - known)
    assert not unknown, f"HUMAN_ONLY_COMMANDS names commands that do not exist: {unknown}"


# --- Heuristic 1: visibility of system status -------------------------------


def test_long_running_work_reports_progress() -> None:
    """Heuristic 1. The audit resolves dependencies over the network; it says so.

    Asserted against the observer the CLI installs rather than against rendered
    output, because the indicator is deliberately silent off a TTY - which is
    exactly how the test suite runs.
    """
    from toolseal.cli._ui import new_progress_observer

    observer = new_progress_observer()
    for method in ("start", "advance", "finish"):
        assert callable(getattr(observer, method)), f"progress observer cannot {method}"


def test_machine_output_is_never_polluted_by_decoration() -> None:
    """Heuristic 1 and 4. Status goes to stderr so `--json` stays parseable."""
    from toolseal.cli import _ui

    assert _ui.err_console.stderr, "progress console must write to stderr, not stdout"


# --- Heuristic 7: flexibility and efficiency of use -------------------------


def test_the_options_typed_most_often_have_short_forms() -> None:
    """Heuristic 7. An accelerator exists for the repeated arguments."""
    expected = {
        ("init",): {"-p", "-f", "-d"},
        ("audit",): set(),
        ("policy", "check"): {"-d"},
    }
    by_path = dict(_leaves())
    for path, wanted in expected.items():
        command = by_path[path]
        present = {
            opt
            for param in command.params
            for opt in getattr(param, "opts", [])
            if len(opt) == 2 and opt.startswith("-")
        }
        missing = wanted - present
        assert not missing, f"`toolseal {' '.join(path)}` lost short flags {sorted(missing)}"


def test_every_command_module_contributes_a_reachable_command() -> None:
    """A command nobody registered is a feature nobody can find (heuristic 7).

    Matched by the callables each module exposes rather than by module name:
    `configure_command` supplies `add framework` and `revert`, so a name-based
    check would call it unreachable while every one of its commands works.
    """
    import toolseal.cli as cli_package

    registered_callbacks: set[str] = set()
    for _, command in _leaves():
        callback = getattr(command, "callback", None)
        if callback is not None:
            registered_callbacks.add(callback.__name__)
    for _, module_name, _ in pkgutil.iter_modules(cli_package.__path__):
        if not module_name.endswith("_command"):
            continue
        module = __import__(f"toolseal.cli.{module_name}", fromlist=["_"])
        public = {
            name
            for name, value in vars(module).items()
            if callable(value) and not name.startswith("_") and inspect.isfunction(value)
        }
        assert public & registered_callbacks, (
            f"{module_name} exposes no command reachable from the app: {sorted(public)}"
        )
