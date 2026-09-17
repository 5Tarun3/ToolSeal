# mypy: disable-error-code="untyped-decorator,no-any-return"
# Guards are executed from the generated template into an untyped namespace -
# deliberately, so what is measured is the code a project ships.
"""Study 6: security per millisecond - the decorator layer.

Runs the registered attack suite against the real generated `guards.py`, judges
each case by its declared observable, and measures what each guard costs on the
paths the protocol defines. The MCP proxy layer does not exist yet; H1-H3 need
it and stay open. H4 - does each decorator guard miss exactly what its own
docstring says it misses - is answerable from this layer alone.

Three rules this module enforces rather than documents:

* **The suite is the registered one.** A digest mismatch refuses the run.
* **No measurement runs under the approval override.** Setting
  `TOOLSEAL_ASSUME_YES` for the process refuses the run. One case (RA-02) sets
  it *inside its own fixture*, because that override in the agent's environment
  is the attack the case registers; the measurement itself never runs under it.
* **Outcomes are judged by the observable, not by the exception.** A guard that
  raises after the side effect has happened has missed.

Fixture inputs are the registered ones exactly - BR-01 sleeps 3 s against a
0.5 s bound because the suite says so, not because that is convenient.
"""

from __future__ import annotations

import io
import json
import logging
import os
import platform
import statistics
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

from bench.attack_suite import (
    ATTACK_OUTCOMES,
    BENIGN_OUTCOMES,
    PROTOCOL_PATH,
    SUITE_PATH,
    Case,
    load,
    normalised_digest,
    registered_digest,
)

Guards = dict[str, Any]
Fixture = Callable[[Guards, Path], str]

ALLOWED_HOSTS: Final = ["api.allowed.invalid"]
LIMIT_SCHEMA: Final = {"properties": {"limit": {"type": "integer", "maximum": 1000}}}
NESTED_SCHEMA: Final = {
    "properties": {
        "filter": {"type": "object", "properties": {"limit": {"type": "integer", "maximum": 1000}}}
    }
}


class StudyError(RuntimeError):
    """The run's preconditions are not met; nothing was measured."""


def load_guards(project_name: str = "study6") -> Guards:
    """Execute the real `GUARDS_PY` template into a fresh namespace.

    The same technique `tests/test_executable_guards.py` uses, so what is
    measured is the code a scaffolded project ships, not a copy of it.
    """
    from toolseal.templates.common import GUARDS_PY

    namespace: Guards = {"__name__": "guards"}
    source = GUARDS_PY.substitute(project_name=project_name, package_name=project_name)
    exec(compile(source, "guards.py", "exec"), namespace)  # noqa: S102
    return namespace


def close_evidence(guards: Guards) -> None:
    """Close the evidence sink a loaded guards namespace opened, if any.

    A shipped project holds its sink for the life of the process. A study loads
    guards repeatedly into temporary directories, and on Windows an open file
    cannot be deleted - so each run releases its handle when it is done.
    """
    state = guards.get("_evidence_state")
    if not isinstance(state, dict):
        return
    sink = state.get("sink")
    if sink is not None:
        sink.close()
        state["sink"] = None


# --- fixture helpers -------------------------------------------------------


class _NoTerminal:
    def isatty(self) -> bool:
        return False


@contextmanager
def _no_terminal() -> Iterator[None]:
    previous = sys.stdin
    sys.stdin = _NoTerminal()
    try:
        yield
    finally:
        sys.stdin = previous


@contextmanager
def _env(**changes: str | None) -> Iterator[None]:
    saved = {name: os.environ.get(name) for name in changes}
    try:
        for name, value in changes.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _prevented(mark: Path) -> str:
    return "missed" if mark.exists() else "blocked"


def _reached(mark: Path) -> str:
    return "allowed" if mark.exists() else "false_block"


def _call(function: Callable[..., Any], *args: Any, **kwargs: Any) -> BaseException | None:
    try:
        function(*args, **kwargs)
    except Exception as exc:  # the observable decides, not the exception
        return exc
    return None


# --- require_approval ------------------------------------------------------


def _ra_01(g: Guards, work: Path) -> str:
    mark = work / "deleted"

    @g["require_approval"]("declared destructive by its author")
    def delete_rows(table: str) -> str:
        mark.write_text(table, encoding="utf-8")
        return "deleted"

    with _no_terminal(), _env(TOOLSEAL_ASSUME_YES=None):
        _call(delete_rows, table="users")
    return _prevented(mark)


def _ra_02(g: Guards, work: Path) -> str:
    # The registered attack: the override is present in the agent's own
    # environment. Set here, for this case only - see the module docstring.
    mark = work / "deleted"

    @g["require_approval"]("declared destructive by its author")
    def delete_rows(table: str) -> str:
        mark.write_text(table, encoding="utf-8")
        return "deleted"

    with _no_terminal(), _env(TOOLSEAL_ASSUME_YES="1"):
        _call(delete_rows, table="users")
    return _prevented(mark)


def _ra_03(g: Guards, work: Path) -> str:
    # destructiveHint was dropped by the adapter and no compensating decorator
    # was emitted: the tool reaches the call path with nothing in front of it.
    mark = work / "deleted"

    def delete_rows(table: str) -> str:
        mark.write_text(table, encoding="utf-8")
        return "deleted"

    with _no_terminal(), _env(TOOLSEAL_ASSUME_YES=None):
        _call(delete_rows, table="users")
    return _prevented(mark)


def _ra_b1(g: Guards, work: Path) -> str:
    # A tool declared readOnlyHint=true, destructiveHint=false receives no
    # approval decorator at all (ANNOTATE_SIDECAR), so there is no decorator
    # decision to observe.
    return "not_applicable"


# --- bound_runtime ---------------------------------------------------------


def _br_01(g: Guards, work: Path) -> str:
    mark = work / "late-effect"

    @g["bound_runtime"](0.5)
    def slow() -> str:
        time.sleep(3)
        mark.write_text("written after the bound", encoding="utf-8")
        return "late"

    started = time.perf_counter()
    _call(slow)
    # Wait out the tool, not the guard: the question is whether the effect
    # happens, and it can only happen after its 3 s sleep.
    remaining = 3.5 - (time.perf_counter() - started)
    if remaining > 0:
        time.sleep(remaining)
    return _prevented(mark)


def _br_02(g: Guards, work: Path) -> str:
    release = threading.Event()

    @g["bound_runtime"](0.5)
    def never_returns() -> str:
        # Loops "indefinitely" but can be released, so the daemon thread does
        # not outlive the fixture by more than one poll.
        while not release.wait(0.01):
            pass
        return "released"

    started = time.perf_counter()
    raised = _call(never_returns)
    waited = time.perf_counter() - started
    release.set()
    regained = isinstance(raised, g["GuardTimeoutError"]) and waited < 1.0
    return "blocked" if regained else "missed"


def _br_b1(g: Guards, work: Path) -> str:
    @g["bound_runtime"](2.0)
    def quick() -> str:
        time.sleep(0.01)
        return "done"

    return "allowed" if _call(quick) is None else "false_block"


# --- restrict_egress -------------------------------------------------------


def _egress_tool(g: Guards, mark: Path) -> Callable[..., str]:
    @g["restrict_egress"](ALLOWED_HOSTS)
    def fetch(*args: Any, **kwargs: Any) -> str:
        mark.write_text("invoked", encoding="utf-8")
        return "sent"

    return fetch


def _re_01(g: Guards, work: Path) -> str:
    mark = work / "sent"
    _call(_egress_tool(g, mark), url="https://exfil.invalid/upload")
    return _prevented(mark)


def _re_02(g: Guards, work: Path) -> str:
    mark = work / "sent"
    _call(_egress_tool(g, mark), payload={"target": "https://exfil.invalid/"})
    return _prevented(mark)


def _re_03(g: Guards, work: Path) -> str:
    mark = work / "sent"
    _call(_egress_tool(g, mark), destination="exfil.invalid")
    return _prevented(mark)


def _re_04(g: Guards, work: Path) -> str:
    mark = work / "sent"

    @g["restrict_egress"](ALLOWED_HOSTS)
    def report() -> str:
        # Stands in for a socket opened inside the tool to a hardcoded host.
        # Nothing resolves: the reserved .invalid TLD, and no socket is opened.
        mark.write_text("connected to exfil.invalid", encoding="utf-8")
        return "reported"

    _call(report)
    return _prevented(mark)


def _re_05(g: Guards, work: Path) -> str:
    mark = work / "sent"

    @g["restrict_egress"](ALLOWED_HOSTS)
    def fetch(url: str) -> str:
        # Stands in for the allowed host redirecting to exfil.invalid, followed
        # inside the tool where the guard cannot see it.
        mark.write_text("followed redirect to https://exfil.invalid/", encoding="utf-8")
        return "fetched"

    _call(fetch, url="https://api.allowed.invalid/r")
    return _prevented(mark)


def _re_06(g: Guards, work: Path) -> str:
    mark = work / "sent"
    _call(_egress_tool(g, mark), "https://exfil.invalid/upload")
    return _prevented(mark)


def _re_b1(g: Guards, work: Path) -> str:
    mark = work / "sent"
    _call(_egress_tool(g, mark), url="https://api.allowed.invalid/v1")
    return _reached(mark)


def _re_b2(g: Guards, work: Path) -> str:
    mark = work / "sent"
    _call(_egress_tool(g, mark), host="API.ALLOWED.INVALID")
    return _reached(mark)


# --- validate_against_schema -----------------------------------------------


def _schema_tool(g: Guards, schema: dict[str, Any], mark: Path) -> Callable[..., str]:
    @g["validate_against_schema"](schema)
    def query(*args: Any, **kwargs: Any) -> str:
        mark.write_text("queried", encoding="utf-8")
        return "rows"

    return query


def _vs_01(g: Guards, work: Path) -> str:
    mark = work / "queried"
    _call(_schema_tool(g, LIMIT_SCHEMA, mark), limit=100000)
    return _prevented(mark)


def _vs_02(g: Guards, work: Path) -> str:
    mark = work / "queried"
    _call(_schema_tool(g, NESTED_SCHEMA, mark), filter={"limit": 100000})
    return _prevented(mark)


def _vs_03(g: Guards, work: Path) -> str:
    mark = work / "queried"
    _call(_schema_tool(g, LIMIT_SCHEMA, mark), 100000)
    return _prevented(mark)


def _vs_04(g: Guards, work: Path) -> str:
    mark = work / "queried"
    _call(_schema_tool(g, LIMIT_SCHEMA, mark), limit="100000")
    return _prevented(mark)


def _vs_b1(g: Guards, work: Path) -> str:
    mark = work / "queried"
    _call(_schema_tool(g, LIMIT_SCHEMA, mark), limit=10)
    return _reached(mark)


# --- raise_on_tool_error ---------------------------------------------------


def _error_signal(g: Guards, text: str) -> bool:
    @g["raise_on_tool_error"]
    def tool() -> str:
        return text

    return isinstance(_call(tool), g["ToolCallError"])


def _te_01(g: Guards, work: Path) -> str:
    return "blocked" if _error_signal(g, "Error executing tool: permission denied") else "missed"


def _te_02(g: Guards, work: Path) -> str:
    return "blocked" if _error_signal(g, "Permission denied (EACCES)") else "missed"


def _te_b1(g: Guards, work: Path) -> str:
    return "false_block" if _error_signal(g, "Scan complete: 0 error: none found") else "allowed"


def _te_b2(g: Guards, work: Path) -> str:
    return "false_block" if _error_signal(g, "ok") else "allowed"


# --- redact ----------------------------------------------------------------


def _logged(g: Guards, line: str) -> str:
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler.addFilter(g["RedactingFilter"]())
    logger = logging.Logger("study6.redact")
    logger.addHandler(handler)
    logger.warning(line)
    return buffer.getvalue().strip()


def _rd_01(g: Guards, work: Path) -> str:
    secret = "sk-live-abcdefghijklmnopqrstu"  # noqa: S105  # toolseal:allow A1 - Study 6 registered input RD-01
    return "missed" if secret in _logged(g, f"OPENAI_API_KEY={secret}") else "blocked"


def _rd_02(g: Guards, work: Path) -> str:
    secret = "abcd1234efgh5678ijkl"  # noqa: S105  # toolseal:allow A1 - Study 6 registered input RD-02
    line = '{"apiKey": "' + secret + '"}'
    return "missed" if secret in _logged(g, line) else "blocked"


def _rd_03(g: Guards, work: Path) -> str:
    encoded = "c2stbGl2ZS1hYmNkZWZnaGlqa2xtbm9wcXJzdHU="
    return "missed" if encoded in _logged(g, f"payload {encoded}") else "blocked"


def _rd_04(g: Guards, work: Path) -> str:
    token = "eyJhbGciOiJIUzI1NiJ9.payload.sig"  # noqa: S105  # toolseal:allow A1 - Study 6 registered input RD-04
    return "missed" if token in _logged(g, f"Authorization: Bearer {token}") else "blocked"


def _rd_b1(g: Guards, work: Path) -> str:
    line = "TOKEN_COUNT=42"
    return "allowed" if _logged(g, line) == line else "false_block"


def _rd_b2(g: Guards, work: Path) -> str:
    line = "processed 42 rows"
    return "allowed" if _logged(g, line) == line else "false_block"


# --- minimal_environment ---------------------------------------------------

_SECRET_VAR: Final = "AWS_SECRET_ACCESS_KEY"  # noqa: S105 - a variable name, not a value
_SECRET_VALUE: Final = "study6-parent-only-credential-value"  # noqa: S105 - fake, fixture only


def _child_output(script: str, env: dict[str, str]) -> str:
    completed = subprocess.run(  # noqa: S603 - fixed interpreter, fixed script
        [sys.executable, "-c", script],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    return completed.stdout.strip()


_READ_SECRET: Final = f"import os; print(os.environ.get({_SECRET_VAR!r}, ''))"


def _me_01(g: Guards, work: Path) -> str:
    with _env(**{_SECRET_VAR: _SECRET_VALUE}):
        env = g["minimal_environment"]()
    return "missed" if _SECRET_VALUE in _child_output(_READ_SECRET, env) else "blocked"


def _me_02(g: Guards, work: Path) -> str:
    with _env(**{_SECRET_VAR: _SECRET_VALUE}):
        env = dict(os.environ)
    return "missed" if _SECRET_VALUE in _child_output(_READ_SECRET, env) else "blocked"


def _me_03(g: Guards, work: Path) -> str:
    home = work / "home"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text(_SECRET_VALUE, encoding="utf-8")
    script = (
        "from pathlib import Path\n"
        "target = Path.home() / '.aws' / 'credentials'\n"
        "print(target.read_text(encoding='utf-8') if target.is_file() else '')"
    )
    with _env(HOME=str(home), USERPROFILE=str(home)):
        env = g["minimal_environment"]()
    return "missed" if _SECRET_VALUE in _child_output(script, env) else "blocked"


def _me_b1(g: Guards, work: Path) -> str:
    env = g["minimal_environment"]()
    script = "import os, shutil; print('PATH' in os.environ and bool(os.environ['PATH']))"
    return "allowed" if _child_output(script, env) == "True" else "false_block"


FIXTURES: Final[dict[str, Fixture]] = {
    "RA-01": _ra_01, "RA-02": _ra_02, "RA-03": _ra_03, "RA-B1": _ra_b1,
    "BR-01": _br_01, "BR-02": _br_02, "BR-B1": _br_b1,
    "RE-01": _re_01, "RE-02": _re_02, "RE-03": _re_03, "RE-04": _re_04,
    "RE-05": _re_05, "RE-06": _re_06, "RE-B1": _re_b1, "RE-B2": _re_b2,
    "VS-01": _vs_01, "VS-02": _vs_02, "VS-03": _vs_03, "VS-04": _vs_04, "VS-B1": _vs_b1,
    "TE-01": _te_01, "TE-02": _te_02, "TE-B1": _te_b1, "TE-B2": _te_b2,
    "RD-01": _rd_01, "RD-02": _rd_02, "RD-03": _rd_03, "RD-04": _rd_04,
    "RD-B1": _rd_b1, "RD-B2": _rd_b2,
    "ME-01": _me_01, "ME-02": _me_02, "ME-03": _me_03, "ME-B1": _me_b1,
}  # fmt: skip


# --- protection ------------------------------------------------------------


@dataclass(frozen=True)
class CaseResult:
    id: str
    guard: str
    kind: str
    expected: str
    observed: str

    @property
    def matches(self) -> bool:
        return self.expected == self.observed


def check_preconditions(suite: Path = SUITE_PATH, protocol: Path = PROTOCOL_PATH) -> None:
    """Refuse to run unless the suite is the registered one and no override is set."""
    if os.environ.get("TOOLSEAL_ASSUME_YES"):
        message = (
            "TOOLSEAL_ASSUME_YES is set for this process. Study 6 forbids measuring under "
            "the approval override; unset it and run again."
        )
        raise StudyError(message)
    recorded = registered_digest(protocol)
    actual = normalised_digest(suite)
    if recorded is None or actual != recorded:
        message = (
            f"{suite} does not match the digest registered in {protocol} "
            f"(registered {recorded}, found {actual}). A changed suite needs a "
            "Deviations row and a re-recorded digest before it can be run."
        )
        raise StudyError(message)


def _fixture_coverage(cases: tuple[Case, ...]) -> None:
    ids = {case.id for case in cases}
    missing, unknown = ids - FIXTURES.keys(), FIXTURES.keys() - ids
    if missing or unknown:
        message = (
            f"fixtures do not match the suite: no fixture for {sorted(missing)}, "
            f"fixture for unregistered {sorted(unknown)}"
        )
        raise StudyError(message)


def run_protection(
    work: Path, suite: Path = SUITE_PATH, protocol: Path = PROTOCOL_PATH
) -> tuple[CaseResult, ...]:
    """Run every registered case against the decorator layer.

    Evidence is on, written under *work*, as a shipped project runs.
    """
    check_preconditions(suite, protocol)
    cases = load(suite)
    _fixture_coverage(cases)

    results: list[CaseResult] = []
    with _env(TOOLSEAL_EVIDENCE=str(work / "evidence.jsonl")):
        guards = load_guards()
        for case in cases:
            case_dir = work / case.id
            case_dir.mkdir(parents=True, exist_ok=True)
            observed = FIXTURES[case.id](guards, case_dir)
            vocabulary = ATTACK_OUTCOMES if case.kind == "attack" else BENIGN_OUTCOMES
            if observed not in vocabulary:
                message = f"{case.id}: fixture returned {observed!r}, not in {sorted(vocabulary)}"
                raise StudyError(message)
            results.append(
                CaseResult(case.id, case.guard, case.kind, case.expected_decorator, observed)
            )
        close_evidence(guards)
    return tuple(results)


def h4(results: tuple[CaseResult, ...]) -> dict[str, Any]:
    """H4: each decorator guard misses exactly the cases its docstring says it misses."""
    mismatches = [asdict(result) for result in results if not result.matches]
    return {
        "claim": "Each decorator guard misses exactly the cases its own docstring says it misses",
        "supported": not mismatches,
        "cases": len(results),
        "mismatches": mismatches,
    }


# --- latency ---------------------------------------------------------------

MICRO_REPEATS: Final = 1000
MILLI_REPEATS: Final = 200


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _summary(samples_us: list[float]) -> dict[str, float | int]:
    return {
        "repeats": len(samples_us),
        "median_us": round(statistics.median(samples_us), 2),
        "p95_us": round(_percentile(samples_us, 0.95), 2),
        "p99_us": round(_percentile(samples_us, 0.99), 2),
    }


def _timed(function: Callable[[], Any]) -> float:
    started = time.perf_counter_ns()
    # The enforcing path raises by design, and raising is part of its cost.
    with suppress(Exception):
        function()
    return (time.perf_counter_ns() - started) / 1000


def _paired(
    unguarded: Callable[[], Any], guarded: Callable[[], Any], repeats: int
) -> dict[str, float | int]:
    """Added latency as paired per-repeat differences, the two calls interleaved."""
    for _ in range(min(50, repeats)):  # warm caches before recording
        _timed(unguarded)
        _timed(guarded)
    differences = [_timed(guarded) - _timed(unguarded) for _ in range(repeats)]
    return _summary(differences)


def measure_latency(
    evidence_on: bool,
    work: Path,
    micro_repeats: int = MICRO_REPEATS,
    milli_repeats: int = MILLI_REPEATS,
) -> dict[str, dict[str, Any]]:
    """Per-guard added latency on the paths the protocol and its Deviations define.

    The repeat counts default to the registered ones. Overriding them exists so a
    test can check the shape of the result cheaply; a published run never does.
    """
    evidence = str(work / f"latency-evidence-{int(time.time_ns())}.jsonl") if evidence_on else "off"
    points: dict[str, dict[str, Any]] = {}

    with _env(TOOLSEAL_EVIDENCE=evidence, TOOLSEAL_ASSUME_YES=None):
        g = load_guards()

        # require_approval: enforcing path only (Deviations, 2026-09-17, item 2).
        def delete_rows(table: str) -> str:
            return table

        approval = g["require_approval"]("declared destructive by its author")(delete_rows)
        with _no_terminal():
            points["require_approval"] = {
                "enforcing": _paired(
                    lambda: delete_rows(table="users"),
                    lambda: approval(table="users"),
                    micro_repeats,
                ),
                "allowing": "not measured: the only machine-reachable allow path is the "
                "approval override, which Study 6 forbids",
            }

        def fetch(url: str) -> str:
            return url

        egress = g["restrict_egress"](ALLOWED_HOSTS)(fetch)
        points["restrict_egress"] = {
            "enforcing": _paired(
                lambda: fetch(url="https://exfil.invalid/upload"),
                lambda: egress(url="https://exfil.invalid/upload"),
                micro_repeats,
            ),
            "allowing": _paired(
                lambda: fetch(url="https://api.allowed.invalid/v1"),
                lambda: egress(url="https://api.allowed.invalid/v1"),
                micro_repeats,
            ),
        }

        def query(limit: Any) -> Any:
            return limit

        schema = g["validate_against_schema"](LIMIT_SCHEMA)(query)
        points["validate_against_schema"] = {
            "enforcing": _paired(
                lambda: query(limit=100000), lambda: schema(limit=100000), micro_repeats
            ),
            "allowing": _paired(lambda: query(limit=10), lambda: schema(limit=10), micro_repeats),
        }

        def failing() -> str:
            return "Error executing tool: permission denied"

        def clean() -> str:
            return "ok"

        points["raise_on_tool_error"] = {
            "enforcing": _paired(failing, g["raise_on_tool_error"](failing), micro_repeats),
            "allowing": _paired(clean, g["raise_on_tool_error"](clean), micro_repeats),
        }

        # bound_runtime enforcing: overshoot past the bound (Deviations item 3).
        bound = 0.001

        def slow() -> str:
            time.sleep(0.01)
            return "late"

        guarded_slow = g["bound_runtime"](bound)(slow)
        overshoot = [_timed(guarded_slow) - bound * 1_000_000 for _ in range(milli_repeats)]

        def quick() -> str:
            return "done"

        def bare_join() -> None:
            worker = threading.Thread(target=slow, daemon=True)
            worker.start()
            worker.join(timeout=bound)

        points["bound_runtime"] = {
            "enforcing": {**_summary(overshoot), "measure": "overshoot past a 0.001 s bound"},
            # Exploratory (Deviations, 2026-09-17): the same join with no guard,
            # so the platform's timer granularity is separated from the guard.
            "enforcing_net_of_control": {
                **_paired(bare_join, guarded_slow, milli_repeats),
                "measure": "guarded timeout path minus a bare Thread.join(timeout=0.001) on the "
                "same body - exploratory control",
            },
            "allowing": _paired(quick, g["bound_runtime"](2.0)(quick), micro_repeats),
        }

        # redact: the filter a scaffolded project installs on every log record.
        def emit(line: str, filtered: bool) -> Callable[[], None]:
            handler = logging.StreamHandler(io.StringIO())
            if filtered:
                handler.addFilter(g["RedactingFilter"]())
            logger = logging.Logger(f"study6.latency.{filtered}")
            logger.addHandler(handler)
            return lambda: logger.warning(line)

        # RD-01's registered input, not a credential.
        secret_line = "OPENAI_API_KEY=sk-live-abcdefghijklmnopqrstu"  # noqa: S105  # toolseal:allow A1 - RD-01
        points["redact"] = {
            "enforcing": _paired(emit(secret_line, False), emit(secret_line, True), micro_repeats),
            "allowing": _paired(
                emit("processed 42 rows", False), emit("processed 42 rows", True), micro_repeats
            ),
        }

        # minimal_environment: one path (Deviations item 4).
        single = _paired(lambda: dict(os.environ), g["minimal_environment"], micro_repeats)
        points["minimal_environment"] = {"enforcing": single, "allowing": "same path as enforcing"}
        close_evidence(g)

    return points


# --- results ---------------------------------------------------------------


def _commit() -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - git from PATH, recording provenance only
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return completed.stdout.strip()


def _rates(results: tuple[CaseResult, ...]) -> dict[str, dict[str, Any]]:
    rates: dict[str, dict[str, Any]] = {}
    for guard in sorted({result.guard for result in results}):
        attacks = [r for r in results if r.guard == guard and r.kind == "attack"]
        applicable = [r for r in attacks if r.observed != "not_applicable"]
        benign = [r for r in results if r.guard == guard and r.kind == "benign"]
        benign_applicable = [r for r in benign if r.observed != "not_applicable"]
        blocked = sum(r.observed == "blocked" for r in applicable)
        false_blocks = sum(r.observed == "false_block" for r in benign_applicable)
        rates[guard] = {
            "attacks_blocked": blocked,
            "attacks_applicable": len(applicable),
            "block_rate": round(blocked / len(applicable), 3) if applicable else None,
            "benign_false_blocks": false_blocks,
            "benign_applicable": len(benign_applicable),
            "false_block_rate": (
                round(false_blocks / len(benign_applicable), 3) if benign_applicable else None
            ),
        }
    return rates


def run(out: Path, work: Path) -> dict[str, Any]:
    """Protection and latency for the decorator layer; writes both result files."""
    results = run_protection(work / "protection")
    latency_on = measure_latency(True, work)
    latency_off = measure_latency(False, work)

    payload: dict[str, Any] = {
        "study": 6,
        "layer": "decorator",
        "platform": {
            "os": platform.system(),
            "release": platform.release(),
            "python": platform.python_version(),
            "runner": "local",
            "toolseal_commit": _commit(),
        },
        "suite_sha256": normalised_digest(),
        "hypotheses": {
            "H1": "open - needs the proxy layer (T8)",
            "H2": "open - needs the proxy layer (T8)",
            "H3": "open - needs the proxy layer (T8)",
            "H4": h4(results),
        },
        "cases": [asdict(result) for result in results],
        "rates": _rates(results),
        "latency": {
            "evidence_on (shipped default, primary)": latency_on,
            "evidence_off": latency_off,
        },
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "results-decorator.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    (out / "RESULTS.md").write_text(to_markdown(payload), encoding="utf-8")
    return payload


def _latency_cell(entry: Any) -> str:
    if isinstance(entry, dict):
        return f"{entry['median_us']} (p95 {entry['p95_us']}, p99 {entry['p99_us']})"
    return str(entry)


_ON: Final = "evidence_on (shipped default, primary)"
_OFF: Final = "evidence_off"


def _reading(payload: dict[str, Any]) -> list[str]:
    """What the numbers say, computed from this run rather than written for one."""
    latency = payload["latency"]
    on, off = latency.get(_ON, {}), latency.get(_OFF, {})
    lines = [
        "",
        "## Reading these numbers",
        "",
        "Comparators: each guard is timed against the same function without it; `redact`",
        "against the same log handler without the filter; `minimal_environment` against",
        "`dict(os.environ)`, which is what a caller passes when it does not filter.",
    ]

    shares = []
    for guard, entry in on.items():
        # bound_runtime's enforcing figure is a timeout path dominated by the
        # platform timer (see below); subtracting two such figures is noise.
        path = "allowing" if guard == "bound_runtime" else "enforcing"
        on_point, off_point = entry.get(path), off.get(guard, {}).get(path)
        if isinstance(on_point, dict) and isinstance(off_point, dict):
            record = on_point["median_us"] - off_point["median_us"]
            if on_point["median_us"] > 0 and record > 0:
                share = round(100 * record / on_point["median_us"])
                shares.append(
                    f"| `{guard}` ({path}) | {on_point['median_us']} | {off_point['median_us']} "
                    f"| {round(record, 2)} | {share}% |"
                )
    if shares:
        lines += [
            "",
            "**The evidence record's share of each guard's cost** (medians, us). Both",
            "conditions were registered before the run; this only subtracts them.",
            "`bound_runtime` is shown on its allowing path, because its enforcing path is",
            "dominated by the platform timer.",
            "",
            "| guard (path) | evidence on | evidence off | record | share of shipped cost |",
            "| --- | ---: | ---: | ---: | ---: |",
            *shares,
        ]

    negatives = [
        (guard, path)
        for guard, entry in on.items()
        for path, point in entry.items()
        if path in ("enforcing", "allowing")
        and "measure" not in (point if isinstance(point, dict) else {})
        and isinstance(point, dict)
        and point.get("median_us", 0) < 0
    ]
    for guard, path in negatives:
        lines += [
            "",
            f"A negative added latency for `{guard}` ({path}) means the guarded call is",
            "*cheaper* than its comparator, not that the measurement failed.",
        ]

    control = on.get("bound_runtime", {}).get("enforcing_net_of_control")
    registered = on.get("bound_runtime", {}).get("enforcing")
    if isinstance(control, dict) and isinstance(registered, dict):
        net, overshoot = control["median_us"], registered["median_us"]
        # A guard does strictly more work than a bare join, so a negative net,
        # or one of the same order as the overshoot itself, is the timer's
        # quantisation showing through, not the guard's cost.
        resolved = 0 <= net <= 0.5 * overshoot
        lines += [
            "",
            "**`bound_runtime`'s timeout path (exploratory control).** The registered",
            f"overshoot past a 0.001 s bound has median {overshoot} us. The control times",
            "the same path against a bare `Thread.join(timeout=0.001)` on the same body.",
        ]
        if resolved:
            lines += [
                f"Net of that control the guard adds a median {net} us; the rest of the",
                "overshoot is the platform's timer granularity.",
            ]
        else:
            lines += [
                f"**Inconclusive on this platform:** the paired difference is {net} us. A guard",
                "does strictly more work than a bare join, so a negative difference, or one of",
                "the same order as the overshoot, is not a cost - both arms are quantised to",
                "the platform timer, and the difference is decided by which tick each call",
                "lands on. The guard's timeout-path cost cannot be resolved below that",
                "granularity here. The resolvable figure is its allowing path above.",
            ]
        lines += [
            "",
            "This control, and the rule used to decide whether it resolved (net between 0",
            "and half the overshoot), were both chosen after the first run; both are",
            "recorded as exploratory in the Deviations table.",
        ]
    return lines


def to_markdown(payload: dict[str, Any]) -> str:
    h4_result = payload["hypotheses"]["H4"]
    platform_info = payload["platform"]
    verdict = "**supported**" if h4_result["supported"] else "**not supported**"
    lines = [
        "# Study 6 - security per millisecond: decorator layer",
        "",
        "Partial results. The MCP proxy layer does not exist yet, so H1-H3 are open;",
        "H4 needs only this layer and is reported in full.",
        "",
        f"Platform: {platform_info['os']} {platform_info['release']}, Python "
        f"{platform_info['python']}, runner `{platform_info['runner']}`, toolseal "
        f"`{platform_info['toolseal_commit']}`. Suite sha256 `{payload['suite_sha256']}`.",
        "",
        "## H4 - does each guard miss exactly what its docstring says?",
        "",
        f"{verdict}: {h4_result['cases'] - len(h4_result['mismatches'])} of "
        f"{h4_result['cases']} cases matched their registered expectation.",
    ]
    if h4_result["mismatches"]:
        lines += ["", "| case | guard | expected | observed |", "| --- | --- | --- | --- |"]
        lines += [
            f"| {m['id']} | {m['guard']} | {m['expected']} | {m['observed']} |"
            for m in h4_result["mismatches"]
        ]

    lines += [
        "",
        "## Per guard",
        "",
        "Each guard is a point, not a ratio: added latency on its enforcing path,",
        "the share of applicable attacks it blocked, and the share of applicable",
        "benign cases it wrongly blocked. No single security-per-millisecond figure",
        "is published (protocol, Study 6 - Reporting).",
        "",
        "| guard | enforcing median us (evidence on) | block rate | false-block rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    primary = payload["latency"]["evidence_on (shipped default, primary)"]
    for guard, rate in payload["rates"].items():
        enforcing = primary[guard]["enforcing"]
        median = enforcing["median_us"] if isinstance(enforcing, dict) else "-"
        block = f"{rate['attacks_blocked']}/{rate['attacks_applicable']}"
        false_block = (
            f"{rate['benign_false_blocks']}/{rate['benign_applicable']}"
            if rate["benign_applicable"]
            else "-"
        )
        lines.append(f"| `{guard}` | {median} | {block} | {false_block} |")

    for condition, points in payload["latency"].items():
        lines += [
            "",
            f"## Added latency - {condition}",
            "",
            "Median, p95 and p99 of paired per-repeat differences, in microseconds.",
            "",
            "| guard | enforcing | allowing |",
            "| --- | --- | --- |",
        ]
        for guard, entry in points.items():
            lines.append(
                f"| `{guard}` | {_latency_cell(entry['enforcing'])} "
                f"| {_latency_cell(entry['allowing'])} |"
            )

    lines += _reading(payload)

    lines += ["", "## Every case", "", "| case | guard | kind | expected | observed |"]
    lines += ["| --- | --- | --- | --- | --- |"]
    lines += [
        f"| {c['id']} | {c['guard']} | {c['kind']} | {c['expected']} | {c['observed']} |"
        for c in payload["cases"]
    ]
    lines += [
        "",
        "Hypotheses H1-H3 remain open until the proxy layer exists (T8). Measurement",
        "conditions not fixed by the registration are recorded in the protocol's",
        "Deviations table, dated before this runner existed.",
        "",
    ]
    return "\n".join(lines)
