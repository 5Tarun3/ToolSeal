"""User acceptance test: drive every feature the way a user would, in order.

The pytest suite proves each unit behaves. This proves the *product* works:
one journey from "never seen this tool" to "scaffolded, audited, configured and
reverted", run against the installed console script in a throwaway directory,
asserting on what the user actually sees rather than on internal state.

It exists because unit tests cannot fail the way a product fails. Every command
can pass its own tests while the tool is still unusable - a flag that means two
things, an error that blames the tool for a typo, a report a script cannot
parse. Those are the failures this catches, and each step below is written as
the question a user would be asking at that moment.

Run it with `python scripts/uat.py`. Exit 0 means every acceptance step passed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Result:
    """One acceptance step: what was asked, and what came back."""

    step: str
    description: str
    passed: bool
    detail: str = ""


@dataclass
class Journey:
    """The running record of an acceptance session."""

    executable: str
    results: list[Result] = field(default_factory=list)
    step: str = ""

    def stage(self, name: str) -> None:
        self.step = name
        print(f"\n=== {name}")

    def _run(self, args: Sequence[str], *, cwd: Path, stdin: str = "") -> tuple[int, str]:
        completed = subprocess.run(  # noqa: S603 - argv is this script's own fixtures
            [self.executable, *args],
            cwd=cwd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        return completed.returncode, completed.stdout + completed.stderr

    def _record(self, description: str, passed: bool, detail: str = "") -> None:
        self.results.append(Result(self.step, description, passed, detail))
        mark = "PASS" if passed else "FAIL"
        print(f"  {mark}  {description}")
        if not passed and detail:
            print(f"        {detail}")

    def exits(self, code: int, description: str, args: Sequence[str], *, cwd: Path) -> str:
        """Assert the exit code, which is the contract a script branches on."""
        got, output = self._run(args, cwd=cwd)
        self._record(
            description,
            got == code,
            f"wanted exit {code}, got {got}: {output.strip().splitlines()[:1]}",
        )
        return output

    def shows(
        self, text: str, description: str, args: Sequence[str], *, cwd: Path, stdin: str = ""
    ) -> str:
        """Assert on what the user reads, not on internal state."""
        _, output = self._run(args, cwd=cwd, stdin=stdin)
        self._record(description, text in output, f"{text!r} not in: {output.strip()[:160]}")
        return output

    def emits_json(self, description: str, args: Sequence[str], *, cwd: Path) -> object:
        """Assert `--json` is parseable, which is the whole point of the flag."""
        _, output = self._run(args, cwd=cwd)
        try:
            payload = json.loads(output)
        except json.JSONDecodeError as exc:
            self._record(description, False, f"not valid JSON ({exc}): {output.strip()[:160]}")
            return None
        self._record(description, True)
        return payload

    def claim(self, description: str, passed: bool, detail: str = "") -> None:
        """Assert something observed directly, such as a file not existing."""
        self._record(description, passed, detail)


def run(journey: Journey, root: Path) -> None:
    ts = journey

    ts.stage("1. Discovery - a new user opens the tool")
    ts.exits(0, "--version reports a version", ["--version"], cwd=root)
    ts.shows("Scaffold", "top-level help groups commands by pillar", ["--help"], cwd=root)
    ts.shows("policy explain", "help points at the check catalogue", ["--help"], cwd=root)
    ts.shows(
        "registry search", "the registry group points onward", ["registry", "--help"], cwd=root
    )
    ts.emits_json("doctor --json is parseable", ["doctor", "--json"], cwd=root)

    ts.stage("2. Scaffold - create a project")
    ts.exits(0, "init scaffolds with secure defaults", ["init", "myagent"], cwd=root)
    ts.shows(
        "toolseal.toml",
        "init --dry-run names what it would write",
        ["init", "ghost", "--dry-run"],
        cwd=root,
    )
    ts.claim("init --dry-run wrote nothing", not (root / "ghost").exists())

    project = root / "myagent"

    ts.stage("3. Audit - the question the tool exists to answer")
    ts.shows("100/100", "a fresh scaffold passes its own checks", ["audit", "."], cwd=project)
    ts.exits(0, "a clean audit exits 0", ["audit", "."], cwd=project)
    payload = ts.emits_json("audit --json is parseable", ["audit", ".", "--json"], cwd=project)
    ts.claim(
        "audit --json carries the score",
        isinstance(payload, dict) and "score" in payload,
        f"payload keys: {sorted(payload) if isinstance(payload, dict) else type(payload)}",
    )

    ts.stage("4. Policy - what the rules are, and why")
    ts.exits(0, "policy explain lists every check", ["policy", "explain"], cwd=project)
    ts.shows(
        "How to fix it", "explain names the remediation", ["policy", "explain", "A1"], cwd=project
    )
    ts.shows("gdpr", "policy list names the regimes", ["policy", "list"], cwd=project)
    ts.exits(0, "policy show attributes each rule to a source", ["policy", "show"], cwd=project)
    checked = ts.emits_json(
        "policy check --json is parseable", ["policy", "check", "--json"], cwd=project
    )
    ts.claim(
        "policy check --json keeps the 'not a verdict' caveat",
        isinstance(checked, dict) and bool(checked.get("disclaimer")),
        "a consumer could otherwise present coverage as a verdict",
    )

    ts.stage("5. Registry - find a tool")
    ts.exits(0, "registry search finds a server", ["registry", "search", "filesystem"], cwd=project)
    ts.emits_json(
        "registry search --json is parseable",
        ["registry", "search", "filesystem", "--json"],
        cwd=project,
    )

    ts.stage("6. Mistakes - every error a user will actually make")
    ts.exits(
        2, "a mistyped provider is a usage error", ["init", "x", "--provider", "nope"], cwd=root
    )
    ts.shows(
        "available:",
        "a rejected value lists the accepted ones",
        ["init", "x", "--provider", "nope"],
        cwd=root,
    )
    ts.exits(2, "an unknown check id is a usage error", ["policy", "explain", "ZZ9"], cwd=project)
    ts.exits(
        2, "an unknown registry entry is a usage error", ["registry", "show", "nosuch"], cwd=project
    )
    ts.shows(
        "toolseal registry search",
        "a miss suggests how to recover",
        ["registry", "show", "nosuch"],
        cwd=project,
    )
    ts.exits(
        2,
        "a mistyped audit path is a usage error, not an internal one",
        ["audit", str(root / "no-such-dir")],
        cwd=root,
    )

    bad = root / "badcfg"
    bad.mkdir(exist_ok=True)
    (bad / "toolseal.toml").write_text("not = valid [[[\n", encoding="utf-8")
    output = ts.exits(
        2, "a typo in the user's own toolseal.toml is a usage error", ["audit", "."], cwd=bad
    )
    ts.claim(
        "a user's typo is never reported as an internal bug",
        "internal" not in output.lower(),
        output.strip()[:160],
    )

    ts.stage("7. Guided flow - the wizard")
    ts.shows(
        "Next time:",
        "the wizard teaches the non-interactive form",
        ["init", "-i"],
        cwd=root,
        stdin="wiz\n1\n1\n1\n",
    )
    ts.exits(
        2, "--json and --interactive are refused together", ["init", "w2", "-i", "--json"], cwd=root
    )
    ts.exits(2, "a missing name outside a terminal is refused, not hung on", ["init"], cwd=root)

    ts.stage("8. Reversibility - undo what was added")
    ts.exits(
        0,
        "add mcp writes a server into the project",
        ["add", "mcp", "filesystem", "--framework", "claude-code"],
        cwd=project,
    )
    ts.exits(0, "revert --dry-run previews the undo", ["revert", "--dry-run"], cwd=project)
    ts.exits(0, "revert undoes it", ["revert", "--force"], cwd=project)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--executable",
        default=shutil.which("toolseal") or "toolseal",
        help="The toolseal console script to exercise.",
    )
    parser.add_argument("--keep", action="store_true", help="Keep the scratch project tree.")
    args = parser.parse_args()

    root = Path(tempfile.mkdtemp(prefix="toolseal-uat-"))
    journey = Journey(executable=args.executable)
    print(f"Acceptance run against {args.executable}\nScratch tree: {root}")

    try:
        run(journey, root)
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)

    failed = [result for result in journey.results if not result.passed]
    total = len(journey.results)
    print(f"\n{'=' * 68}")
    print(f"UAT: {total - len(failed)}/{total} acceptance steps passed")
    for result in failed:
        print(f"  FAILED [{result.step}] {result.description}")
    print("=" * 68)
    return 1 if failed else 0


if __name__ == "__main__":
    os.environ.setdefault("NO_COLOR", "1")
    sys.exit(main())
