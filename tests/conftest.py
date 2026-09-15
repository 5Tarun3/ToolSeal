"""Suite-wide fixtures.

The check `C3` resolution path is memoised for the life of the process
(`toolseal.core.policy.family_c._resolve_cached`), by design - see that
module's docstring. That is exactly the property that makes it dangerous to
leave alone in tests: a test in one module that installs a fake resolver
seeds real cache entries keyed by `(name, channels, known)`, and those
entries outlive `monkeypatch`'s teardown of the fake itself. A later test in
a *different* module - `test_gate_vertical_slice.py`'s real, unmocked audit
of a scaffold that pins `langchain`, for instance - can then have its
"resolved cleanly" answer come from another test's stub instead of a live
registry lookup, silently and order-dependently.

Clearing the cache before every test, suite-wide, closes that: any call
during a test either hits a real registry or the fake that test itself
installed, never a leftover from some earlier module.
"""

from __future__ import annotations

import os

import pytest


def pytest_configure(config: pytest.Config) -> None:
    """Pin a terminal size for the whole session (spec: this fixes CI, not a
    style preference).

    `shutil.get_terminal_size()` - what both Click's help formatter and Rich
    read width from - checks the `COLUMNS`/`LINES` environment variables
    first and only falls back to `(80, 24)` if an OS lookup then *raises*.
    Several `--help` tests in `test_usability_heuristics.py` assert on
    substrings of rendered help text (`--force`, `--dry-run`, `--yes`); on a
    CI runner with no controlling terminal, that OS lookup can come back
    `(0, 0)` instead of raising, which skips the fallback entirely and
    collapses every column to near-zero width - each word wraps onto its own
    line, breaking any substring assertion that spans a wrap point. Setting
    both variables up front makes the width deterministic everywhere this
    suite runs, rather than only wherever the OS call happens to raise.

    `setdefault` rather than an unconditional set: a developer who exported a
    real width to see wrapping as they will in production keeps seeing it.
    """
    os.environ.setdefault("COLUMNS", "80")
    os.environ.setdefault("LINES", "24")


@pytest.fixture(autouse=True)
def _clear_c3_resolution_cache() -> None:
    from toolseal.core.policy.family_c import _resolve_cached

    _resolve_cached.cache_clear()
