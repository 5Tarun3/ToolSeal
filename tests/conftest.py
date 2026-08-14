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

import pytest


@pytest.fixture(autouse=True)
def _clear_c3_resolution_cache() -> None:
    from toolseal.core.policy.family_c import _resolve_cached

    _resolve_cached.cache_clear()
