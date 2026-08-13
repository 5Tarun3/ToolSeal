"""The Study 3 harness.

The number this study produces is flattering, which is exactly why the tests
here are about the caveats rather than the measurement. A ratio in the tens of
thousands invites overclaiming, so what is pinned is that the report keeps
saying what it excludes and what it is not comparing like for like.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.overhead import (
    guard_overhead,
    measure,
    redaction_overhead,
    run,
    to_markdown,
    write,
)

REPEATS = 15


def test_measure_records_every_repeat() -> None:
    timing = measure("noop", lambda: None, REPEATS)

    assert len(timing.samples) == REPEATS
    assert timing.mean >= 0
    assert timing.p95 >= timing.median


def test_guard_overhead_is_measured_on_both_paths() -> None:
    payload = guard_overhead(REPEATS)

    assert payload["unguarded"]["repeats"] == REPEATS
    assert payload["guarded"]["repeats"] == REPEATS
    assert "overhead_per_call_us" in payload


def test_guard_costs_something_but_not_tens_of_milliseconds() -> None:
    # Both halves matter. A guard measured at zero would mean it was optimised
    # away and nothing was tested; a guard costing tens of milliseconds would
    # undercut the study's argument.
    #
    # The bound is generous on purpose. This asserts an order of magnitude, not
    # a benchmark: a scheduler hiccup on a shared machine has been observed
    # pushing a single repeat past 1 ms against a ~14 us signal, and a tight
    # bound here would fail for reasons that say nothing about the guard.
    payload = guard_overhead(REPEATS)

    assert payload["overhead_per_call_ms"] < 10.0


def test_overhead_uses_a_statistic_robust_to_outliers() -> None:
    # Named in the payload so a reader knows the figure is not a mean.
    assert "median" in guard_overhead(REPEATS)["statistic"]


def test_redaction_is_measured() -> None:
    assert redaction_overhead(REPEATS)["redaction"]["repeats"] == REPEATS


def test_report_states_what_it_excludes() -> None:
    # Provider latency is excluded on purpose. If that caveat ever falls out,
    # the numbers read as a claim about end-to-end agent performance, which they
    # are not.
    text = to_markdown(run(REPEATS))

    assert "provider latency" in text
    assert "deliberately" in text


def test_report_refuses_to_present_the_ratio_bare() -> None:
    # The comparison is indicative, not like-for-like: 800 ms buys a learned
    # policy, a guard reinstates one declared property. Letting the ratio speak
    # for itself would be the overclaim.
    text = to_markdown(run(REPEATS))

    assert "not like-for-like" in text
    assert "narrower than the ratio suggests" in text


def test_reference_point_is_attributed_not_reproduced() -> None:
    payload = run(REPEATS)

    assert "quoted from the paper" in payload["reference_point"]
    assert payload["comparison"]["agentwarden_ms_per_call"] == 800


def test_write_emits_both_artifacts(tmp_path: Path) -> None:
    write(run(REPEATS), tmp_path)

    payload = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert payload["study"].startswith("S3")
    assert (tmp_path / "RESULTS.md").read_text(encoding="utf-8").startswith("# Study 3")


def test_repeats_are_reported_so_precision_is_not_overstated() -> None:
    payload = run(REPEATS)

    assert payload["repeats"] == REPEATS
    for key in ("unguarded", "guarded", "redaction"):
        # Median and p95 alongside the mean: a single figure from a noisy
        # machine overstates its own precision.
        assert {"mean_us", "median_us", "p95_us"} <= payload[key].keys()
