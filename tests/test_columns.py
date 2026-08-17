"""`toolseal.cli._columns` - the width arithmetic every hand-rolled table shares.

Pinned in isolation because every table in the CLI depends on it: a bug here
would misalign `doctor`, `policy list`, `audit`'s family table and `registry
search` all at once, and none of those commands' own tests would explain why.
"""

from __future__ import annotations

from toolseal.cli._columns import clip, col_width


def test_heading_wider_than_every_value_sets_the_width() -> None:
    assert col_width("package@version", ["a", "b@1"]) == len("package@version")


def test_value_wider_than_the_heading_sets_the_width() -> None:
    assert col_width("id", ["a-fairly-long-identifier"]) == len("a-fairly-long-identifier")


def test_width_matches_the_longest_of_heading_and_data_regardless_of_order() -> None:
    # Whichever is wider must win, not whichever happens to be checked first -
    # a heading longer than its data is exactly the bug this guards against.
    assert col_width("short", ["much longer than the heading"]) == len(
        "much longer than the heading"
    )
    assert col_width("much longer than any value", ["a", "bb"]) == len("much longer than any value")


def test_empty_column_is_sized_by_its_heading_alone() -> None:
    assert col_width("standard", []) == len("standard")


def test_clip_leaves_short_values_untouched() -> None:
    assert clip("short", 20) == "short"


def test_clip_marks_a_shortened_value_as_cut_off() -> None:
    clipped = clip("a-value-much-longer-than-its-column", 10)

    assert len(clipped) == 10
    assert clipped.endswith("...")
    assert clipped != "a-value-mu"  # a silent truncation would look complete


def test_clip_degrades_gracefully_at_widths_too_small_for_a_marker() -> None:
    assert clip("abcdef", 2) == "ab"
    assert len(clip("abcdef", 2)) == 2
