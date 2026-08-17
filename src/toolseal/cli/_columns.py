"""Width arithmetic for the CLI's hand-rolled tables.

Every columnar output in this CLI is a handful of f-strings, not a table
framework - but they all need the same two computations: a column must be at
least as wide as its own heading (a heading that lost the width comparison
would render narrower than its data and break alignment), and a cell that
still overflows a capped column must be shortened in a way that reads as
"cut off" rather than as a normal, complete value.
"""

from __future__ import annotations

from collections.abc import Iterable


def col_width(header: str, values: Iterable[str]) -> int:
    """The width a column needs: whichever is wider, the heading or the data.

    The heading is folded into the same ``max`` as the data on purpose - a
    heading wider than its column, or a column that ignores its heading's
    width, is the alignment bug this function exists to prevent.
    """
    return max([len(header), *(len(v) for v in values)])


def clip(value: str, width: int) -> str:
    """Shorten *value* to fit *width*, marking the cut so it reads as truncated."""
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."
