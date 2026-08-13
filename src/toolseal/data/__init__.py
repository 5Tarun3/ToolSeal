"""Data files shipped with the package.

Catalogues live inside the package rather than in the repository's `reference/`
directory because `pyproject.toml` builds the wheel from `src/toolseal` alone.
A catalogue outside it would work from a checkout and be missing from an
install, which is the worst of both.
"""
