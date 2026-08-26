"""The curated registry seed (P16): data only, no code.

`curated.json` is a `RegistryIndex` (`toolseal.core.registry.index`), selected
from an already-crawled index by `bench/registry_seed.py` against the
criteria fixed in `research/registry-curation-criteria.md`. It ships inside
the package for the same reason `toolseal.data.regimes` and
`toolseal.data.standards` do: `pyproject.toml` builds the wheel from
`src/toolseal` alone, so data a command needs after `pip install` has to live
here rather than in the repository's `research/` or `reference/` directories.
"""
