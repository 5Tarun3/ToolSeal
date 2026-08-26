# Registry curation criteria (P16)

Fixed in writing, before any curated set exists — no entry has been chosen and
no selection script has been written as of this commit. This follows the same
ordering `research/studies/s1/selection-criteria.md` used for the corpus
strata: the rule is committed first, so a later reader can check the result
against a document that predates it, rather than against a description
written after the fact to match whatever came out.

This document is cited by the project plan's risk register ("curation
criteria fixed in writing before seeding") and by its threats-to-validity
table ("registry entries curated by us, then audited by us — curation
criteria fixed and published before auditing; audit is automated"). Both
exist because of one specific failure mode, addressed head-on below.

## Why the audit score plays no part in selection

toolseal's registry claim is that listed entries are audited. If entries are
*chosen* because they scored well and then reported as "the audited set
scores well," the claim proves nothing — it measures the selection filter,
not the ecosystem. This is true regardless of good intentions: it is a
structural problem with using a measurement as its own inclusion test.

So: **no rule below reads `audit.score`, `audit.blocking`, or `audit.findings`**
(`toolseal.core.registry.index.EntryAudit`). Every rule reads a field of the
descriptor itself — `toolseal.core.registry.utd.UnifiedToolDescriptor` — the
same normalized record the crawl produces before any assessment runs.

That does not make the overlap with the score coincidental in a way worth
glossing over. `core/registry/crawl.py`'s `assess()` deducts points for
several of the exact things this document also selects on: no verifiable
registry, no repository, no description, not the latest version, not active.
Two things are true at once, and both matter:

1. The overlap is not evidence of circularity. `assess()` is a *downstream*
   computation over these same descriptor fields, with an arbitrary point
   weighting (-30 / -20 / -10 / -10 / -25 / -15) attached by whoever wrote
   the scorer. Selecting on the fields directly is auditable per-field by
   inspection ("does this entry declare a repository? yes or no") without
   trusting that weighting at all, and is stable if that weighting is ever
   changed — reweighting `assess()` tomorrow does not silently change who is
   in the curated set today, because the set was never a function of the
   score to begin with.
2. What *would* be circular is selecting on the score itself (`score >= 60`,
   "not blocking," or any threshold on `EntryAudit`). That collapses several
   independent judgments into one opaque number and then reports "the
   registry favors well-assessed tools" — a tautology, since the filter and
   the yardstick are the same thing. This document's rules never do that.

Each rule below is justified independently of whether it happens to produce a
particular score, and each is checked against the finished selection in the
P16 report precisely so that a reader can see it was not tuned toward one.

## Source

The already-crawled, already-normalized local index that `toolseal registry
sync` produces from the official MCP registry
(`https://registry.modelcontextprotocol.io/v0/servers`), per plan §2.6 and
the P15 crawl → normalize → audit pipeline (`core/registry/crawl.py`). P16
does not run a second crawl or add a second source; it selects a subset of an
index that P15 already built, keeping "acquire the data" and "curate the
data" as two separably reviewable steps.

The specific snapshot used for the one committed selection — its `built_at`
timestamp, total entry count, and a content hash — is recorded in the P16
report rather than in this document, because this document fixes the *rule*,
which must survive being re-run against a different, later snapshot; the
report records what one particular run of the rule was applied to.

### A second acquisition path: search, not only pagination

The paginated crawl above has a bias worth stating plainly rather than
discovering later: `crawl_mcp_registry`'s default walk returns whatever the
registry's own pagination sorts first, and one full crawl measured 1988 of
2000 entries under the `ai.*` prefix, a single namespace (`ai.bowmark`)
accounting for roughly a third of the total by itself. A `max_pages`-bounded
`sync` run over that ordering can complete having sampled almost nothing
outside one heavily-populated namespace — genuinely registered, widely-used
servers such as `@upstash/context7-mcp` or `@sentry/mcp-server` exist in the
registry and simply never surface within any practical page budget.

`bench/registry_seed_search.py` reaches entries via the registry's own
`?search=` filter instead of pagination order, for a short, explicit list of
names independently verified against npm before being searched for. This
changes *how an entry is found*, not *whether it qualifies*: every candidate
still passes through the exact same `included()` predicate defined in this
document, reading only descriptor fields, blind to `EntryAudit` — the
supplement does not get a looser rule to compensate for the smaller
candidate pool a single search term returns. A term that turns up nothing
`included()`-worthy is reported as excluded, the same as any candidate from
the paginated crawl.

This does not fix the underlying pagination bias — a full, unbiased crawl of
the registry (or a search-term-driven crawl broad enough to be representative
rather than a short hand-picked list) is future work. It is a documented,
narrow workaround for specific names known in advance, not a claim that the
curated set's *composition* is now representative of the ecosystem.

## Inclusion rules

All of the following must hold. A descriptor is included only if every rule
passes — this is a conjunction, not a scored combination.

**1. `source.registry` is `npm` or `pypi`.**
These are the two channels `core/registry/resolve.py`'s `resolve()` checks by
default for check C3 (ToolGate) — the two registries this project can
independently re-verify a package still resolves in, today, without adding a
new verification channel first. `oci`, `nuget`, `mcpb`, and anything the
crawl could not classify (`unknown`) are excluded not as a judgment on the
tools themselves, but because shipping an entry as part of an audited
registry while having no way to re-check its existence undercuts the
provenance claim the registry makes. This is the "source registry is one of
the two supported" criterion named in the task brief, grounded in code that
already exists for an unrelated reason (C3), not invented for this document.

**2. `provenance.repository` is declared (non-null).**
A published source location is the minimum a curator, a later auditor, or a
developer deciding whether to install something needs in order to go look at
the actual code, its license, and its issue history. Its absence is not a
statement about the tool's quality; it just means there is nothing today's
registry entry can point a reader at.

**3. `description` is non-empty.**
A listing with no stated purpose cannot be evaluated for fit by someone
reading the registry, independent of anything about its security posture.
Note on this specific snapshot: every one of the 2000 crawled entries already
carries a non-empty description, so this rule changes no membership in the
one selection actually committed here. It is kept anyway because the
criteria are meant to describe what any future re-run checks, not only what
happened to bind on one snapshot — dropping a rule because it is currently
slack would make this document stop matching the code that implements it.

**4. `is_latest` is true.**
The registry's own `isLatest` metadata marks which of possibly several
published versions of a server is current; other versions of the same server
appear in the crawl as separate entries (the descriptor `id` embeds the
version). Keeping only the latest keeps one entry per server and matches
what installing "the postgres server," say, would actually resolve to today.
A superseded version is a worse default regardless of any other property it
has.

**5. `status` is `active`.**
The registry's own lifecycle field. An entry whose source registry marks it
`deprecated` or otherwise not active is a listing its own publisher says not
to use; a curated starting-point set should not include one on that basis
alone, independent of anything else known about it.

## Exclusion

Everything that fails any rule above is excluded. There is no manual
override list in either direction — nothing is added back in after failing a
rule, and nothing is dropped after passing every rule. This is what makes
"apply the criteria mechanically" (P16, task 2) a meaningful instruction
rather than a formality: a script, not a person, decides membership.

## The cap

The plan's risk register sets a hard cap of 100–200 entries. This cap bounds
*effort and blast radius* — how much a v1 registry can grow before curation
becomes unbounded — not a target the rules above are tuned to hit.

- If the mechanical rules select **fewer than 100**, the true count is
  reported as-is. The criteria are not loosened to reach the floor; a
  looser rule invented after seeing the count would be selecting on the
  outcome by a slower route than reading the score directly, and is exactly
  as circular.
- If the mechanical rules select **more than 200**, the surviving set is
  truncated to 200 by sorting on `id` (the descriptor's own canonical sort
  key — `RegistryIndex.to_dict()` already sorts entries this way, so this
  introduces no new field) ascending, and keeping the first 200.
  Lexicographic order on an identifier is the one tie-break available that
  carries no popularity signal, no editorial judgment, and no dependence on
  `EntryAudit`.

## Reproducibility

Selection is a pure function of the input index: `select(index) ->
tuple[IndexEntry, ...]` in `bench/registry_seed.py` reads only descriptor
fields, sorts deterministically, and applies the cap as described above.
Running it twice against the same input index produces the same output in
the same order — pinned by
`tests/test_bench_registry_seed.py::test_selection_is_idempotent`, which
applies the function to one fixture index twice and asserts the results are
identical, including order. Nothing in the selection path reads wall-clock
time, randomness, or any state outside the index passed in.

## What this does not establish

None of the above says anything about whether an included server's tools are
what they claim to be — enumerating a server's tools means running it, and
this project has decided not to execute untrusted code from the registry
(`core/registry/crawl.py`). Every entry in the curated set, like every entry
in the full crawl, carries `tools_enumerated: false`. The curated set is
audited on provenance and completeness; it is not audited on behavior.
