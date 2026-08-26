# P1 - Remote MCP annotation capture

**Question.** What security annotations do real, production, OAuth-protected MCP
servers actually declare - and does `tools/list` describe the callable surface?

**Why it was run.** P0 answered a translation question against a *synthetic*
fixture server whose annotations were ground truth by construction. Nothing in
this project had ever observed a real server's annotations: all 113 curated
registry entries carry `tools_enumerated: false`, because crawling records
metadata without running anything. Contribution C5 and check family G both act
on annotation hints, so the hints' real-world shape was an untested input.

## Method

Three vendor-operated remote servers were enumerated over authenticated HTTP
using the MCP Inspector CLI, which performs its own OAuth flow and holds its own
token:

```
npx @modelcontextprotocol/inspector@latest --cli \
  --server-url <url> --transport http --method tools/list
```

Raw JSON-RPC responses are stored verbatim in `results/`, unedited. No response
was transcribed or summarised by hand; `summary.json` is generated from them.

Cross-validation: an independent enumeration path (a headless Claude Code
subprocess reporting its loaded MCP tool names) returned exactly the same tool
counts - 9 / 28 / 55 - from a *different* OAuth grant.

## Results

| Server | URL | Tools | Annotated |
|---|---|---|---|
| Sentry | `mcp.sentry.dev/mcp` | 9 | 9 |
| Notion | `mcp.notion.com/mcp` | 28 | 28 |
| Linear | `mcp.linear.app/mcp` | 55 | 55 |

Hint coverage (`present` / `true`):

| Hint | Sentry | Notion | Linear |
|---|---|---|---|
| `readOnlyHint` | 9 / 6 | 28 / 14 | 55 / 33 |
| `destructiveHint` | 9 / 2 | 28 / 3 | 55 / 18 |
| `idempotentHint` | **1** / 0 | 28 / 16 | 55 / 34 |
| `openWorldHint` | 9 / 8 | 28 / 3 | 55 / 5 |

`title` was declared by none of the 92 tools.

### Findings

1. **Annotations are universal here, not absent.** Every one of the 92 tools
   carries annotations. The registry's `tools_enumerated: false` posture means
   the project has been modelling a world with no annotation data while
   production servers declare it comprehensively.

2. **Coverage is uneven per server.** Sentry omits `idempotentHint` on 8 of 9
   tools; Notion and Linear declare all four hints on every tool. An omitted
   hint is not a neutral value - a consumer that reads a missing
   `idempotentHint` as `false` is guessing, and the spec's defaults differ by
   whether `readOnlyHint` is set.

3. **No internal contradictions.** No tool declared `readOnlyHint` and
   `destructiveHint` simultaneously, and all four Linear `delete_*` tools are
   correctly marked destructive and non-idempotent. For these three vendors the
   hints are self-consistent; this probe does *not* establish that they are
   truthful, only that they are not self-refuting.

4. **`tools/list` understates the callable surface (Sentry).** Sentry exposes a
   search-and-dispatch pair: `search_sentry_tools` (readOnly, `openWorldHint`
   false) returns a catalogue of operations that are "intentionally not exposed
   as top-level tools", and `execute_sentry_tool` invokes any of them by name.
   Its `arguments` parameter is `{"type": "object", "additionalProperties": {}}`
   - unconstrained. So a single `destructiveHint: true` covers an unbounded set
   of operations, and no parameter-level constraint is available to synthesise a
   guard against. **Enumerating this server and recording `tools_enumerated:
   true` would be actively misleading.** Four other tools carry similarly open
   object parameters (see `summary.json`).

5. **`openWorldHint` splits by product.** Near-universal for Sentry (8/9),
   uncommon for Notion (3/28) and Linear (5/55).

6. **Scope grants are coarse and bundled.** Sentry's authorize request asks for
   `org:read project:write team:write event:write` as one non-negotiable bundle
   - three write grants to enumerate a monitoring tool.

## Limitations

- One account, one point in time. Tool sets may vary by plan, workspace or
  granted scope; a differently-scoped grant may see a different catalogue.
- The Inspector's OAuth client is registered separately from the editor's, so
  these results reflect that client's grant.
- Finding 3 concerns self-consistency only. Whether a tool marked
  `readOnlyHint: true` in fact only reads is not tested here; that requires
  behavioural probing, not enumeration.
- Sentry's hidden catalogue was not enumerated - doing so requires *calling*
  `search_sentry_tools`, which is a tool invocation, not enumeration.

## C5: lowering the captured corpus

`c5_lowering.py` builds a `UnifiedToolDescriptor` per captured tool - real
annotations, real input schema - and runs `plan_translation` into each target.
Results in `results/c5-lowering.json`.

| Target | Lossless | Guards synthesised |
|---|---|---|
| `langchain` (LangChain / LangGraph) | 92 / 92 | 0 |
| `claude-code` | 92 / 92 | 0 |
| `crewai` | **0 / 92** | 452 |

CrewAI's 452 guards: 337 `annotate_sidecar`, 92 `preserve_description`,
23 `require_approval`. This reproduces P0's adapter-dependent result at scale
and on real data: the same tool lowers losslessly into two targets and needs
several guards in the third.

Those are the figures *after* the fix below. The first run of this probe
produced 268 / 92 / 92 - the 92 approval gates being the defect it found.

### Finding: `require_approval` fires on hint *presence*, not hint *value*

`require_approval` is synthesised for all 92 tools, but only **23** declare
`destructiveHint: true`. The other **69** are gated because they mention
`destructiveHint` at all - including tools that explicitly declare
`destructiveHint: false`.

Verified end to end. Lowering Linear's `get_issue`
(`readOnlyHint: true`, `destructiveHint: false`) into `crewai` emits:

```python
# G1: the source declared destructiveHint, which this framework cannot carry.
# The consequence is restored as an approval step.
@require_approval("declared destructive by its author")
@tool
def get_issue(**kwargs: object) -> object:
```

The decorator's justification string is false: the author declared this tool
*not* destructive. The generated comment is technically true - the hint was
declared - which is precisely the conflation at fault.

**Mechanism.** `SecurityAnnotations` documents that `None` and `False` must not
be conflated, and honours it: `declared()` returns a property when the hint is
*set*. But `_COMPENSATION` in `translate/lattice.py` maps
`DESTRUCTIVE -> REQUIRE_APPROVAL` on membership alone, and `translate/lower.py`
never reads `annotations.destructive`. So the value is discarded one layer below
the class that took care to preserve it. `plan_translation` receives a
`frozenset[SecurityProperty]` - a shape that cannot carry values - so this is a
signature-level limitation, not a missing conditional.

**Consequence.** A CrewAI scaffold for Linear puts a human approval gate on
`get_issue`, `list_teams`, `list_issues` and 66 others. Beyond the false
justification, an approval prompt on three quarters of a toolset is the
condition under which reviewers approve reflexively - so the gate that *does*
matter, on the 23 genuinely destructive tools, is worth less.

Note this is invisible to a fixture where every annotated tool is destructive,
which is why P0 did not catch it. It needed a corpus containing tools that
declare `destructiveHint: false`.

**Not fixed here.** The repair is a design decision - whether the lattice's
input becomes value-carrying, or `lower.py` filters on value before emitting -
and it changes G1's meaning for every existing entry.

### Secondary observation

`_BINDING_TEMPLATE` in `translate/lower.py` hardcodes
`from langchain_core.tools import tool` and a `@tool` decorator for *every*
target, so a `crewai` binding imports LangChain. CrewAI does accept LangChain
tools, so this may be deliberate; flagged rather than asserted as a defect,
since there is one template and no per-target variant.

### Resolution

Fixed by making the lattice's compensation value-aware
(`_VALUE_SENSITIVE_COMPENSATION` in `translate/lattice.py`).
`plan_translation` gained an optional `values` argument;
`UnifiedToolDescriptor.annotation_values()` supplies it, and `lower.py` passes
it. `DESTRUCTIVE` now compensates to `REQUIRE_APPROVAL` when asserted true and
to `ANNOTATE_SIDECAR` when asserted false.

`values` is optional and **fails closed**: a caller that omits it, or supplies
`None` (not declared), keeps the approval gate. Only an explicit `false`
downgrades one, so no caller can weaken a guard by forgetting an argument.
`declared()` was deliberately left alone - filtering it to true-valued hints
would have made `false` indistinguishable from *undeclared*, the exact
conflation `SecurityAnnotations` documents against, and would have silently
changed what family G audits through `lift.py`.

Effect on this corpus: `require_approval` drops from 92 to 23 - exactly the
count of tools declaring `destructiveHint: true` - and `annotate_sidecar` rises
by the same 69. Total guards are unchanged at 452: nothing was dropped, only
reclassified, so the "nothing degrades silently" invariant still holds.

Regression tests: `test_destructive_false_is_annotated_not_gated`,
`test_destructive_true_is_still_gated`,
`test_destructive_without_a_value_fails_closed` (tests/test_lattice.py) and
`test_a_tool_declared_not_destructive_is_not_approval_gated`,
`test_a_tool_declared_destructive_is_still_approval_gated`
(tests/test_lowering.py).
