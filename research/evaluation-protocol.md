# Evaluation protocol

**Pre-registration** · plan step P5 · written before any data is collected.

## Why this document exists first

Every measurement in this project is cheap to re-run and easy to shape after the
fact. Corpus membership, metric definitions and exclusion rules all admit
choices that could be made — unconsciously — to favour the tool being evaluated.

This document fixes those choices in advance. It is committed before collection
begins, and every departure from it is recorded in [Deviations](#deviations)
with a date and a reason. A result produced under a rule invented after seeing
the data is reported as exploratory, not confirmatory.

## Claims under test

| | Claim | Study | Falsified if |
| --- | --- | --- | --- |
| **RQ1** | The ecosystem's own setup guidance produces insecure configurations | 1 | Official guidance scores clean across families A and B |
| **RQ2** | Secure defaults cost no developer time | 2 | Setup with the tool is not faster, or the security delta is negligible |
| **RQ3** | Secure defaults cost no runtime | 3 | Scaffolded projects are measurably slower or more token-hungry |
| **RQ4** | Translation loses security properties, adapter-dependently | 4 | Loss is uniform across adapters, or absent |
| **RQ5** | Interception layers trade protection against latency, and both are measurable | 6 | One layer is both cheaper and blocks at least as much |

RQ4 is already supported by probe
[P0](probes/p0_translation_fidelity/), which is a pilot, not the study.

## Shared rules

**Snapshotting.** Every artifact fetched from the network — documentation page,
README, repository, registry entry — is stored with a retrieval timestamp and a
content hash. All analysis runs against the snapshot. Upstream changing mid-study
must not silently change a result.

**Versions.** Every tool, adapter, framework and model version used is recorded
with the run. Results are reported against those versions and are not claimed to
generalise beyond them.

**Reporting.** Effect sizes and intervals, not bare significance. Sample sizes
here are small enough that a p-value alone would be misleading. Per-task and
per-stratum figures are published alongside aggregates, because an aggregate can
hide a task the tool handles badly.

**Negative results.** A study that fails to support its claim is reported with
the same prominence as one that succeeds. The falsification column above is
binding.

---

## Study 1 — Posture of ecosystem setup guidance (RQ1)

Every finding here concerns an artefact this project does not own. What gets
reported to its maintainer, when, and what the paper is allowed to publish
about it — including the absolute rule that a live credential never appears in
a paper or a results file — is fixed in [`../DISCLOSURE.md`](../DISCLOSURE.md),
committed before this study's corpus was collected.

### Population

Four strata, each sampled and reported separately:

| Stratum | Definition |
| --- | --- |
| `official-docs` | Getting-started and quickstart pages from the frameworks in scope |
| `mcp-servers` | READMEs and example configurations of published MCP servers |
| `templates` | Public repositories presenting themselves as agent starters |
| `llm-generated` | Setups produced by prompting models with realistic setup tasks |

### Selection criteria — fixed in advance

**Include** a document or repository when it:

1. presents itself as a way to get an agent running, not as an API reference;
2. contains enough configuration to materialise a project — at minimum a
   provider credential step and a tool or MCP server binding;
3. is reachable without authentication or payment;
4. was updated within 18 months of the snapshot date.

**Exclude** when it:

1. targets a framework outside the study scope;
2. is a fork or near-duplicate of an already-included entry (by content hash of
   the configuration, not of the prose);
3. is authored by this project;
4. cannot be materialised into a project without inventing configuration the
   source did not specify. Exclusions of this kind are counted and reported —
   an ambiguous quickstart is itself a finding, and burying it would bias the
   sample toward the tidy ones.

**Sampling.** `mcp-servers` and `templates` are ranked by a popularity signal
recorded at snapshot time, and the top *N* are taken. *N* is fixed before
collection and reported. `official-docs` is a census of the frameworks in scope.

**`llm-generated`.** Prompts are drawn from the same task list as Study 2, so
the two studies remain comparable. Models are run locally where possible.
Sampling is *k* completions per prompt at a fixed temperature, all recorded.

### Procedure

1. Materialise each entry into a project directory, following its instructions
   literally and inventing nothing.
2. Run `toolseal audit --json`.
3. Record per-check verdicts, per-family scores, and the `blocking` flag.

Materialisation is the only judgement-laden step. It is performed to a written
rubric, and a 10% sample is independently re-materialised by a second person
with agreement reported.

### Metrics

- Per-family score distribution, by stratum.
- Per-check failure rate across the corpus — which specific defect is most
  common is more actionable than any aggregate.
- Proportion of entries with at least one `critical` finding.
- Comparison of `llm-generated` against `official-docs`, since models are
  trained on that guidance.

---

## Study 2 — Controlled with/without evaluation (RQ2)

This study is also the product demo, instrumented.

### Tasks

A fixed list of setup tasks, written before any measurement, spanning the v1
matrix: each supported provider, each supported framework, and MCP wiring.

The list must include **at least two tasks the tool handles poorly or not at
all**. A benchmark composed only of favourable cases measures nothing, and their
per-task results are reported rather than folded into an average.

### Conditions

| Arm | Operator | Instructions |
| --- | --- | --- |
| `manual` | Scripted agent | Official documentation only |
| `toolseal` | Scripted agent | The tool's own documentation |

Both arms run on a clean container image, fixed for the study, with no cached
package downloads and no pre-existing credentials.

The scripted arm is the primary measurement because it is reproducible and
re-runnable in CI. It is a **lower-bound proxy** for a human developer and is
reported as such. Agent transcripts are published.

### Human arm — secondary

**Status as of 2026-08-12: deferred, and likely to be dropped.** No participant
access is available, and whether an ethics committee is reachable for this
project is unresolved. The scripted arm is therefore the only planned
measurement for RQ2.

This is permitted by the design rather than a departure from it: the human arm
was specified as conditional from the outset. The consequence must be stated in
the write-up — the developer-experience result rests on an LLM agent following
documentation, which is a lower-bound proxy for a developer, and no
human-subjects data was collected.

Should access and approval both become available before week 19, the design
stands as originally specified: `n ≈ 12–15` participants, each completing a
subset of tasks in both conditions with order counterbalanced, and with
recruitment criteria, consent text and the analysis plan fixed before the first
session.

### Metrics

**Developer experience** — wall-clock time to a working agent, commands issued,
files created or edited, error-and-retry cycles.

**Security posture** — `toolseal audit` score per family, and `blocking`.

"Working agent" is defined before collection as: the process starts, connects to
the provider, and completes one tool-using exchange. A task that never reaches
this state is recorded as a failure with elapsed time, not discarded.

### Analysis

Paired per task. Report the per-task distribution and the aggregate; a single
task dominating the aggregate must be visible.

---

## Study 3 — Runtime cost of secure defaults (RQ3)

### Procedure

A scaffolded project and a naive equivalent — same provider, same framework,
same tools, differing only in configuration — run an identical fixed task set.

Compensating guards are enabled, since their cost is the point: the claim is
that configuration-time enforcement is cheaper than the runtime enforcement it
substitutes for.

### Metrics

End-to-end latency per tool call and per task, and token consumption. Repeated
runs with the distribution reported, not a single figure — provider latency is
noisy and a mean alone would overstate precision.

### Reference point

AgentWarden reports roughly 800 ms per call for runtime capability governance
[P14]. That figure is the comparison, quoted from the paper rather than
reproduced here; this study does not re-run their system.

---

## Study 4 — Translation fidelity at scale (RQ4)

Extends probe P0 from three tools and two adapters to the full matrix.

### Population

Abstractions: MCP, LangChain/LangGraph, CrewAI, OpenAI function calling,
Microsoft Agent Framework. Adapters: every maintained path between them.

Each `(adapter, version)` pair is a unit. Versions are pinned and recorded.

### Procedure

The P0 method, unchanged: a fixture server declares ground truth, each adapter
loads it, and the translated tool is compared property by property with verdicts
`preserved` / `dropped` / `mutated` / `unknown`.

The fixture is extended to cover properties P0 did not exercise — nested
schemas, arrays, optional fields, and error paths.

### Metrics

Loss rate per property per adapter. Whether compensating guards restore the
behaviour the target could not express, tested by invoking the generated binding
and observing whether the guard fires.

### Known limitation

The probe searches a fixed list of attribute names for annotation carriers, so
an adapter storing them somewhere unusual is scored as dropping them. The list
is `ANNOTATION_CARRIERS` in `probes/p0_translation_fidelity/probe.py` and grows
as adapters are added. Any `dropped` verdict for a newly added adapter is
manually confirmed against its source before publication.

---

## Study 6 — Security per millisecond (RQ5)

Pre-registered 2026-09-17, before any guard was measured against any case and
before the MCP proxy it compares against was built. Study 3 measured the cost of
a guard's bypass branch (see Deviations); this study measures enforcing paths
and, for the first time in this project, what each guard actually stops.

### Claims under test

| | Claim | Falsified if |
| --- | --- | --- |
| **H1** | The decorator layer adds less latency per enforcing call than the proxy layer | Decorator median ≥ proxy median |
| **H2** | The proxy layer blocks strictly more attack cases than the decorator layer | Proxy blocked count ≤ decorator blocked count |
| **H3** | The two layers trade off cost against protection | One layer is both cheaper **and** blocks at least as much. Then there is no curve, and the claim this programme rests on fails. |
| **H4** | Each decorator guard misses exactly the cases its own docstring says it misses | A case the suite declares `missed` is observed `blocked`, or the reverse |

H3's falsification condition is binding. A result showing no trade-off is
reported with the same prominence as one showing it.

### Metrics

**Added latency** is `t(guarded) − t(unguarded)` on identical inputs, in the same
process, with the same repeat count.

- Measured separately on the **enforcing** path and the **allowing** path. Never
  on a bypass: a run with `TOOLSEAL_ASSUME_YES` set is invalid for this study.
- Reported as median, p95 and p99. The mean is not the central estimate.
- Repeats: **1000** per measurement at microsecond scale, **200** at millisecond
  scale. Fixed here, not tuned afterwards.
- Tool bodies are trivial; provider latency is excluded.

**Protection** is judged by each case's declared observable, **not** by whether
the guard raised.

| Observable | Judged by |
| --- | --- |
| `side_effect` | A sentinel the tool body creates. Absent after the call → prevented. |
| `signal` | Whether failure reached the caller as an exception. |
| `log_content` | Whether the secret string appears in captured log output. |
| `child_env` | Whether a spawned child can read the secret. |

**A guard that raises after the side effect has happened has missed.**

| Case kind | Outcomes |
| --- | --- |
| attack | `blocked` · `missed` · `not_applicable` |
| benign | `allowed` · `false_block` · `not_applicable` |

A run-time error is `missed` for an attack unless the observable shows the effect
was also prevented, and `false_block` for a benign case.

**Reporting.** No single ratio is published. Each (layer, guard) is reported as
the point `(median added latency on the enforcing path, block rate, false-block
rate)`, with every per-case outcome alongside the aggregates.

### The attack suite

`research/studies/s6/attack-suite.toml`, validated by `bench/attack_suite.py` and
`tests/test_bench_attack_suite.py`, which enforce:

1. every guard has cases;
2. every guard has at least one attack expected `blocked` and one expected
   `missed` at the decorator layer;
3. every attack cites a checkable `mitre-atlas` technique;
4. case ids are unique and outcomes use the vocabulary for their kind;
5. benign cases exist;
6. the file's digest matches the one registered below.

Expected outcomes were declared from reading source, not from execution. Proxy
expectations are design commitments for a proxy not yet built.

**Registered suite.** `research/studies/s6/attack-suite.toml` sha256: `b97c79f46e98313288dd94850b40c1fa234a75879978ada28ba72ac64bfc3f49` (re-recorded 2026-10-12, comment-only; see Deviations)

### Baselines

Selected under `research/studies/s6/baseline-criteria.md`, committed before any
candidate was examined. The result is `research/studies/s6/baselines.toml`.

### Platforms

| Platform | Protection outcomes | Latency | Isolation |
| --- | --- | --- | --- |
| Windows, local machine | reported | primary | host |
| Linux, CI runner | reported | reported, lower-confidence | container |
| macOS, CI runner | reported | reported, lower-confidence | host |

Every result row records OS, Python version, runner type and toolseal commit.

---

## Threats to validity

| Threat | Mitigation |
| --- | --- |
| The taxonomy is authored by the same project it evaluates | Every check cites published work or a standard; the taxonomy is committed before the audit engine; an outside reviewer rates a sample of check-to-finding assignments |
| Materialisation of Study 1 entries is judgement-laden | Written rubric; 10% double-materialised with agreement reported; unmaterialisable entries counted, not dropped |
| Scripted agent is not a developer | Reported as a lower-bound proxy; human arm where possible; transcripts published |
| Corpus selection bias | Criteria pre-registered above; full corpus list published including exclusions |
| Task selection favours the tool | At least two adverse tasks required; per-task results always reported |
| Upstream drift during the study | Snapshot and hash everything; analyse from the snapshot |
| Small samples overstated | Effect sizes and intervals; no significance claims from underpowered comparisons |

---

## Deviations

Every departure from this protocol is recorded here with a date and a reason,
and any affected result is labelled exploratory.

| Date | Change | Reason |
| --- | --- | --- |
| 2026-08-19 | Study 1's `official-docs`, `mcp-servers` and `templates` strata run without the 10%-double-materialised agreement check this document's Procedure section requires. | No second person is available to this collection run. Recorded here rather than silently omitted; results from these strata are single-materialiser and reported as such. |
| 2026-08-19 | `mcp-servers` and `templates` use a fixed *N* = 6 (`research/studies/s1/selection-criteria.md`), smaller than an unqualified reading of "top *N*" might suggest. | *N* is chosen small enough for one person to materialise every entry carefully, per the mitigation above; a larger *N* would dilute rather than remove the single-materialiser limitation. |
| 2026-09-17 | Study 3's per-call guard figure (0.85 µs, and the 888888.9x ratio derived from it) is relabelled as the cost of the approval guard's **bypass branch**, and superseded by Study 6. | `bench/overhead.py::guard_overhead` measures `require_approval` with `TOOLSEAL_ASSUME_YES=1` set and logging disabled, so the timed path is an environment lookup, not a guard refusing a call. Found while pre-registering Study 6, which measures enforcing paths only. The figure stays published with its basis stated. |
| 2026-09-17 | Study 6 measurement conditions the registration left unspecified, added before any runner existed: (1) latency measured with the evidence channel off and on, the shipped default (on) primary; (2) `require_approval`'s allowing path is not measured - its only machine-reachable allow path is the `TOOLSEAL_ASSUME_YES` override this study forbids, and the interactive path is human reaction time; (3) `bound_runtime`'s enforcing path is reported as overshoot, t(guarded) minus the bound, with a 0.001 s bound and 0.01 s body at 200 repeats; (4) `minimal_environment` has a single path and is reported once; (5) latency percentiles are taken over paired per-repeat differences with the unguarded and guarded calls interleaved; (6) decorator-layer protection outcomes and H4 are published before the proxy exists, with H1-H3 left open. | The evidence channel (T4) runs inside each guard, so its cost is part of guard latency and the registration predates it. Items 2-4 are paths the registered definition cannot reach without contradicting another registered rule. No registered rule, case or expected outcome is changed; the suite digest is unchanged. |
| 2026-09-17 | **Exploratory, added after the first decorator-layer run.** A control is added to `bound_runtime`'s enforcing-path measurement: a bare `threading.Thread.join(timeout=bound)` on the same 0.01 s body with no guard, reported alongside the registered overshoot figure and as overshoot net of that control. The registered overshoot figure is still reported unchanged. | The first run reported a ~9 ms overshoot past a 0.001 s bound. Measured separately with no guard, a bare `join(timeout=0.001)` on the same Windows machine takes a median 8.2 ms, so the registered figure measures the platform's timer granularity rather than the guard. Because the control was chosen after seeing that result, anything derived from it is labelled exploratory, not confirmatory. |
| 2026-09-17 | **Exploratory, after the second run.** The `bound_runtime` control is judged resolved only when the guarded-minus-control median lies between 0 and half the registered overshoot; otherwise it is reported as inconclusive. `bound_runtime` is shown on its allowing path, not its timeout path, in the evidence-share view. | The second run's control produced -5775.55 us: the guarded timeout path apparently 5.8 ms faster than a bare join, which is impossible since the guard does strictly more work. Both arms are quantised to the Windows timer and the paired difference reflects tick alignment. Rather than publish that figure as a cost, or as the guard being "cheaper" as the first interpretation text did, the result is reported inconclusive. The threshold was chosen after seeing the data and is exploratory. |
| 2026-10-09 | **Exploratory.** Study 1's filename recovery (`bench/generated.py`, `bench/corpus.py`) now reads a name written as a comment on a block's first line (`# agent.py`), and its lookback stops at the end of the previous block. The `llm-generated` stratum is re-collected under the fix (same prompt, model, temperature and sample count; 18 completions over the current 6 tasks, where the first run had 12). Each row now records how many fenced blocks the completion had. The three network-collected strata are not re-collected. | The first run's 0 of 12 was written up as the model never naming a file. Re-sampling with the raw text kept showed `qwen2.5:3b` naming files on the block's first line in 17 of 18 completions, which the parser never read, and the lookback reading a command inside one block (`python3 main.py`) as the name of the next. The fix was made after the result was seen, so the re-collected stratum and Study 5's re-cut built on it are labelled exploratory, and the label is a field on both payloads. The network strata's upstream pages have changed since collection, so re-collecting would measure drift rather than the fix; on `templates`, whose content hashes are unchanged, the fixed recovery produced byte-identical files. |
| 2026-10-09 | Study 4 run. Population as run: seven units over four adapters (`langchain-mcp-adapters`, `crewai-tools`, `openai-agents` non-strict and strict, `agent-framework-core` plain and with FIDES labels) plus `langchain-core`'s `convert_to_openai_tool`; Windows only. Additions to the registered procedure, fixed before the committed run: (1) whether an invalid call left the client is judged from a call log the fixture writes before validating, not from error text; (2) a field the adapter made required counts as an `inputConstraints` loss in the lattice comparison; (3) `ANNOTATION_CARRIERS` gains `additional_properties`. **Exploratory, added after the first trial run:** `validate_against_schema` applied by hand (`direct.` rows), because the trial showed `lower()` never emits it for an MCP tool; and `uniqueItems` left unenforced by the fixture server, kept as found. | Items 1-3 make the registered metrics computable for adapters P0 did not cover. The `direct.` rows size a gap the trial revealed, so they are labelled exploratory and kept out of the loss-rate table; the fixture was not changed after the trial, because that would be tuning. |
| 2026-10-12 | Study 6's attack suite gains one trailing TOML comment, `# toolseal:allow A1 - ...`, on the `input` line of the provider-key redaction case, and its registered digest is re-recorded (previously c2056d79...8edf0, now b97c79f4...c3f49). No case, input value, observable, expected outcome or basis changes; the parsed suite is identical. | The release gate's self-audit (`toolseal audit .`) reports the case's fabricated `sk-live-...` input as a critical A1 credential literal and blocks every release. Suppression is line-level by design, so the line itself must carry it. The published decorator-layer results (`results-decorator.json`, `suite_sha256` c2056d79...) were produced against byte-identical cases and stand; any re-run records the new digest. |

---

Citation `[P14]` refers to the reviewed literature set.
