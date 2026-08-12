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

`n ≈ 12–15` participants, each completing a subset of tasks in both conditions
with order counterbalanced. Runs only if ethics approval (P6) is granted in time;
the study does not depend on it. Recruitment criteria, consent text and the
analysis plan are fixed before the first session.

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
| — | none yet | — |

---

Citation `[P14]` refers to the reviewed literature set.
