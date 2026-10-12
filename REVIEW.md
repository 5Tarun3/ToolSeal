# Reviewing toolseal

A guide for reading this repository from the start, and a status report on the
research components. Written for review before pushing 28 local commits.

**State at time of writing:** 881 tests passing, 5 skipped (the skips need a
running Ollama). `ruff`, `ruff format` and `mypy --strict` clean.
`toolseal audit .` scores 100/100 on itself, no findings.

> **Updated 2026-10-09.** The research rows below are brought up to date:
> Study 1's zero was a harness defect and is fixed (exploratory re-run, 12 of
> 18 materialised); Study 4 has run; Study 5 part (b) is delivered; the
> severity drift guard and the HIPAA source check are closed. Test counts and
> commit counts above are from the original writing and are not refreshed.

---

## 1. How to review, in order

The repository has a spine. Reading it in dependency order costs far less than
opening files alphabetically, because almost everything downstream is an
executable restatement of two documents.

### Step 0 — verify the claims before reading the code

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
uv run toolseal audit .          # the tool, on itself: expect 100/100
```

If those disagree with the paragraph above, stop and start there.

### Step 1 — the two normative documents

Everything else implements these. Read them first or the code will look arbitrary.

| Read | Why it comes first |
| --- | --- |
| `reference/taxonomy.md` | The 28 checks. Normative — the paper cites it. Note its "Rules for changing this document": ids are permanent, a rewritten check records the rewrite, severity changes need a stated reason. |
| `docs/superpowers/specs/2026-08-13-standards-compliance-policy-design.md` | The standards/compliance/policy design. §5 profiles, §6 relaxation, §8 the lock, §9 the UTD compliance block. |

`docs/` is gitignored, so the spec is local-only. That is worth a decision: the
paper cites it, and it currently exists on one machine.

### Step 2 — the policy core

This is where the research contribution lives. Read in this order:

```
core/policy/model.py       Check, Verdict, Finding, AuditReport, scoring
core/policy/controls.py    control catalogues (the standards mapping)
core/policy/coverage.py    the checks x controls matrix
core/policy/profile.py     the overlay engine (P44)
core/policy/relax.py       justified, expiring deviations (P44)
core/policy/lock.py        seal / verify (P48)
core/policy/family_*.py    the 28 checks themselves
```

**Three scoring decisions carry the argument.** Verify each survived:

- `Verdict.UNKNOWN` is distinct from `PASS`. "We did not look" must never be
  reported as "we looked and it was fine."
- Inapplicable checks leave the denominator. A project with no remote endpoint
  is not penalised for family D.
- `blocking` is reported *apart* from the score, because a severity-weighted
  average can hide one critical finding behind a long tail of passes.
  `relaxed_critical` was added alongside it for the same reason.

### Step 3 — the rest of the engine

```
core/audit/extract.py      files -> ProjectModel  (the trust boundary)
core/audit/engine.py       runs checks; a raising check becomes UNKNOWN, not silence
core/registry/utd.py       the Unified Tool Descriptor + compliance block
core/translate/lattice.py  what each abstraction can express
core/translate/lower.py    guard synthesis - contribution C5
core/injection.py          hash-verified managed files, reversible
```

### Step 4 — the surface

`cli/` is deliberately thin: it formats and exits. If you find computation
there, that is a finding.

### Step 5 — the evidence

```
research/evaluation-protocol.md
research/probes/p0_translation_fidelity/     the falsification probe
research/studies/s1|s2|s3|s5/RESULTS.md
```

### Step 6 — read the tests as specification

Three carry unusual weight:

| Test | What it pins |
| --- | --- |
| `tests/test_executable_guards.py` | Guards are **executed**, not read. A generated binding that imports something undefined looks fine until run. |
| `tests/test_control_mapping.py` | Row-level drift guard: `reference/taxonomy.md` and the code must agree in **both** directions. Proven able to fail against misattribution, stale rows and fabrication. |
| `tests/test_gate_vertical_slice.py` | End-to-end: scaffold produces a project that scores clean. |

---

## 2. What the repository is

```mermaid
flowchart TB
    subgraph docs["Normative documents"]
        TAX["reference/taxonomy.md<br/>28 checks"]
        SPEC["design spec<br/>profiles, lock, UTD"]
    end

    subgraph core["core/"]
        POL["policy/<br/>checks, profiles,<br/>relaxation, lock"]
        AUD["audit/<br/>extract + engine"]
        REG["registry/<br/>UTD, index, resolve"]
        TRA["translate/<br/>lattice, lift, lower"]
        SCA["scaffold + injection<br/>+ credentials"]
    end

    subgraph out["Surfaces"]
        CLI["cli/<br/>thin: format and exit"]
        RES["research/<br/>studies + probe"]
    end

    TAX -->|executable form| POL
    SPEC -->|executable form| POL
    AUD --> POL
    REG --> TRA
    TRA -->|guards| SCA
    POL --> CLI
    AUD --> CLI
    REG --> CLI
    POL --> RES
```

### The three pillars, and what cuts across them

```mermaid
flowchart LR
    INIT["init / add<br/>SCAFFOLD"] --> PROJ["a project"]
    REGI["search / add tool<br/>REGISTRY"] --> LOWER["lower + guards<br/>TRANSLATE"]
    LOWER --> PROJ
    PROJ --> AUDIT["audit<br/>28 checks"]
    AUDIT --> REPORT["terminal | JSON | SARIF"]
    POLICY["policy<br/>explain / profiles / lock"] -.governs.-> AUDIT
    POLICY -.governs.-> LOWER
```

`init`/`add` **always** emit the secure configuration — there is no insecure
path to opt into. `audit` is advisory: findings, scores, never a block. That
asymmetry is deliberate and load-bearing for the DX claim.

### How a check reaches a verdict

```mermaid
flowchart TB
    FILES["project files"] --> EX["extract.py"]
    EX --> PM["ProjectModel"]
    PROF["profile resolution<br/>severities, relaxations"] --> CHECKS["modified check set"]
    BASE["28 baseline checks"] --> CHECKS
    PM --> ENG["engine.audit_model"]
    CHECKS --> ENG
    ENG --> V{"verdict"}
    V --> P["PASS"]
    V --> F["FAIL"]
    V --> NA["NOT_APPLICABLE<br/>leaves denominator"]
    V --> U["UNKNOWN<br/>could not look"]
    V --> R["RELAXED<br/>justified + expiring"]
```

The engine never learns that profiles exist. Resolution happens above it and
hands it a modified check set. That boundary is asserted by test.

---

## 3. Paper components: status and inference

### Contributions

| | Contribution | Status | Evidence |
| --- | --- | --- | --- |
| **C1** | Taxonomy of agent **configuration** misconfigurations | **Done** | `reference/taxonomy.md`, 28 checks, 7 families, every check citing an external control |
| **C2** | First measurement of setup-guidance security posture | **Done, partly exploratory** | Study 1, all four strata; `llm-generated` 12 of 18 materialised, mean 47.7, labelled exploratory |
| **C3** | toolseal itself: scaffolder, registry, auditor | **Done** | 881 tests; self-audit 100/100 |
| **C4** | Secure defaults are free in DX and runtime | **Done** | Studies 2 and 3 |
| **C5** | Expressiveness lattice + compensating guards | **Done, with measured gaps** | Study 4: seven units; two lattice entries wrong; the validation guard is never emitted for an MCP tool and covers flat schemas only |
| **C6** | Control mapping from taxonomy to published standards | **Done** | Study 5 |

### What each result actually says

**Study 2 — the DX claim, and it is strong.**
Manual mean audit score **8.0**; toolseal **100.0**. Manual **10 steps**;
toolseal **2**. Four of six manual projects carry a critical finding.

*Inference:* secure defaults cost nothing in setup effort — they cost less. The
manual arm is an **idealised** quickstart (no typos, no debugging), so it is a
**lower bound** on manual effort, which makes the advantage a conservative
estimate. The two adverse tasks are refusals, which is the correct behaviour
and is reported rather than hidden.

**Study 3 — the runtime claim, and it needs careful wording.**
A compensating guard costs **0.85 µs** per call. AgentWarden reports ~800 ms
per call for runtime capability governance.

*Inference:* properties knowable at configuration time do not need re-deriving
on every call. The ~888,000× ratio is **indicative, not like-for-like** —
AgentWarden's 800 ms buys a learned, task-aware policy; a guard reinstates one
declared property. The results file says so itself, and two tests exist to stop
the bare ratio being quoted. **Keep that discipline in the paper.**

**Study 1 — the negative was the harness.**
The first run reported 12 completions from `qwen2.5:3b`, **0 materialised**, and
this section read it as an instruction-following result. It was a parser
defect: the model named its files as a first-line comment (`# agent.py`), which
filename recovery never read. Fixed and re-run: **12 of 18 materialised, mean
47.7**, every one failing `A4`, `E2`, `E3`, `F1`.

*Inference:* a small local model reproduces the same insecure defaults the
ecosystem's guidance does. Because the fix followed the result, the stratum is
labelled exploratory. The lesson stands in a different form: exclusions being
counted is what made the zero visible, and identical exclusion strings are what
hid its cause - rows now record how many blocks each completion had.

**Study 4 — loss is adapter-dependent, and so is enforcement.**
Seven units over four adapters. Only `langchain-mcp-adapters` carries the
annotation hints. `crewai-tools` validates client-side but loses array and
nullable constraints; the others send every invalid call to the server. The
lattice is wrong about CrewAI's input constraints and strict-mode OpenAI's
required sets, and `lower()` never emits the validation guard for an MCP tool.
See `research/studies/s4/README.md`.

**Study 5 — coverage, with the denominator kept honest.**

| standard | coverage | note |
| --- | --- | --- |
| `owasp-llm-top10` | 5/5 = 100% | complete enumeration |
| `owasp-agentic-top10` | 5/5 = 100% | complete enumeration |
| `owasp-agentic-threats` | 6/6 = 100% | complete enumeration |
| `nist-ai-rmf` | 4/5 = 80% | **curated subset** (~7 of 70) |
| `iso-42001` | 1/3 = 33% | **curated subset** (~4 of 36) |

0 of 28 checks unmapped. Uncovered and named: `A.6.2.2`, `A.6.2.4`, `MANAGE-2.2`.

*Inference:* the three complete enumerations measure real reach. The two marked
subsets measure **which controls were shortlisted**, not the taxonomy's reach —
their files were drawn up before any mapping existed. `complete_enumeration` is
a field on the data, not a footnote, so the distinction travels into any table.
Coverage also counts *citations*, not adequacy. Both caveats are printed by
`toolseal policy list` and stated in the study.

### Still to do for the paper

| Item | Blocks | Note |
| --- | --- | --- |
| ~~**Study 4**~~ | C5's empirical half | **Done 2026-10-09**, Windows only. Its findings are product changes still to make (see §5) |
| ~~**Study 1 re-run**~~ | C2 | **Done 2026-10-09**; the model was capable, the parser was not. Exploratory |
| **P38** coordinated disclosure | Study 1 on third-party repos | Must exist **before** auditing others' code, not after |
| **P37 / P41** write-up, then reconcile every claim against measured evidence | — | P41 is the step that catches overclaims |
| **Externally review the mapping** | C1, C6 | The drift guard proves document and code agree; nothing proves either is *right* |
| ~~**HIPAA URL**~~ | C6 | **Done 2026-10-09**: verified against eCFR's versioner API, quotations verbatim |

---

## 4. Methodology: what is done and how

### The evaluation spine

```mermaid
flowchart LR
    P0["P0 probe<br/>falsification, week 1"] -->|gates| C5["C5 + family G"]
    S1["Study 1<br/>corpus audit"] --> C2
    S2["Study 2<br/>with/without"] --> C4
    S3["Study 3<br/>runtime cost"] --> C4
    S4["Study 4<br/>translation at scale"] --> C5
    S5["Study 5<br/>coverage"] --> C6
```

### How each was done

**P0 — falsification first.** Before building anything that depended on it, the
hypothesis "adapters drop MCP security metadata" was tested. It came back
**half-false**: `langchain-mcp-adapters` preserves all 15 annotation
properties; `crewai-tools` drops all 15. The claim was reframed to
*loss is adapter-dependent, not inherent* — a sharper claim, and the reason
compensating guards are possible at all.

**Study 2 — scripted, not human.** An idealised manual baseline is generated
from what the official quickstarts actually instruct, then both arms are
audited by the same engine. No human arm (deliberately dropped). The idealised
baseline is the methodological choice that makes the result conservative.

**Study 3 — median, not mean.** An early version reported a mean, and a single
scheduler hiccup dragged it past 1 ms against a ~14 µs signal. Switched to
median with p95 reported alongside. Provider latency is excluded deliberately:
a model round trip would hide a microsecond-scale difference and produce a
meaningless null.

**Study 5 — generated, not typed.** Every number comes from
`uv run python -m bench s5`, so the study regenerates when the mapping changes.

### Methodological habits worth preserving

These are why the numbers can be trusted, and each was earned by fixing a
specific failure:

1. **Falsify before building.** P0 ran in week 1 and gated C5.
2. **Execute, do not read.** Guards are run, not inspected — a generated
   binding that imports something undefined looks fine on the page.
3. **Report the negative.** Study 1's zero was published as a result - and because it was published rather than dropped, it could later be traced to a harness defect.
4. **Keep the denominator honest.** `complete_enumeration`, inapplicable checks
   leaving the denominator, `UNKNOWN` distinct from `PASS`.
5. **Make the caveat structural.** A field on the data, not a sentence in a
   docstring, because only the field survives being copied into a table.
6. **Prove the guard can fail.** The drift guard was rebuilt row-level and
   verified against misattribution, stale rows and fabrication.

### What is left, and how it should be done

| Left | Method it should follow |
| --- | --- |
| **Study 4 on Linux and macOS** | Same runner (`python -m bench s4`); a different platform is a different unit, reported alongside, never merged |
| **Study 4's product fixes** | Each its own change, measured again afterwards, so the published numbers keep describing the code they measured |
| **P16 registry seeding** | Curation criteria fixed **in writing before** seeding — the plan's own mitigation against curating and then auditing our own entries |
| **P40 demo rehearsal** | Twice, on genuinely fresh machines, recorded as fallback |

---

## 5. Known open items

| Item | Kind | Where |
| --- | --- | --- |
| `MANAGE-2.2` uncovered | Real mapping gap | Study 5 names it |
| `B4` extended rather than adding `B6` | Judgment call | P46; preserved the 28-check invariant |
| `data_classes` has no automatic producer | Deliberate | Deriving it from hostnames would be the heuristic inference the spec forbids |
| ~~Severity drift unguarded~~ | Done (T2) | The drift guard now compares severities; `C2` is a named exemption |
| `docs/` is gitignored | Decision needed | The paper cites specs that exist on one machine only |
| Study 4's product findings | C5 | Validation guard unreachable from MCP and flat-only; CrewAI and `openai_fc` lattice entries; no agent-framework profile; bindings always import `langchain_core` |

---

## 6. Fast path if you only have an hour

1. `uv run pytest` and `uv run toolseal audit .` — check the claims hold.
2. `reference/taxonomy.md` — the whole argument in one file.
3. `core/policy/model.py` — scoring semantics; the three decisions in §1 Step 2.
4. `tests/test_executable_guards.py` and `tests/test_control_mapping.py` — the
   two tests that keep the rest honest.
5. `research/studies/s2/RESULTS.md` and `s3/RESULTS.md` — the headline numbers.
6. `git log --oneline origin/main..HEAD` — the 28 commits awaiting push.
