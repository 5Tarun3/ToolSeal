# Configuration misconfiguration taxonomy

**Version 1** · plan step P1 · the authoritative definition of what `toolseal audit`
detects and what `toolseal init` / `toolseal add` prevent.

## What this is

Agent security failures are largely configuration failures. Configuration is
written once, at setup, usually by copying a quickstart, and rarely revisited.
This document enumerates the defects that get written in that moment.

Every check carries a **remediation that the scaffolder applies automatically**.
That is the point of pairing them: the taxonomy is not a list of complaints, it
is the specification for what a secure default looks like. A check with no
automatic remediation is a check that should not exist yet.

Each entry states its **grounding** — the published work or standard it derives
from. A check that cannot cite a reason to exist is an opinion, and opinions do
not belong in a security baseline.

## Severity and scoring

| Severity | Weight | Meaning |
| --- | ---: | --- |
| `critical` | 10 | Directly exploitable, or discloses a credential |
| `high` | 6 | Materially widens the attack surface |
| `medium` | 3 | Weakens defence in depth |
| `low` | 1 | Hygiene; matters in aggregate |

Every check evaluates to `pass`, `fail`, or `not_applicable`. Checks that cannot
apply are excluded from the denominator — a project with no MCP servers is not
penalised for family D.

```
family_score = 100 × (1 − Σ weight(failed) / Σ weight(applicable))
overall      = severity-weighted pass rate across all applicable checks
blocking     = true if any applicable check of severity `critical` failed
```

Scores are **always reported per family** alongside the overall figure, and
`blocking` is reported separately. A single number must never be able to hide a
critical finding behind a long tail of passes.

`audit` reports; it does not block. The exit-code contract carries the outcome:
`0` clean, `1` findings present.

---

## Family A — Credential exposure

Credentials are the highest-value target in an agent project and the thing
quickstarts handle worst. Every mainstream getting-started guide instructs the
reader to paste a live API key into a plaintext file.

| ID | Check | Severity |
| --- | --- | --- |
| `A1` | Credential literal in tracked source or configuration | `critical` |
| `A2` | Secret-bearing file tracked by version control, or missing ignore rule | `high` |
| `A3` | One credential shared across providers or environments | `medium` |
| `A4` | Credential reachable in logs or error output | `high` |
| `A5` | Credential embedded in a child process's declared environment | `high` |

**A1 — Credential literal in tracked source or configuration**
*Detects:* known credential shapes (`sk-`, `sk-ant-`, `ghp_`, `AKIA`, `xoxb-`,
PEM private key headers) and high-entropy string assignments to
credential-named keys, in files tracked by version control.
*Remediates:* provision the credential into the OS keychain; generated config
references it by name rather than value; emit `.env.example` carrying
placeholders only.
*Grounding:* OWASP LLM02 Sensitive Information Disclosure; secret detection in
SkillSpector [P13]; standard practice (Gitleaks, TruffleHog).

**A2 — Secret-bearing file tracked, or missing ignore rule**
*Detects:* a `.env`, `credentials.json` or equivalent that is tracked, or absent
from `.gitignore` while present on disk.
*Remediates:* write the ignore rules and install a `detect-private-key`
pre-commit hook at scaffold time.
*Grounding:* OWASP LLM02; MalOSS on credential leakage as a supply-chain
vector [P10].

**A3 — One credential shared across providers or environments**
*Detects:* a single variable serving more than one provider, or no separation
between development and production credential sources.
*Remediates:* per-provider named keychain entries and distinct profiles.
*Grounding:* least privilege; blast-radius containment [P1].

**A4 — Credential reachable in logs or error output**
*Detects:* logging configured without a redaction filter; debug or verbose modes
that serialise configuration; provider clients constructed with request logging
enabled.
*Remediates:* install a redaction filter in the generated project, mirroring the
one `toolseal` applies to itself.
*Grounding:* OWASP LLM02. `toolseal` applies this check to its own logging.

**A5 — Credential embedded in a child process's declared environment**
*Detects:* an MCP server entry whose `env` block carries literal key material —
the dominant pattern in published `mcp.json` examples.
*Remediates:* emit an indirection that resolves the value from the keychain at
launch, so the config file itself holds no secret.
*Grounding:* OWASP LLM02; gateway and provenance controls [P1].

---

## Family B — Capability overprovisioning

AgentWarden measures **15× overprovisioning** in default agent runtimes and
spends a learned policy plus roughly 800 ms per call correcting it at
runtime [P14]. That overprovisioning is a default, and defaults are written
here. This family exists to delete the problem at configuration time instead.

| ID | Check | Severity |
| --- | --- | --- |
| `B1` | All tools bound to every agent or session unconditionally | `high` |
| `B2` | Shell or code-execution capability present without declared justification | `critical` |
| `B3` | Filesystem capability with unbounded or home-directory root | `high` |
| `B4` | MCP server granted scope wider than the declared task | `medium` |
| `B5` | Tool set resolved dynamically with no allowlist | `medium` |

**B1 — All tools bound unconditionally**
*Detects:* agent construction passing the complete tool collection rather than a
task-scoped subset.
*Remediates:* scaffold binds an explicit per-agent tool list.
*Grounding:* [P14] Skill Economy Ratio; OWASP Agentic — Excessive Agency.

**B2 — Shell or code execution without declared justification**
*Detects:* a shell, `exec`, or arbitrary-code tool in the tool set with no
corresponding justification entry in project configuration.
*Remediates:* the scaffold never includes one by default; adding one requires an
explicit justification field that the audit then reads.
*Grounding:* OWASP Agentic — Excessive Agency; dangerous-API analysis [P8, P10].

**B3 — Filesystem capability with unbounded root**
*Detects:* a filesystem tool or MCP server rooted at `/`, `~`, or the user
profile.
*Remediates:* scaffold roots filesystem access at the project workspace.
*Grounding:* least privilege; over-privileged capability auditing [S4].

**B4 — MCP server scoped wider than the declared task**
*Detects:* the server's advertised capability set exceeds what the project
declares it for.
*Remediates:* record the intended scope at `add` time and narrow the launch
configuration to match.
*Grounding:* [P14]; [S4].

**B5 — Tool set resolved dynamically with no allowlist**
*Detects:* tools discovered at runtime from a server or registry with no
pinned allowlist, so the available set can change without a code change.
*Remediates:* scaffold writes a resolved allowlist; drift is then visible as a
diff rather than silent.
*Grounding:* dynamic discovery as a governance gap [P1]; rug-pull risk.

---

## Family C — Supply-chain integrity

The mature part of the problem. These checks integrate existing tooling rather
than reimplementing it; the contribution is that they run at configuration time,
where the decision is actually made.

| ID | Check | Severity |
| --- | --- | --- |
| `C1` | Dependencies unpinned, or no lockfile | `high` |
| `C2` | Dependency carrying a known advisory | inherited |
| `C3` | Unverified package or MCP server name | `critical` |
| `C4` | Install from an unverified source | `high` |
| `C5` | No SBOM | `low` |

**C1 — Unpinned dependencies**
*Detects:* any dependency declared with an unconstrained specifier; or the
absence of both a lockfile **and** a fully pinned dependency set.
*Remediates:* the scaffold pins every direct dependency to the exact version the
cell was verified against.
*Grounding:* dependency-challenge catalogue [P6]; reproducible builds [P7].

> **Refined 2026-08-12.** Originally "absent lockfile, **or** unconstrained
> specifiers", which reported a finding against a fully `==`-pinned project that
> had no separate lockfile. A fully pinned set already reproduces the direct
> dependency graph, which is what the lockfile requirement exists for. It
> remains weaker than hash pinning, since transitive versions still float, so
> the recommendation stands — but on its own it is no longer a finding. Recorded
> per rule 3.

**C2 — Dependency carrying a known advisory**
*Detects:* resolved dependency set queried against OSV.
*Remediates:* prefer a patched version at scaffold time; report otherwise.
*Severity:* inherited from the advisory rather than fixed.
*Grounding:* [P9]; [P11] names transitive supply chain as its own gap.

**C3 — Unverified package or MCP server name**
*Detects:* a name that resolves nowhere (**phantom**), or resolves to a
near-miss of an established name or a different owner (**lookalike**).
*Remediates:* resolution is checked against the official MCP registry and
package indexes before install; unverified names are refused by `add`.
*Grounding:* slopsquatting [P5], which names *"no real-time package-existence
validation in coding tools"* as an open gap. This is the ToolGate component.
*Evaluated at* both `add` time (refusing an unverified name outright) *and*
`audit` time — a project `toolseal` did not scaffold gets every declared
dependency resolved and classified. Dependencies are resolved against PyPI
only, since extraction only ever produces Python dependencies; querying npm
first (a much larger namespace) would let a hallucinated name that happens to
collide with an unrelated npm package come back "verified". An unreachable
registry reports `unknown`, never a pass.
*MCP servers:* `MCPServerBinding.name` is the local alias under which a server
is keyed in `mcpServers` (the JSON object key), not the package that gets
installed — the package is a token in `args`. `audit` extracts it from an
npx-style invocation (the argument after `-y` or `--package`) and resolves
*that*, against npm, since MCP server packages are npm-published; the config
key itself is never resolved. When no such flag is present, the package name
cannot be determined from static config and that server is not resolved — a
scope limitation, not a guess.
*Limitation:* lookalike detection depends on a shipped list of established
names (`src/toolseal/data/known_packages.toml`); a typosquat of a name absent
from that list reads as phantom if unregistered, and is missed entirely if the
squatter registered it. Phantom detection needs no list and is unaffected.

**C4 — Install from an unverified source**
*Detects:* `curl | bash`, a floating git ref, a plain-HTTP source, or any
install path without an integrity check.
*Remediates:* scaffold installs from indexed, integrity-checked sources only.
*Grounding:* [P10]; SLSA and in-toto provenance [P7].

**C5 — No SBOM**
*Detects:* no CycloneDX or SPDX document for the project.
*Remediates:* generate one at scaffold time and refresh it on dependency change.
*Grounding:* [P4] on AIBOM as security assurance; [P7].

---

## Family D — Transport and endpoint

Applies only to projects that talk to a remote MCP server or a non-default
provider endpoint.

| ID | Check | Severity |
| --- | --- | --- |
| `D1` | Remote MCP endpoint over a non-TLS transport | `critical` |
| `D2` | Remote MCP server reached without authentication | `high` |
| `D3` | Provider base URL overridden to a non-default host | `high` |

**D1 — Non-TLS remote endpoint**
*Detects:* an `http://` MCP endpoint that is not loopback.
*Remediates:* scaffold refuses to write a non-TLS remote endpoint.
*Grounding:* [P1] on gateway transport security.

**D2 — Unauthenticated remote server**
*Detects:* a remote server entry carrying no authentication material or scheme.
*Remediates:* `add` requires an auth mechanism for remote servers.
*Grounding:* [P1] control layer; [P2] Zero Trust Agentic Access.

**D3 — Provider base URL overridden**
*Detects:* a provider client pointed at a host other than the vendor default —
the mechanism by which traffic, including credentials, is silently proxied.
*Remediates:* scaffold writes vendor defaults; an override must be declared.
*Grounding:* OWASP LLM03 Supply Chain; [P1].

---

## Family E — Execution containment

These are *configuration* checks — whether isolation is configured — not runtime
enforcement. Runtime enforcement is out of scope and covered by [P12] and [P14].

| ID | Check | Severity |
| --- | --- | --- |
| `E1` | Code-execution capability with no configured isolation | `critical` |
| `E2` | Agent inherits ambient host credentials | `high` |
| `E3` | No timeout or resource bound on tool calls | `medium` |

**E1 — Code execution with no isolation**
*Detects:* a code-execution tool with no container, sandbox or restricted
interpreter configured.
*Remediates:* scaffold does not include one; adding one requires an isolation
setting.
*Grounding:* [P1] execution layer; [P10] sandboxing.

**E2 — Ambient host credentials**
*Detects:* the agent process inheriting cloud CLI profiles, SSH agent sockets,
or a full environment copy.
*Remediates:* scaffold launches with an explicit, minimal environment.
*Grounding:* least privilege; confused-deputy exposure [P1].

**E3 — No timeout or resource bound**
*Detects:* tool invocation configured without a timeout or call budget.
*Remediates:* scaffold writes defaults.
*Grounding:* OWASP LLM10 Unbounded Consumption.

---

## Family G — Translation integrity

*(Family F follows; G is presented here because it derives directly from
measurement.)*

Grounded in probe **P0**, which measured what
[`langchain-mcp-adapters`](../research/probes/p0_translation_fidelity/) and
`crewai-tools` preserve. The headline result: **loss is adapter-dependent**. The
same MCP server loaded into two frameworks produces tools with different
security posture. Because the loss is not inherent, it can be compensated.

| ID | Check | Severity | P0 status |
| --- | --- | --- | --- |
| `G1` | Security annotation dropped in translation | `high` | confirmed (CrewAI) |
| `G2` | Constraint declared but not enforced client-side | `medium` | rewritten |
| `G3` | Error result indistinguishable from success | `medium` | confirmed |
| `G4` | Unexpressible property with no compensating guard | `high` | grounded |
| `G5` | Tool description mutated in translation | `medium` | confirmed (CrewAI) |

**G1 — Annotation dropped**
*Detects:* an MCP annotation hint (`readOnlyHint`, `destructiveHint`,
`idempotentHint`, `openWorldHint`) present at source but absent on the
translated tool.
*Remediates:* emit a compensating guard — a `destructiveHint` that a target
cannot carry becomes an approval wrapper — and record the substitution.
*Measured:* `crewai-tools` drops all 15 annotation properties; `CrewAIMCPTool`
exposes no carrier. `langchain-mcp-adapters` preserves them on `.metadata`.

**G2 — Constraint declared but not enforced client-side**
*Detects:* schema constraints present on the translated tool but not validated
before dispatch.
*Remediates:* generated bindings validate against the declared schema locally.
*Measured:* neither adapter rejects a schema-violating call; the invalid call is
sent and the server rejects it. Constraints survive translation, so the original
wording of this check — that constraints are *lost* — was wrong and has been
rewritten to target enforcement.

**G3 — Error result indistinguishable from success**
*Detects:* an MCP `isError` result surfaced as ordinary tool content.
*Remediates:* generated bindings map error results onto the framework's failure
channel.
*Measured:* rejected calls return content beginning `Error executing tool …`
rather than raising. Failure is not programmatically distinguishable from
success without parsing prose.

**G4 — Unexpressible property with no compensating guard**
*Detects:* the expressiveness lattice marks a property as unrepresentable in the
target, and no guard was emitted.
*Remediates:* guard synthesis; a `compensated` status in the manifest.

**G5 — Description mutated in translation**
*Detects:* the translated description is not the author's text verbatim.
*Remediates:* record the mutation in the compensation manifest so the text the
model actually reads is auditable.
*Measured:* `crewai-tools` prepends `Tool Name:` and a serialised copy of the
argument schema to every description. The description is what reaches the
model's context, so this changes what the model reads.

---

## Family F — Accountability

| ID | Check | Severity |
| --- | --- | --- |
| `F1` | No audit log of tool invocations | `medium` |
| `F2` | No approval gate on destructive operations | `high` |

**F1 — No tool-invocation audit log**
*Detects:* no logging of tool calls and outcomes.
*Remediates:* scaffold configures structured invocation logging, with the
credential redaction filter applied.
*Grounding:* [P2] Agent Visibility and Control; [P1] governance layer.

**F2 — No approval gate on destructive operations**
*Detects:* a tool marked destructive — by annotation or by capability inference
— reachable with no human confirmation step.
*Remediates:* scaffold wraps destructive tools in an approval step. This is the
same mechanism G1 uses as its compensating guard, which is why `destructiveHint`
surviving translation matters.
*Grounding:* [P1] DLP and inline policy; OWASP Agentic — Excessive Agency.

---

## Control mapping

Every check cites the published obligations it bears on. The mapping is held in
the check definitions and verified against the shipped catalogues by
`tests/test_control_mapping.py`, so this table and the code cannot drift apart.

Catalogues: `owasp-llm-top10`, `owasp-agentic-threats`, `owasp-agentic-top10`,
`nist-ai-rmf`, `iso-42001` (clause identifiers only; the standard is paywalled
and its text is not reproduced).

The two agentic catalogues are different documents, not two names for one.
`owasp-agentic-threats` holds the `T1`–`T15` taxonomy from *Agentic AI – Threats
and Mitigations* (v1.0, February 2025); `owasp-agentic-top10` holds the ranked
`ASI01`–`ASI10` list from *OWASP Top 10 for Agentic Applications* (December
2025). Conflating them is the mistake this table exists to prevent.

| Check | Controls |
| --- | --- |
| `A1` | owasp-llm-top10:LLM02 · owasp-agentic-threats:T3 · owasp-agentic-top10:ASI03 |
| `A2` | owasp-llm-top10:LLM02 · owasp-agentic-top10:ASI03 |
| `A3` | owasp-llm-top10:LLM02 · owasp-agentic-threats:T3 · owasp-agentic-top10:ASI03 |
| `A4` | owasp-llm-top10:LLM02 · owasp-agentic-top10:ASI03 |
| `A5` | owasp-llm-top10:LLM02 · owasp-agentic-threats:T3 · owasp-agentic-top10:ASI03 |
| `B1` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T2 · owasp-agentic-top10:ASI02 |
| `B2` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T11 · owasp-agentic-top10:ASI05 |
| `B3` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T3 · owasp-agentic-top10:ASI03 |
| `B4` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T3 · owasp-agentic-top10:ASI02 |
| `B5` | owasp-llm-top10:LLM03 · owasp-agentic-threats:T2 · nist-ai-rmf:GOVERN-6.1 · owasp-agentic-top10:ASI04 |
| `C1` | owasp-llm-top10:LLM03 · nist-ai-rmf:GOVERN-6.1 · owasp-agentic-top10:ASI04 |
| `C2` | owasp-llm-top10:LLM03 · nist-ai-rmf:MAP-4.1 · owasp-agentic-top10:ASI04 |
| `C3` | owasp-llm-top10:LLM03 · owasp-agentic-threats:T9 · nist-ai-rmf:GOVERN-6.1 · owasp-agentic-top10:ASI04 |
| `C4` | owasp-llm-top10:LLM03 · nist-ai-rmf:GOVERN-6.1 · owasp-agentic-top10:ASI04 |
| `C5` | owasp-llm-top10:LLM03 · iso-42001:A.10.3 · owasp-agentic-top10:ASI04 |
| `D1` | owasp-llm-top10:LLM02 · owasp-agentic-threats:T9 · owasp-agentic-top10:ASI07 |
| `D2` | owasp-llm-top10:LLM03 · owasp-agentic-threats:T9 · owasp-agentic-top10:ASI07 · owasp-agentic-top10:ASI03 |
| `D3` | owasp-llm-top10:LLM03 · owasp-llm-top10:LLM02 · owasp-agentic-top10:ASI04 |
| `E1` | owasp-llm-top10:LLM05 · owasp-agentic-threats:T11 · owasp-agentic-top10:ASI05 |
| `E2` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T3 · owasp-agentic-top10:ASI03 |
| `E3` | owasp-llm-top10:LLM10 · owasp-agentic-threats:T4 · owasp-agentic-top10:ASI02 |
| `F1` | owasp-agentic-threats:T8 · owasp-agentic-top10:ASI08 · owasp-agentic-top10:ASI09 · nist-ai-rmf:MANAGE-4.1 |
| `F2` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T2 · owasp-agentic-top10:ASI02 |
| `G1` | owasp-llm-top10:LLM06 · owasp-agentic-threats:T2 · owasp-agentic-top10:ASI02 |
| `G2` | owasp-llm-top10:LLM05 · owasp-agentic-threats:T2 · owasp-agentic-top10:ASI02 |
| `G3` | owasp-llm-top10:LLM05 |
| `G4` | owasp-llm-top10:LLM06 · nist-ai-rmf:MEASURE-2.7 · owasp-agentic-top10:ASI02 |
| `G5` | owasp-llm-top10:LLM01 · nist-ai-rmf:MEASURE-2.7 · owasp-agentic-top10:ASI01 |

**`F1` has no *checkable* home in either ranked Top 10.** The OWASP Agentic AI
threat taxonomy's own crosswalk for `T8 — Repudiation & Untraceability` (the
control `F1` already cites) states it is "carried directly into ASI08
(Cascading Failures) and ASI09 (Human-Agent Trust Exploitation)", so `F1`
cites `owasp-agentic-top10:ASI08` and `owasp-agentic-top10:ASI09` alongside
`owasp-agentic-threats:T8` and `nist-ai-rmf:MANAGE-4.1`. Both `ASI08` and
`ASI09` are `checkable = false`: accountability is absorbed into two
composite, runtime failure categories rather than named as its own checkable
entry in the ranked agentic list, and the OWASP LLM Top 10 has no place for
it at all. The gap this table records is therefore narrower than an earlier
version claimed — accountability is not cited by *nothing* in the ranked
lists — but it is real: no ranked list, agentic or otherwise, gives
tool-invocation logging a checkable entry of its own, so it cannot count
toward this project's checkable-coverage figure against either Top 10.

**`G3` carries no agentic mapping at all.** Error-channel semantics
correspond to nothing in either agentic catalogue, so `G3` cites only
`owasp-llm-top10:LLM05`.

**`E3` does map into the ranked agentic Top 10, via `owasp-agentic-top10:ASI02`.**
An earlier version of this document reasoned by semantic proximity — that
`ASI08 Cascading Failures` was `E3`'s "nearest-sounding" entry in the ranked
list, and too poor a fit to cite regardless of its checkability — and left
the ranked list out of `E3` entirely. That reasoning was never checked
against a primary source, and it was wrong: the threat taxonomy's own
crosswalk for `T4 — Resource Overload` (the control `E3` already cites)
states plainly that `T4` is "Mapped under ASI02 (Tool Misuse &
Exploitation)", and the summary crosswalk table repeats it. `E3` cites
`owasp-agentic-top10:ASI02` on that authority, not on a resemblance
judgment — `ASI02` is `checkable = true`, and now counts toward the ranked
agentic Top 10's coverage denominator. (`G5`, for comparison, legitimately
cites two non-checkable controls — `owasp-llm-top10:LLM01` and
`owasp-agentic-top10:ASI01` — because those *are* good fits for what a
mutated tool description enables; a non-checkable control is not
disqualified from being cited, only from counting toward the coverage
denominator. `F1`'s citations of `ASI08`/`ASI09` above rest on the same
principle.)

**Coverage is computed over *checkable* controls only.** Five of the ten OWASP
LLM risks — prompt injection, data and model poisoning, system-prompt leakage,
embedding weaknesses, and misinformation — are runtime or data-quality
properties that no configuration file can answer, as are most of the agentic
threats. They stay in the catalogues marked `checkable = false` so the
denominator describes the whole standard rather than the convenient part of it.

**Coverage counts citations, not adequacy.** A checkable control is "covered"
the moment one check cites it — `ControlCoverage.is_covered` is
`bool(check_ids)`. That is a statement about the denominator, not the
numerator: a citation records that a check was judged relevant to the
obligation, not that the check discharges it. Whether a given check actually
addresses what a control demands is a judgment the percentage does not make
and this document does not claim to have made for it.

## Totals

| Family | Checks | Applies when |
| --- | ---: | --- |
| A Credential exposure | 5 | always |
| B Capability overprovisioning | 5 | always |
| C Supply-chain integrity | 5 | always |
| D Transport and endpoint | 3 | a remote endpoint is configured |
| E Execution containment | 3 | always |
| F Accountability | 2 | always |
| G Translation integrity | 5 | a tool was translated across frameworks |
| **Total** | **28** | |

## Rules for changing this document

1. A new check needs a grounding citation and an automatic remediation. Without
   both it is a feature request, not a check.
2. Identifiers are permanent. A retired check keeps its ID, marked withdrawn;
   IDs are never reused. Reports from different versions must stay comparable.
3. A check whose wording is contradicted by measurement gets rewritten, and the
   rewrite is recorded — as `G2` was after P0.
4. Severity changes require a stated reason. Scores across versions are compared
   in the evaluation, so silent reweighting invalidates the comparison.

## Open items

- **Drift guard.** Implemented, and row-level: `tests/test_control_mapping.py`
  parses the Control mapping table and asserts, per check, that the
  implemented check ids and their exact control sets agree with this document
  — no missing row, no stale row for a withdrawn or unregistered check, no row
  carrying a control the code does not. The control half is genuinely closed.
  The severity half is still open — the test does not compare severities
  against the family tables above, so those can still drift unnoticed.
- `C2` inherits severity from the advisory; the mapping from CVSS to the four
  levels here is not yet fixed.
- Family G currently assumes MCP as the source abstraction. The expressiveness
  lattice (P4) generalises it.

Citations `[P1]`–`[P14]` refer to the reviewed literature set; `[S4]` to the
supplementary MCP-security set.
