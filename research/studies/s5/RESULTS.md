# Study 5 - control coverage (C6)

Coverage counts citations, not adequacy: a checkable control is reported as covered the moment one check cites it, which is not evidence the check discharges the obligation. C6 is explicitly secondary (spec §11) - the control-mapping feature is justified by operator ease, not by this analysis.

## Part (a): coverage of each standard's checkable controls

| standard | coverage | checkable | published controls | name |
| --- | ---: | ---: | ---: | --- |
| `iso-42001` | 33%* | 1/3 | 4 | ISO/IEC 42001:2023 (Annex A, by reference) |
| `mitre-atlas` | 100%* | 14/14 | 16 | MITRE ATLAS |
| `nist-ai-rmf` | 80%* | 4/5 | 7 | NIST AI Risk Management Framework |
| `owasp-agentic-threats` | 100% | 6/6 | 15 | OWASP Agentic AI Threats |
| `owasp-agentic-top10` | 100% | 5/5 | 10 | OWASP Top 10 for Agentic Applications |
| `owasp-llm-top10` | 100% | 5/5 | 10 | OWASP Top 10 for LLM Applications |

`*` marks a catalogue whose file is a curated subset drawn up before any check mapping existed, not the full published standard - its percentage measures coverage of that selection, not of the standard. The complete-enumeration catalogues (unmarked above) list every published entry, `checkable = false` ones included, so their denominator is the whole standard.

Curated subsets in this run:
- `iso-42001`: 4 controls carried here, not the full published standard.
- `mitre-atlas`: 16 controls carried here, not the full published standard.
- `nist-ai-rmf`: 7 controls carried here, not the full published standard.

### Uncovered checkable controls (the honest remainder)

**`iso-42001`**
- `A.6.2.2` - AI system requirements and specification
- `A.6.2.4` - AI system verification and validation

**`nist-ai-rmf`**
- `MANAGE-2.2` - Mechanisms are in place to sustain the value of deployed AI systems

**Checks citing no external control at all:** none of 28.

## Part (b): Study 1 re-cut by control

Status: exploratory - filename recovery was fixed after the first run's 0 of 12 was seen (research/evaluation-protocol.md, Deviations, 2026-10-09).

Each stratum's per-check failures re-derived per control. Counts are check failures summed onto every control the failing check cites, so they can exceed the number of projects; Study 1's aggregates do not record which project failed which check.

### `llm-generated` - 12 of 18 materialised

| control | check failures citing it |
| --- | ---: |
| `mitre-atlas:AML.T0055` | 24 |
| `owasp-agentic-top10:ASI03` | 24 |
| `owasp-agentic-top10:ASI04` | 15 |
| `owasp-llm-top10:LLM03` | 15 |
| `mitre-atlas:AML.T0034.002` | 12 |
| `mitre-atlas:AML.T0081` | 12 |
| `nist-ai-rmf:MANAGE-4.1` | 12 |
| `owasp-agentic-threats:T3` | 12 |
| `owasp-agentic-threats:T4` | 12 |
| `owasp-agentic-threats:T8` | 12 |
| `owasp-agentic-top10:ASI02` | 12 |
| `owasp-agentic-top10:ASI08` | 12 |
| `owasp-agentic-top10:ASI09` | 12 |
| `owasp-llm-top10:LLM02` | 12 |
| `owasp-llm-top10:LLM06` | 12 |
| `owasp-llm-top10:LLM10` | 12 |
| `mitre-atlas:AML.T0109` | 9 |
| `nist-ai-rmf:GOVERN-6.1` | 9 |
| `mitre-atlas:AML.T0010` | 6 |
| `iso-42001:A.10.3` | 5 |
| `nist-ai-rmf:MAP-4.1` | 1 |

### `official-docs` - 1 of 3 materialised

| control | check failures citing it |
| --- | ---: |
| `owasp-agentic-top10:ASI03` | 3 |
| `mitre-atlas:AML.T0055` | 2 |
| `owasp-llm-top10:LLM03` | 2 |
| `mitre-atlas:AML.T0025` | 1 |
| `mitre-atlas:AML.T0034.002` | 1 |
| `mitre-atlas:AML.T0081` | 1 |
| `mitre-atlas:AML.T0109` | 1 |
| `nist-ai-rmf:GOVERN-6.1` | 1 |
| `nist-ai-rmf:MANAGE-4.1` | 1 |
| `owasp-agentic-threats:T3` | 1 |
| `owasp-agentic-threats:T4` | 1 |
| `owasp-agentic-threats:T8` | 1 |
| `owasp-agentic-threats:T9` | 1 |
| `owasp-agentic-top10:ASI02` | 1 |
| `owasp-agentic-top10:ASI04` | 1 |
| `owasp-agentic-top10:ASI07` | 1 |
| `owasp-agentic-top10:ASI08` | 1 |
| `owasp-agentic-top10:ASI09` | 1 |
| `owasp-llm-top10:LLM02` | 1 |
| `owasp-llm-top10:LLM06` | 1 |
| `owasp-llm-top10:LLM10` | 1 |

### `mcp-servers` - 2 of 25 materialised

| control | check failures citing it |
| --- | ---: |
| `mitre-atlas:AML.T0055` | 4 |
| `owasp-agentic-top10:ASI03` | 4 |
| `mitre-atlas:AML.T0034.002` | 2 |
| `mitre-atlas:AML.T0081` | 2 |
| `mitre-atlas:AML.T0109` | 2 |
| `nist-ai-rmf:GOVERN-6.1` | 2 |
| `nist-ai-rmf:MANAGE-4.1` | 2 |
| `owasp-agentic-threats:T3` | 2 |
| `owasp-agentic-threats:T4` | 2 |
| `owasp-agentic-threats:T8` | 2 |
| `owasp-agentic-top10:ASI02` | 2 |
| `owasp-agentic-top10:ASI04` | 2 |
| `owasp-agentic-top10:ASI08` | 2 |
| `owasp-agentic-top10:ASI09` | 2 |
| `owasp-llm-top10:LLM02` | 2 |
| `owasp-llm-top10:LLM03` | 2 |
| `owasp-llm-top10:LLM06` | 2 |
| `owasp-llm-top10:LLM10` | 2 |

### `templates` - 3 of 25 materialised

| control | check failures citing it |
| --- | ---: |
| `mitre-atlas:AML.T0055` | 6 |
| `owasp-agentic-top10:ASI03` | 6 |
| `owasp-agentic-top10:ASI04` | 4 |
| `owasp-llm-top10:LLM03` | 4 |
| `mitre-atlas:AML.T0034.002` | 3 |
| `mitre-atlas:AML.T0081` | 3 |
| `mitre-atlas:AML.T0109` | 3 |
| `nist-ai-rmf:GOVERN-6.1` | 3 |
| `nist-ai-rmf:MANAGE-4.1` | 3 |
| `owasp-agentic-threats:T3` | 3 |
| `owasp-agentic-threats:T4` | 3 |
| `owasp-agentic-threats:T8` | 3 |
| `owasp-agentic-top10:ASI02` | 3 |
| `owasp-agentic-top10:ASI08` | 3 |
| `owasp-agentic-top10:ASI09` | 3 |
| `owasp-llm-top10:LLM02` | 3 |
| `owasp-llm-top10:LLM06` | 3 |
| `owasp-llm-top10:LLM10` | 3 |
| `iso-42001:A.10.3` | 1 |
| `mitre-atlas:AML.T0010` | 1 |


