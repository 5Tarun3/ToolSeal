# Study 5 - control coverage (C6)

Coverage counts citations, not adequacy: a checkable control is reported as covered the moment one check cites it, which is not evidence the check discharges the obligation. C6 is explicitly secondary (spec §11) - the control-mapping feature is justified by operator ease, not by this analysis.

## Part (a): coverage of each standard's checkable controls

| standard | coverage | checkable | published controls | name |
| --- | ---: | ---: | ---: | --- |
| `iso-42001` | 33%* | 1/3 | 4 | ISO/IEC 42001:2023 (Annex A, by reference) |
| `nist-ai-rmf` | 80%* | 4/5 | 7 | NIST AI Risk Management Framework |
| `owasp-agentic-threats` | 100% | 6/6 | 15 | OWASP Agentic AI Threats |
| `owasp-agentic-top10` | 100% | 5/5 | 10 | OWASP Top 10 for Agentic Applications |
| `owasp-llm-top10` | 100% | 5/5 | 10 | OWASP Top 10 for LLM Applications |

`*` marks a catalogue whose file is a curated subset drawn up before any check mapping existed, not the full published standard - its percentage measures coverage of that selection, not of the standard. The complete-enumeration catalogues (unmarked above) list every published entry, `checkable = false` ones included, so their denominator is the whole standard.

Curated subsets in this run:
- `iso-42001`: 4 controls carried here, not the full published standard.
- `nist-ai-rmf`: 7 controls carried here, not the full published standard.

### Uncovered checkable controls (the honest remainder)

**`iso-42001`**
- `A.6.2.2` - AI system requirements and specification
- `A.6.2.4` - AI system verification and validation

**`nist-ai-rmf`**
- `MANAGE-2.2` - Mechanisms are in place to sustain the value of deployed AI systems

**Checks citing no external control at all:** none of 28.

## Part (b): Study 1 re-cut by control

**Not delivered.** 0 of 12 completions in the llm-generated stratum materialised into an auditable project, so aggregate.check_failure_counts is empty - there is nothing to re-derive a per-control table from. The official-docs, mcp-servers, templates strata the evaluation protocol also defines for Study 1 were never collected (no results file exists for any of them). Part (b) is not delivered; coverage_analysis() above stands alone as the evidence for C6.

Per §11 of the design spec and the instructions for this study: an honest gap beats a fabricated table. Part (a) above is the evidence for C6 on its own.

