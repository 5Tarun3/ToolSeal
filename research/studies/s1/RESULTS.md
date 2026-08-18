# Study 1 - Posture of ecosystem setup guidance

RQ1: does the ecosystem's own setup guidance produce insecure configurations?
Four strata, sampled and reported separately, per
[`../../evaluation-protocol.md`](../../evaluation-protocol.md#study-1--posture-of-ecosystem-setup-guidance-rq1).
Selection criteria for `official-docs`, `mcp-servers` and `templates` are
fixed in [`selection-criteria.md`](selection-criteria.md), committed before
any of the three was collected. What this project does with a finding
against a third-party artefact - and the absolute rule that a live credential
never appears here - is fixed in
[`../../../DISCLOSURE.md`](../../../DISCLOSURE.md).

Per-stratum figures are reported first, because an aggregate can hide a
stratum the others do not resemble; the combined table at the end is a
summary of them, not a replacement for them.

## Stratum: `official-docs`

Census of the frameworks toolseal scaffolds for (langgraph, crewai, claude-code), fixed by URL in research/studies/s1/selection-criteria.md.

- Candidates considered: 3
- Materialised into an auditable project: 1
- Excluded (counted, not dropped): 2
- Mean audit score: 63.0
- With at least one critical finding: 0

### Entries

| id | source | materialised | score | blocking | exclusion reason |
| --- | --- | --- | ---: | --- | --- |
| `claude-code` | https://docs.claude.com/en/docs/claude-code/mcp | yes | 63 | False | - |
| `langgraph` | https://docs.langchain.com/oss/python/langchain/mcp | no | - | - | no named file blocks recovered |
| `crewai` | https://docs.crewai.com/en/mcp/overview | no | - | - | no provider credential step visible on this page (inclusion rule 2 of selection-criteria.md) - materialising would require inventing one; the credential setup and the tool binding live on different pages |

### Which checks fail most often

| check | entries failing |
| --- | ---: |
| `A4` | 1 |
| `C1` | 1 |
| `D2` | 1 |
| `E2` | 1 |
| `E3` | 1 |
| `F1` | 1 |

## Stratum: `mcp-servers`

Top 6 GitHub repositories tagged mcp-server, ranked by stars, that survive the fork/archived/18-month-staleness filter in research/studies/s1/selection-criteria.md.

- Candidates considered: 25
- Materialised into an auditable project: 2
- Excluded (counted, not dropped): 23
- Mean audit score: 40.0
- With at least one critical finding: 0

### Entries

| id | source | materialised | score | blocking | exclusion reason |
| --- | --- | --- | ---: | --- | --- |
| `n8n-io__n8n` | https://github.com/n8n-io/n8n | no | - | - | no named file blocks recovered |
| `google-gemini__gemini-cli` | https://github.com/google-gemini/gemini-cli | no | - | - | no named file blocks recovered |
| `koala73__worldmonitor` | https://github.com/koala73/worldmonitor | no | - | - | no named file blocks recovered |
| `D4Vinci__Scrapling` | https://github.com/D4Vinci/Scrapling | yes | 40 | False | - |
| `ruvnet__ruflo` | https://github.com/ruvnet/ruflo | no | - | - | no named file blocks recovered |
| `sansan0__TrendRadar` | https://github.com/sansan0/TrendRadar | yes | 40 | False | - |

### Which checks fail most often

| check | entries failing |
| --- | ---: |
| `A4` | 2 |
| `C1` | 2 |
| `E2` | 2 |
| `E3` | 2 |
| `F1` | 2 |

### Ranked but skipped before a fetch was attempted

A higher-ranked candidate that fails a mechanical criterion (fork, archived, stale, or outside the fixed sample size) is recorded here rather than silently passed over.

| id | reason |
| --- | --- |
| `upstash/context7` | ranked outside the fixed sample size N=6 |
| `ChromeDevTools/chrome-devtools-mcp` | ranked outside the fixed sample size N=6 |
| `amruthpillai/reactive-resume` | ranked outside the fixed sample size N=6 |
| `DeusData/codebase-memory-mcp` | ranked outside the fixed sample size N=6 |
| `bytedance/UI-TARS-desktop` | ranked outside the fixed sample size N=6 |
| `github/github-mcp-server` | ranked outside the fixed sample size N=6 |
| `assafelovic/gpt-researcher` | ranked outside the fixed sample size N=6 |
| `oraios/serena` | ranked outside the fixed sample size N=6 |
| `modelcontextprotocol/python-sdk` | ranked outside the fixed sample size N=6 |
| `activepieces/activepieces` | ranked outside the fixed sample size N=6 |
| `czlonkowski/n8n-mcp` | ranked outside the fixed sample size N=6 |
| `1Panel-dev/MaxKB` | ranked outside the fixed sample size N=6 |
| `mksglu/context-mode` | ranked outside the fixed sample size N=6 |
| `modelscope/FunASR` | ranked outside the fixed sample size N=6 |
| `nukeop/nuclear` | ranked outside the fixed sample size N=6 |
| `microsoft/mcp-for-beginners` | ranked outside the fixed sample size N=6 |
| `triggerdotdev/trigger.dev` | ranked outside the fixed sample size N=6 |
| `xpzouying/xiaohongshu-mcp` | ranked outside the fixed sample size N=6 |
| `open-metadata/OpenMetadata` | ranked outside the fixed sample size N=6 |

## Stratum: `templates`

Top 6 GitHub repositories matching 'agent starter template' in name or description, ranked by stars, that survive the fork/archived/18-month-staleness filter in research/studies/s1/selection-criteria.md.

- Candidates considered: 25
- Materialised into an auditable project: 3
- Excluded (counted, not dropped): 22
- Mean audit score: 43.7
- With at least one critical finding: 0

### Entries

| id | source | materialised | score | blocking | exclusion reason |
| --- | --- | --- | ---: | --- | --- |
| `GoogleCloudPlatform__agent-starter-pack` | https://github.com/GoogleCloudPlatform/agent-starter-pack | yes | 51 | False | - |
| `AlexPEClub__ai-coding-starter-kit` | https://github.com/AlexPEClub/ai-coding-starter-kit | no | - | - | no named file blocks recovered |
| `CWS6206__ai-coding-starter-kit` | https://github.com/CWS6206/ai-coding-starter-kit | no | - | - | no named file blocks recovered |
| `thorchh__agent-starter` | https://github.com/thorchh/agent-starter | yes | 40 | False | - |
| `i-am-bee__beeai-framework-ts-starter` | https://github.com/i-am-bee/beeai-framework-ts-starter | no | - | - | no named file blocks recovered |
| `aws-samples__sample-amazon-bedrock-agentcore-fullstack-webapp` | https://github.com/aws-samples/sample-amazon-bedrock-agentcore-fullstack-webapp | yes | 40 | False | - |

### Which checks fail most often

| check | entries failing |
| --- | ---: |
| `A4` | 3 |
| `C1` | 3 |
| `E2` | 3 |
| `E3` | 3 |
| `F1` | 3 |
| `C5` | 1 |

### Ranked but skipped before a fetch was attempted

A higher-ranked candidate that fails a mechanical criterion (fork, archived, stale, or outside the fixed sample size) is recorded here rather than silently passed over.

| id | reason |
| --- | --- |
| `panaversity/langgraph-agents-template` | not updated within 18 months of the snapshot |
| `sneg55/agent-starter` | ranked outside the fixed sample size N=6 |
| `jeffweisbein/openclaw-starter-kit` | ranked outside the fixed sample size N=6 |
| `vercel-labs/claude-managed-agents-starter` | ranked outside the fixed sample size N=6 |
| `jonathan-vella/apex-accelerator` | ranked outside the fixed sample size N=6 |
| `i-am-bee/agentstack-starter` | ranked outside the fixed sample size N=6 |
| `anayatkhan1/agentkit-starter` | ranked outside the fixed sample size N=6 |
| `trancethehuman/agent_with_memory` | not updated within 18 months of the snapshot |
| `karolswdev/cline-starter` | not updated within 18 months of the snapshot |
| `twinklejoshi/ai-agent-playwright-typescript-template` | ranked outside the fixed sample size N=6 |
| `DINAKAR-S/voice-agent-starter-kit` | ranked outside the fixed sample size N=6 |
| `arjunprabhulal/adk-advanced` | ranked outside the fixed sample size N=6 |
| `shadcn-labs/startercn` | ranked outside the fixed sample size N=6 |
| `spencerpauly/skills-repo` | ranked outside the fixed sample size N=6 |
| `Rohit-554/Catylst` | ranked outside the fixed sample size N=6 |
| `Kohnnn/deepseek-n8n-automate-workflow` | ranked outside the fixed sample size N=6 |
| `odsc2015/agentic-hackathon-template` | ranked outside the fixed sample size N=6 |
| `jigjoy-ai/cli-agent-starter` | ranked outside the fixed sample size N=6 |
| `datarobot-community/datarobot-agent-application` | ranked outside the fixed sample size N=6 |

## Stratum: `llm-generated`

Model: `qwen2.5:3b`. Limitation: a 3B-class open-weight model, not a frontier model. Bounds what can be claimed, and is also what runs on a laptop with no API key.

- Completions: 12
- Materialised into an auditable project: 0
- Excluded (counted, not dropped): 12
- Mean audit score: None
- With at least one critical finding: 0

### Which checks fail most often

| check | completions failing |
| --- | ---: |

Per-check counts are more actionable than the mean: they name the
specific default a model reproduces, which is what a fix has to target.

Exclusions are completions the model did not turn into a usable project.
They are reported rather than discarded, because dropping them would bias
the sample toward the tidy answers and flatter the result.

## Aggregate across strata

Official documentation and a random template repository are different populations; this table summarises the sections above, it does not substitute for reading them.

| stratum | considered | materialised | excluded | mean score | critical |
| --- | ---: | ---: | ---: | ---: | ---: |
| `official-docs` | 3 | 1 | 2 | 63.0 | 0 |
| `mcp-servers` | 25 | 2 | 23 | 40.0 | 0 |
| `templates` | 25 | 3 | 22 | 43.7 | 0 |
| `llm-generated` | 12 | 0 | 12 | None | 0 |

## Known limitation: filename recovery can mis-pair a block's name

`extract_html_files`/`extract_fenced_files` (`bench/corpus.py`) recover a
filename from the prose nearest a code block, the same "just above it" idea
`bench/generated.py` uses for a model completion - and inherit its failure
mode. When a page or README has more than one filename mentioned close to
more than one block, the heuristic can pair a name with the wrong content.
Two entries in this corpus show it plainly:
`mcp-servers/D4Vinci__Scrapling`'s materialised project contains one file,
named `quotes.json` from nearby prose, whose actual content is Python
spider code, not JSON; `templates/aws-samples__sample-amazon-bedrock-agentcore-fullstack-webapp`'s
`agent/strands_agent.py` contains two shell deploy commands, not Python.

This is not the artefact's own documentation being ambiguous - it is this
harness mis-attributing a name it recovered correctly to a block it did not.
Both entries' audit scores are reported as produced, unedited, per the same
discipline that keeps every other number in this document honest, but they
should be read as evidence about the harness's extraction quality on those
two pages, not as a security finding about either project's own quickstart.
Fixing the heuristic after seeing which two entries it mis-paired would be
exactly the after-the-fact tuning `research/evaluation-protocol.md` exists to
prevent, so it stands as recorded, with this caveat attached.
