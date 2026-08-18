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
