# Study 2 - with/without setup comparison

Manual arm: idealised quickstart; lower bound on manual effort.
Any advantage shown here is therefore a conservative estimate.

| task | adverse | manual steps | toolseal steps | manual score | toolseal score |
| --- | --- | ---: | ---: | ---: | ---: |
| `ollama-langgraph` |  | 10 | 2 | 24 | 100 |
| `ollama-crewai` |  | 10 | 2 | 24 | 100 |
| `openai-langgraph` |  | 10 | 2 | 0 | 100 |
| `openai-crewai` |  | 10 | 2 | 0 | 100 |
| `anthropic-langgraph` |  | 10 | 2 | 0 | 100 |
| `anthropic-crewai` |  | 10 | 2 | 0 | 100 |
| `adverse-unsupported-framework` | yes | n/a | refused | n/a | n/a |
| `adverse-unsupported-provider` | yes | n/a | refused | n/a | n/a |

## Aggregate

- Tasks: 8 (2 adverse)
- Mean audit score, manual: 8.0
- Mean audit score, toolseal: 100.0
- Projects with a critical finding, manual: 4
- Projects with a critical finding, toolseal: 0

Per-task figures are above and in `results.json`. An aggregate that hides
one dominant task is worse than no aggregate.
