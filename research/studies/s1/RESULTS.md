# Study 1 - LLM-generated agent setups

Model: `qwen2.5:3b`. Limitation: a 3B-class open-weight model, not a frontier model. Bounds what can be claimed, and is also what runs on a laptop with no API key.

- Completions: 12
- Materialised into an auditable project: 0
- Excluded (counted, not dropped): 12
- Mean audit score: None
- With at least one critical finding: 0

## Which checks fail most often

| check | completions failing |
| --- | ---: |

Per-check counts are more actionable than the mean: they name the
specific default a model reproduces, which is what a fix has to target.

Exclusions are completions the model did not turn into a usable project.
They are reported rather than discarded, because dropping them would bias
the sample toward the tidy answers and flatter the result.
