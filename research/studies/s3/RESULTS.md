# Study 3 - runtime cost of secure defaults

Repeats per measurement: 200.
Excludes provider latency, deliberately: a model round trip hides a millisecond-scale difference and would produce a meaningless null.

| operation | repeats | mean (us) | median (us) | p95 (us) |
| --- | ---: | ---: | ---: | ---: |
| tool call, no guard | 200 | 0.46 | 0.4 | 0.5 |
| tool call, approval guard | 200 | 20.54 | 19.5 | 24.2 |
| redact one log line | 200 | 9.03 | 8.0 | 12.5 |

## Per-call cost of a compensating guard

- **10.04 us** (0.01 ms) per guarded call.
- Reference: AgentWarden reports ~800 ms per call for runtime capability governance; quoted from the paper, not reproduced here.
- Configuration-time enforcement is roughly **80000.0x** cheaper per call than the runtime figure it is compared against.

The comparison is indicative, not like-for-like: AgentWarden's 800 ms buys
a learned, task-aware policy, while a compensating guard reinstates one
declared property. The claim is narrower than the ratio suggests - that
properties knowable at configuration time do not need to be re-derived on
every call - and the report says so rather than letting the number speak
for itself.
