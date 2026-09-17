# Study 6 — Security per millisecond (RQ5)

**Status: decorator layer run; proxy layer not built.** The suite, criteria and
baselines were committed before any number existed. The decorator layer has now
been measured against them - see [`RESULTS.md`](RESULTS.md): **H4 is supported,
34 of 34 cases**, and H1-H3 stay open until the MCP proxy (T8) exists. The
Linux and macOS rows are defined in `.github/workflows/study6.yml` and have
not been run; running them is a manual dispatch. The
claims, metrics and falsification conditions live in
[`../../evaluation-protocol.md`](../../evaluation-protocol.md#study-6--security-per-millisecond-rq5).

## What is registered

| Artifact | Fixes | Held by |
| --- | --- | --- |
| [`baseline-criteria.md`](baseline-criteria.md) | How baselines are chosen | Committed before the survey (bc3cd23) |
| [`attack-suite.toml`](attack-suite.toml) | The protection numerator: 34 cases, expected outcome per layer | sha256 in the protocol; `tests/test_bench_attack_suite.py` |
| [`baselines.toml`](baselines.toml) | The comparison systems | `tests/test_s6_baselines.py` |
| [`RESULTS.md`](RESULTS.md), [`results-decorator.json`](results-decorator.json) | Decorator-layer outcomes and latency (Windows, local) | `bench/study6.py`; `tests/test_bench_study6.py` |

## Workloads

**Primary — the attack suite's own fixtures.** In-process, offline and
deterministic. Protection outcomes are measured here. Hostnames use the reserved
`.invalid` TLD, so no case can reach a real network.

**Secondary — the MCP servers.** The 18 stdio servers in
[`../../registry-utility-coverage.md`](../../registry-utility-coverage.md) remain
the population, used for proxy pass-through latency at realistic tool-list
sizes. The servers probe P3 could not start are carried forward as recorded, not
re-selected around.

## Platforms

| Platform | Protection outcomes | Latency | Isolation |
| --- | --- | --- | --- |
| Windows, local machine | reported | **primary** | host |
| Linux, CI runner | reported | reported, *lower-confidence* | container |
| macOS, CI runner | reported | reported, *lower-confidence* | host |

Protection outcomes are deterministic, so they are reported from every platform.
Latency is not: shared CI runners are noisy at microsecond scale, so their
latency is labelled lower-confidence and the local machine is primary. Hosted
macOS runners have no Docker, so that row runs in host isolation.

Every result row records OS, Python version, runner type and toolseal commit.

## What the registration already commits to

The suite's declared expectations, before any measurement:

| Layer | Attacks blocked | Attacks missed | Not applicable | Benign false blocks |
| --- | ---: | ---: | ---: | ---: |
| Decorator | 8 | 16 | 0 | 2 |
| Proxy | 16 | 2 | 6 | 0 |

These are expectations read from source, not results. Two attacks - a socket
the tool opens internally, and a redirect from an allowed host - are expected
to defeat **both** layers, because neither an argument decorator nor an MCP
proxy can see them.

## Changing any of this

Editing `attack-suite.toml` fails its digest test. The only legitimate path is a
dated row in the protocol's Deviations table, the digest re-recorded, and any
affected result labelled exploratory.
