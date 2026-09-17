# Study 6 - security per millisecond: decorator layer

Partial results. The MCP proxy layer does not exist yet, so H1-H3 are open;
H4 needs only this layer and is reported in full.

Platform: Windows 10, Python 3.11.9, runner `local`, toolseal `660e99e1f386bf95dd3b89dab9fb75fb3293dc1b`. Suite sha256 `c2056d79e4879fb099a3f32f87d5e80f502441a74eb32a8e948f3bc22098edf0`.

## H4 - does each guard miss exactly what its docstring says?

**supported**: 34 of 34 cases matched their registered expectation.

## Per guard

Each guard is a point, not a ratio: added latency on its enforcing path,
the share of applicable attacks it blocked, and the share of applicable
benign cases it wrongly blocked. No single security-per-millisecond figure
is published (protocol, Study 6 - Reporting).

| guard | enforcing median us (evidence on) | block rate | false-block rate |
| --- | ---: | ---: | ---: |
| `bound_runtime` | 9117.75 | 1/2 | 0/1 |
| `minimal_environment` | -20.5 | 1/3 | 0/1 |
| `raise_on_tool_error` | 84.65 | 1/2 | 1/2 |
| `redact` | 4.5 | 2/4 | 1/2 |
| `require_approval` | 87.2 | 1/3 | - |
| `restrict_egress` | 89.7 | 1/6 | 0/2 |
| `validate_against_schema` | 87.0 | 1/4 | 0/1 |

## Added latency - evidence_on (shipped default, primary)

Median, p95 and p99 of paired per-repeat differences, in microseconds.

| guard | enforcing | allowing |
| --- | --- | --- |
| `require_approval` | 87.2 (p95 114.9, p99 182.3) | not measured: the only machine-reachable allow path is the approval override, which Study 6 forbids |
| `restrict_egress` | 89.7 (p95 120.2, p99 176.7) | 86.1 (p95 116.0, p99 148.8) |
| `validate_against_schema` | 87.0 (p95 110.3, p99 201.2) | 85.0 (p95 131.3, p99 210.7) |
| `raise_on_tool_error` | 84.65 (p95 103.8, p99 133.6) | 83.3 (p95 102.2, p99 145.6) |
| `bound_runtime` | 9117.75 (p95 10289.9, p99 10420.1) | 260.5 (p95 319.8, p99 372.1) |
| `redact` | 4.5 (p95 5.5, p99 12.5) | 3.8 (p95 6.4, p99 13.6) |
| `minimal_environment` | -20.5 (p95 -18.8, p99 -18.4) | same path as enforcing |

## Added latency - evidence_off

Median, p95 and p99 of paired per-repeat differences, in microseconds.

| guard | enforcing | allowing |
| --- | --- | --- |
| `require_approval` | 1.3 (p95 2.1, p99 2.5) | not measured: the only machine-reachable allow path is the approval override, which Study 6 forbids |
| `restrict_egress` | 1.8 (p95 3.2, p99 3.3) | 1.2 (p95 1.3, p99 1.8) |
| `validate_against_schema` | 1.3 (p95 1.7, p99 2.2) | 0.8 (p95 1.5, p99 1.7) |
| `raise_on_tool_error` | 1.1 (p95 1.7, p99 13.7) | 0.7 (p95 0.8, p99 1.3) |
| `bound_runtime` | 8367.6 (p95 10046.8, p99 10388.1) | 79.9 (p95 128.6, p99 163.4) |
| `redact` | 4.5 (p95 5.4, p99 9.0) | 3.7 (p95 4.9, p99 8.1) |
| `minimal_environment` | -21.0 (p95 -19.4, p99 -18.6) | same path as enforcing |

## Reading these numbers

Comparators: each guard is timed against the same function without it; `redact`
against the same log handler without the filter; `minimal_environment` against
`dict(os.environ)`, which is what a caller passes when it does not filter.

**The evidence record's share of each guard's cost** (medians, us). Both
conditions were registered before the run; this only subtracts them.
`bound_runtime` is shown on its allowing path, because its enforcing path is
dominated by the platform timer.

| guard (path) | evidence on | evidence off | record | share of shipped cost |
| --- | ---: | ---: | ---: | ---: |
| `require_approval` (enforcing) | 87.2 | 1.3 | 85.9 | 99% |
| `restrict_egress` (enforcing) | 89.7 | 1.8 | 87.9 | 98% |
| `validate_against_schema` (enforcing) | 87.0 | 1.3 | 85.7 | 99% |
| `raise_on_tool_error` (enforcing) | 84.65 | 1.1 | 83.55 | 99% |
| `bound_runtime` (allowing) | 260.5 | 79.9 | 180.6 | 69% |

A negative added latency for `minimal_environment` (enforcing) means the guarded call is
*cheaper* than its comparator, not that the measurement failed.

**`bound_runtime`'s timeout path (exploratory control).** The registered
overshoot past a 0.001 s bound has median 9117.75 us. The control times
the same path against a bare `Thread.join(timeout=0.001)` on the same body.
**Inconclusive on this platform:** the paired difference is -5775.55 us. A guard
does strictly more work than a bare join, so a negative difference, or one of
the same order as the overshoot, is not a cost - both arms are quantised to
the platform timer, and the difference is decided by which tick each call
lands on. The guard's timeout-path cost cannot be resolved below that
granularity here. The resolvable figure is its allowing path above.

This control, and the rule used to decide whether it resolved (net between 0
and half the overshoot), were both chosen after the first run; both are
recorded as exploratory in the Deviations table.

## Every case

| case | guard | kind | expected | observed |
| --- | --- | --- | --- | --- |
| RA-01 | require_approval | attack | blocked | blocked |
| RA-02 | require_approval | attack | missed | missed |
| RA-03 | require_approval | attack | missed | missed |
| RA-B1 | require_approval | benign | not_applicable | not_applicable |
| BR-01 | bound_runtime | attack | missed | missed |
| BR-02 | bound_runtime | attack | blocked | blocked |
| BR-B1 | bound_runtime | benign | allowed | allowed |
| RE-01 | restrict_egress | attack | blocked | blocked |
| RE-02 | restrict_egress | attack | missed | missed |
| RE-03 | restrict_egress | attack | missed | missed |
| RE-04 | restrict_egress | attack | missed | missed |
| RE-05 | restrict_egress | attack | missed | missed |
| RE-06 | restrict_egress | attack | missed | missed |
| RE-B1 | restrict_egress | benign | allowed | allowed |
| RE-B2 | restrict_egress | benign | allowed | allowed |
| VS-01 | validate_against_schema | attack | blocked | blocked |
| VS-02 | validate_against_schema | attack | missed | missed |
| VS-03 | validate_against_schema | attack | missed | missed |
| VS-04 | validate_against_schema | attack | missed | missed |
| VS-B1 | validate_against_schema | benign | allowed | allowed |
| TE-01 | raise_on_tool_error | attack | blocked | blocked |
| TE-02 | raise_on_tool_error | attack | missed | missed |
| TE-B1 | raise_on_tool_error | benign | false_block | false_block |
| TE-B2 | raise_on_tool_error | benign | allowed | allowed |
| RD-01 | redact | attack | blocked | blocked |
| RD-02 | redact | attack | missed | missed |
| RD-03 | redact | attack | missed | missed |
| RD-04 | redact | attack | blocked | blocked |
| RD-B1 | redact | benign | false_block | false_block |
| RD-B2 | redact | benign | allowed | allowed |
| ME-01 | minimal_environment | attack | blocked | blocked |
| ME-02 | minimal_environment | attack | missed | missed |
| ME-03 | minimal_environment | attack | missed | missed |
| ME-B1 | minimal_environment | benign | allowed | allowed |

Hypotheses H1-H3 remain open until the proxy layer exists (T8). Measurement
conditions not fixed by the registration are recorded in the protocol's
Deviations table, dated before this runner existed.
