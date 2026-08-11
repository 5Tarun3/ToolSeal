# P0 — Translation fidelity probe

**Question.** When an MCP tool is loaded into an agent framework, which of its
security-relevant properties survive the translation?

**Why it was run first.** Plan step P0 exists to falsify an assumption before
anything is built on it. Contribution C5 and check family G both assume that
popular adapters silently drop MCP security metadata. That assumption was
untested, so it was tested before it could cost a term's work.

## Method

`fixture_server.py` declares three MCP tools that between them carry every
property under test — the four MCP annotation hints, and JSON Schema constraints
(`enum`, `minimum`/`maximum`, `pattern`, `minLength`/`maxLength`). Those
declarations are ground truth.

`probe.py` loads the same server through each adapter and compares the resulting
framework-native tool against ground truth, property by property, recording one
of four verdicts: `preserved`, `dropped`, `mutated`, `unknown`.

It then calls each tool with arguments that violate its own schema. This
separates a constraint that is merely *present* from one that is *enforced*, and
shows whether an MCP error result stays distinguishable from a successful call.

```bash
uv sync --group research
uv run python research/probes/p0_translation_fidelity/probe.py
```

Evidence lands in [`results/`](results/) — `findings.json` for machine
consumption, `findings.md` for reading.

## Result

Versions tested: `mcp 1.28.1`, `langchain-mcp-adapters 0.3.2`,
`langchain-core 1.5.4`, `crewai-tools 1.15.14`, `pydantic 2.12.5`.

| adapter / family | preserved | dropped | mutated |
| --- | --- | --- | --- |
| langchain-mcp-adapters / annotation | 15 | 0 | 0 |
| langchain-mcp-adapters / constraint | 7 | 0 | 0 |
| langchain-mcp-adapters / description | 3 | 0 | 0 |
| langchain-mcp-adapters / enforcement | 0 | 2 | 0 |
| langchain-mcp-adapters / error semantics | 0 | 0 | 2 |
| crewai-tools / annotation | 0 | **15** | 0 |
| crewai-tools / constraint | 7 | 0 | 0 |
| crewai-tools / description | 0 | 0 | **3** |

### The original hypothesis was half wrong, and the half that survived is sharper

**`langchain-mcp-adapters` preserves everything.** All four annotation hints and
the tool title are carried on `tool.metadata`, and `args_schema` retains the raw
JSON Schema with every constraint intact. The blanket claim that adapters drop
security metadata is false for the most widely used adapter.

**`crewai-tools` drops every annotation.** `CrewAIMCPTool` exposes no carrier for
them — not `metadata`, not `annotations`, not `extras`. A tool its author marked
`destructiveHint: true` arrives in CrewAI indistinguishable from a read-only one.
Schema constraints do survive, rebuilt into a Pydantic model.

**`crewai-tools` also rewrites every description.** The author's text is retained
but wrapped: the adapter prepends `Tool Name:` and a serialised copy of the
argument schema. Since the description is what reaches the model's context, the
text the author wrote is not the text the model reads.

**Constraints are declared client-side but enforced server-side.** Neither
adapter rejects a schema-violating call locally. The invalid call is sent, and
the server's own validation rejects it. Defence in depth is therefore absent: a
tool whose server does *not* validate has no second line.

**MCP error results are flattened into ordinary output.** A rejected call comes
back as tool content beginning `Error executing tool ...`, not as a raised
exception. Programmatically, failure is indistinguishable from success without
parsing English prose.

## Verdict

**Contribution C5 survives, reframed.** The interesting finding is not that
translation loses metadata — it is that **loss is adapter-dependent**. The same
MCP server, loaded into two frameworks, yields tools with different security
posture. That is a sharper claim than the original hypothesis, it is measurable,
and because the loss is not inherent it can be compensated.

### Consequences for check family G

| Check | Original wording | Status after P0 |
| --- | --- | --- |
| `G1` | Security annotation dropped in translation | **Confirmed.** Fires on the CrewAI path, not the LangChain path. |
| `G2` | Input-schema constraints lost | **Rewritten.** Constraints survive both adapters. The real defect is that they are enforced only server-side, so `G2` becomes *constraint declared but not enforced client-side*. |
| `G3` | Error semantics lost | **Confirmed.** `isError` is flattened into tool content by the LangChain path. |
| `G4` | Unexpressible property with no compensating guard | **Unchanged.** Now grounded in a measured case: CrewAI annotations. |
| `G5` | Description mutated during translation | **Confirmed.** CrewAI injects a serialised schema into the description. |

Four of five checks stand, three of them now backed by measurement rather than
assumption. `G2` was wrong as written and has been rewritten to match what was
observed.

## Limitations

Three tools, one MCP server, one version of each adapter, on Windows. This is
enough to answer the go/no-go question P0 was created for; it is **not** the
ecosystem measurement. Study 4 broadens this across abstractions and adapter
versions, and should treat these numbers as a pilot.

The probe searches a fixed list of attribute names for annotation carriers. An
adapter storing them somewhere unusual would be scored as dropping them. The
candidate list is in `probe.py` as `ANNOTATION_CARRIERS` and should grow as new
adapters are tested.
