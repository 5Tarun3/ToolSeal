# Research

Probes and measurement harnesses that produce evidence for the project's claims.
Nothing here ships in the `toolseal` package.

Everything under `research/` depends on the `research` dependency group, which is
deliberately separate from `dev` so that neither contributors nor CI pay to
install heavy agent frameworks:

```bash
uv sync --group research
```

Each probe owns a directory containing the code, a README stating its question
and verdict, and a `results/` directory holding the generated evidence. Results
are committed: a claim in the paper should be traceable to the run that produced
it, and re-running a probe against newer library versions should produce a diff
rather than an argument.

| Probe | Question | Status |
| --- | --- | --- |
| [`probes/p0_translation_fidelity`](probes/p0_translation_fidelity/) | What do cross-framework tool adapters preserve, and what do they lose? | Answered |
