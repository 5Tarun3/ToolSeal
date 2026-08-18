"""Shared machinery for Study 1's official-docs/mcp-servers/templates strata.

Same spirit as `tests/test_bench_generated.py`: the extractor is what can
silently fabricate a result, so it is what gets tested, plus the snapshot and
redaction discipline that keeps a committed file free of credential values.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.corpus import (
    Artefact,
    extract_fenced_files,
    extract_html_files,
    materialise,
    mentions_credential_step,
    to_dict,
    to_markdown,
    write,
    write_flat_index,
)

from toolseal.core.policy.family_a import CREDENTIAL_SHAPES

MARKDOWN_NAMED = """Set it up.

```json mcp.json
{"mcpServers": {}}
```

```requirements.txt
crewai
```
"""

MARKDOWN_UNNAMED = """```json
{"mcpServers": {}}
```
"""

HTML_WITH_CONTEXT = """
<p>Add this to your <code>.mcp.json</code> file:</p>
<pre><code>{"mcpServers": {}}</code></pre>
"""

HTML_WITHOUT_CONTEXT = """
<p>Here is an example.</p>
<pre><code>{"mcpServers": {}}</code></pre>
"""

HTML_SCRIPT_NOISE = """
<script>var agent.py = "should not leak into context";</script>
<p>Save it as config.json.</p>
<pre><code>{"mcpServers": {}}</code></pre>
"""


def test_named_markdown_fence_is_recovered() -> None:
    files = extract_fenced_files(MARKDOWN_NAMED)

    assert set(files) == {"mcp.json", "requirements.txt"}
    assert files["mcp.json"] == '{"mcpServers": {}}\n'


def test_unnamed_markdown_fence_is_not_guessed_at() -> None:
    assert extract_fenced_files(MARKDOWN_UNNAMED) == {}


def test_json_is_materialisable_here_unlike_bench_generated() -> None:
    # bench/generated.py excludes .json for a reason specific to that
    # stratum (its docstring). A published MCP server's quickstart is
    # overwhelmingly a JSON mcpServers block, so this stratum accepts it.
    files = extract_fenced_files(MARKDOWN_NAMED)
    assert files["mcp.json"]


def test_markdown_path_traversal_is_rejected() -> None:
    hostile = "```../../evil.py\nprint(1)\n```"

    assert extract_fenced_files(hostile) == {}


def test_html_pre_block_named_in_preceding_text_is_recovered() -> None:
    files = extract_html_files(HTML_WITH_CONTEXT)

    assert set(files) == {".mcp.json"}
    assert "mcpServers" in files[".mcp.json"]


def test_html_pre_block_with_no_nearby_filename_is_not_guessed_at() -> None:
    assert extract_html_files(HTML_WITHOUT_CONTEXT) == {}


def test_html_script_content_does_not_leak_into_filename_context() -> None:
    # The <script> text mentions "agent.py"; if script content leaked into
    # the context window, that name (not config.json) would win because it
    # is closer to nothing meaningful. The real, page-authored name must win.
    files = extract_html_files(HTML_SCRIPT_NOISE)

    assert set(files) == {"config.json"}


def test_credential_step_is_detected_by_env_var_name() -> None:
    assert mentions_credential_step("export OPENAI_API_KEY=...") is True
    assert mentions_credential_step("export ANTHROPIC_API_KEY=...") is True


def test_credential_step_absent_when_no_such_variable_is_named() -> None:
    assert mentions_credential_step("from langchain_mcp_adapters import Client") is False


def test_artefact_with_no_files_is_excluded_not_scored(tmp_path: Path) -> None:
    artefact = Artefact(
        stratum="mcp-servers", id="x", source_url="https://example.test", retrieved_at="t"
    )

    result = materialise(artefact, tmp_path)

    assert not result.materialised
    assert "no named file blocks" in result.excluded
    assert result.audit_score is None


def test_materialised_artefact_is_audited(tmp_path: Path) -> None:
    artefact = Artefact(
        stratum="mcp-servers",
        id="x",
        source_url="https://example.test",
        retrieved_at="t",
        files={
            "agent.py": 'KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - must trigger A1
        },
    )

    result = materialise(artefact, tmp_path)

    assert result.materialised
    assert result.audit_score is not None
    assert "A1" in result.findings


def test_exclusions_are_counted_in_the_aggregate() -> None:
    artefacts = [
        Artefact(stratum="s", id="a", source_url="u", retrieved_at="t", excluded="no files"),
        Artefact(
            stratum="s",
            id="b",
            source_url="u",
            retrieved_at="t",
            audit_score=40,
            blocking=True,
            findings=["A1"],
        ),
    ]

    aggregate = to_dict("s", "population note", artefacts)["aggregate"]

    assert aggregate["candidates_considered"] == 2
    assert aggregate["excluded"] == 1
    assert aggregate["materialised"] == 1
    assert aggregate["mean_score"] == 40


def test_committed_payload_carries_no_credential_shape(tmp_path: Path) -> None:
    """P38 clause 4: a live credential must never reach a committed results file.

    Same proof as `test_bench_generated.test_committed_payload_carries_no_credential_shape`,
    for this stratum's own serialisation path (`materialise` -> `to_dict` -> `write`).
    """
    credential = "sk-abcdefghijklmnopqrst"  # toolseal:allow A1 - fixture, never persisted
    artefact = Artefact(
        stratum="mcp-servers",
        id="x",
        source_url="https://example.test",
        retrieved_at="t",
        files={"agent.py": f'KEY = "{credential}"\n'},
    )

    result = materialise(artefact, tmp_path / "materialise")
    assert "A1" in result.findings

    payload = to_dict("mcp-servers", "note", [result])
    raw = json.dumps(payload)

    assert credential not in raw
    for _label, pattern in CREDENTIAL_SHAPES:
        assert not pattern.search(raw)

    out_dir = tmp_path / "out"
    write(payload, [result], out_dir)
    results_json_raw = (out_dir / "results.json").read_text(encoding="utf-8")
    results_md_raw = (out_dir / "RESULTS.md").read_text(encoding="utf-8")
    snapshot_meta_raw = (out_dir / "snapshot" / "x" / "meta.json").read_text(encoding="utf-8")

    for raw_text in (results_json_raw, results_md_raw, snapshot_meta_raw):
        assert credential not in raw_text
        for _label, pattern in CREDENTIAL_SHAPES:
            assert not pattern.search(raw_text)

    # The materialised file itself is what got audited; it is committed
    # verbatim because it is exactly what toolseal audit ran against, and it
    # necessarily still carries the fixture value the test injected.
    materialised_file = out_dir / "snapshot" / "x" / "materialised" / "agent.py"
    assert credential in materialised_file.read_text(encoding="utf-8")


def test_mechanically_skipped_candidates_are_counted_not_dropped() -> None:
    payload = to_dict(
        "mcp-servers",
        "note",
        [],
        skipped=[("a/fork-of-b", "fork of another entry (exclusion rule 2)")],
    )

    assert payload["aggregate"]["candidates_considered"] == 1
    assert payload["aggregate"]["excluded"] == 1
    assert payload["mechanically_skipped"] == [
        {"id": "a/fork-of-b", "reason": "fork of another entry (exclusion rule 2)"}
    ]
    text = to_markdown(payload)
    assert "a/fork-of-b" in text
    assert "fork of another entry" in text


def test_write_flat_index_matches_the_name_bench_coverage_checks_for(tmp_path: Path) -> None:
    # bench/coverage.py's OTHER_S1_STRATA looks for exactly
    # results.<stratum>.json alongside research/studies/s1/results.json.
    payload = to_dict("mcp-servers", "note", [])

    write_flat_index(payload, tmp_path, "mcp-servers")

    assert (tmp_path / "results.mcp-servers.json").is_file()
    assert json.loads((tmp_path / "results.mcp-servers.json").read_text()) == payload


def test_write_produces_results_json_and_markdown(tmp_path: Path) -> None:
    artefacts = [
        Artefact(stratum="s", id="a", source_url="u", retrieved_at="t", excluded="no files"),
    ]
    payload = to_dict("s", "note", artefacts)

    write(payload, artefacts, tmp_path)

    assert (tmp_path / "results.json").is_file()
    assert (tmp_path / "RESULTS.md").is_file()
    assert (tmp_path / "snapshot" / "a" / "meta.json").is_file()
    assert not (tmp_path / "snapshot" / "a" / "materialised").exists()
