"""The Study 1 harness.

The parser is the part that can silently fabricate a result, so that is what is
tested. Every rule here exists to stop an unusable completion being counted as a
usable one.
"""

from __future__ import annotations

import json
from pathlib import Path

from bench.generated import Completion, evaluate, extract_files, to_dict, to_markdown

from toolseal.core.policy.family_a import CREDENTIAL_SHAPES

NAMED_ON_FENCE = """Here you go.

```python agent.py
print("hi")
```

```requirements.txt
langchain
```
"""

NAMED_ABOVE_FENCE = """**agent.py**

```python
print("hi")
```
"""

UNNAMED = """```python
print("hi")
```
"""


def test_filename_on_the_fence_line_is_used() -> None:
    files = extract_files(NAMED_ON_FENCE)

    assert set(files) == {"agent.py", "requirements.txt"}
    assert 'print("hi")' in files["agent.py"]


def test_filename_just_above_the_fence_is_used() -> None:
    # The model did name the file, just not where it was asked to. Reading it
    # from there recovers a name the model gave rather than inventing one.
    assert set(extract_files(NAMED_ABOVE_FENCE)) == {"agent.py"}


def test_an_unnamed_block_is_not_given_a_name() -> None:
    # This is the rule that keeps the study honest. Guessing "agent.py" here
    # would turn an unusable answer into a usable one and improve the score of
    # a model that ignored the instruction.
    assert extract_files(UNNAMED) == {}


# What qwen2.5:3b actually returns, trimmed from a real completion: the name is
# a comment on the block's first line, the convention it uses in 17 of 18
# completions. The first parser read only the fence line and the lines above
# it, so it recovered nothing and the first run reported 0 of 12.
NAMED_ON_FIRST_LINE = """```python
# agent.py
import os
```
```python
# requirements.txt
langchain
```
"""


def test_filename_as_a_first_line_comment_is_used() -> None:
    files = extract_files(NAMED_ON_FIRST_LINE)

    assert set(files) == {"agent.py", "requirements.txt"}
    # Verbatim: the comment line stays, because it is valid in every
    # materialisable format and removing it would be editing the answer.
    assert files["agent.py"] == "# agent.py\nimport os\n"


def test_a_first_line_comment_that_is_not_only_a_filename_is_not_a_name() -> None:
    # "# Run python main.py" mentions a file; it does not name this block.
    assert extract_files("```python\n# Run python main.py\nprint(1)\n```") == {}


def test_lookback_does_not_read_into_the_previous_block() -> None:
    # Seen in a real completion: `python3 main.py` inside a run.sh block sat
    # within the lookback window of the next, unnamed block, which was then
    # written out as main.py. A name has to come from prose, not from code.
    text = "```bash\n#!/bin/bash\npython3 main.py\n```\n```sh\nPYTHONPATH=.\n```\n"

    assert extract_files(text) == {}


def test_payload_records_how_many_blocks_each_completion_had() -> None:
    # Without this, "the model returned nothing" and "the model returned five
    # blocks the parser could not name" are the same exclusion string, which is
    # how the first run's 0 of 12 went unexamined.
    completion = Completion(task_id="t", sample=0, text=UNNAMED, excluded="no named file blocks")

    row = to_dict([completion], "test-model")["completions"][0]

    assert row["blocks"] == 1


def test_paths_cannot_escape_the_sample_directory() -> None:
    hostile = "```python ../../evil.py\nprint(1)\n```"

    assert extract_files(hostile) == {}


def test_non_materialisable_suffixes_are_skipped() -> None:
    assert extract_files("```json data.json\n{}\n```") == {}


def test_completion_with_no_files_is_excluded_not_scored(tmp_path: Path) -> None:
    result = evaluate(Completion(task_id="t", sample=0, text=UNNAMED), tmp_path)

    assert not result.materialised
    assert "no named file blocks" in result.excluded
    assert result.audit_score is None


def test_completion_with_no_python_is_excluded(tmp_path: Path) -> None:
    completion = Completion(task_id="t", sample=0, files={"requirements.txt": "langchain\n"})

    result = evaluate(completion, tmp_path)

    assert "no Python source" in result.excluded


def test_materialised_completion_is_audited(tmp_path: Path) -> None:
    completion = Completion(
        task_id="t",
        sample=0,
        files={
            "agent.py": 'KEY = "sk-abcdefghijklmnopqrst"\n',  # toolseal:allow A1 - must trigger A1
            "requirements.txt": "langchain\n",
        },
    )

    result = evaluate(completion, tmp_path)

    assert result.materialised
    assert result.audit_score is not None
    assert "A1" in result.findings


def test_exclusions_are_counted_in_the_aggregate() -> None:
    completions = [
        Completion(task_id="a", sample=0, excluded="no named file blocks"),
        Completion(task_id="b", sample=0, audit_score=40, blocking=True, findings=["A1"]),
    ]

    aggregate = to_dict(completions, "test-model")["aggregate"]

    assert aggregate["completions_total"] == 2
    assert aggregate["excluded"] == 1
    assert aggregate["materialised"] == 1
    # The mean is over what was actually scored, not over the total. Averaging
    # an exclusion in as zero would understate the model.
    assert aggregate["mean_score"] == 40


def test_report_carries_the_model_limitation() -> None:
    text = to_markdown(to_dict([], "qwen2.5:3b"))

    assert "qwen2.5:3b" in text
    assert "open-weight" in text


def test_payload_is_labelled_exploratory() -> None:
    # The parser was fixed after the first run's result was seen. The protocol
    # labels anything that follows from such a change exploratory, and the
    # label is a field so it survives being copied into a table.
    payload = to_dict([], "test-model")

    assert payload["status"].startswith("exploratory")
    assert "exploratory" in to_markdown(payload)


def test_report_explains_what_an_exclusion_means() -> None:
    text = to_markdown(to_dict([], "test-model"))

    assert "reported rather than discarded" in text


def test_committed_payload_carries_no_credential_shape(tmp_path: Path) -> None:
    """P38 clause 4: a live credential must never reach a committed results file.

    A completion is materialised with a real-shaped key so A1 has something to
    catch, then run through the exact serialisation `write()` commits to
    `research/studies/`. `to_dict` only ever stores `Completion.findings`
    (bare check ids from `evaluate`'s `{f.check_id for f in report.findings}`),
    never `Finding.detail` - this proves the matched credential value has no
    path into the payload by scanning the actual JSON bytes with the same
    patterns A1 itself uses to recognise a credential.
    """
    credential = "sk-abcdefghijklmnopqrst"  # toolseal:allow A1 - fixture, never persisted
    completion = Completion(
        task_id="t",
        sample=0,
        files={"agent.py": f'KEY = "{credential}"\n'},
    )

    result = evaluate(completion, tmp_path)
    assert "A1" in result.findings  # the fixture must actually trigger the check

    payload = to_dict([result], "test-model")
    raw = json.dumps(payload)

    assert credential not in raw
    for _label, pattern in CREDENTIAL_SHAPES:
        assert not pattern.search(raw)
