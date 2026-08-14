"""The Study 1 harness.

The parser is the part that can silently fabricate a result, so that is what is
tested. Every rule here exists to stop an unusable completion being counted as a
usable one.
"""

from __future__ import annotations

from pathlib import Path

from bench.generated import Completion, evaluate, extract_files, to_dict, to_markdown

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


def test_report_explains_what_an_exclusion_means() -> None:
    text = to_markdown(to_dict([], "test-model"))

    assert "reported rather than discarded" in text
