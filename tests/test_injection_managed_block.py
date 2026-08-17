"""Managed-block mode: `CLAUDE.md` gets a delimited block, not a takeover.

`inject` used to write managed files with a plain overwrite, which is correct
for files toolseal owns outright (`.claude/settings.json`) but destroys an
existing project's `CLAUDE.md`. `RenderedFile.block_managed=True` switches
`inject` into a mode where only the text between `BLOCK_BEGIN`/`BLOCK_END` is
toolseal's: created when the file is absent, appended when the file exists
without a block, replaced in place when the block is already there - and
`revert` undoes exactly that, never more.

These tests exercise `inject`/`revert` directly with `block_managed=True`,
independent of the Claude Code adapter, so they pin down the general
machinery rather than one caller of it.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

import pytest

from toolseal.core.adapters.base import RenderedFile
from toolseal.core.injection import BLOCK_BEGIN, BLOCK_END, inject, load, plan_revert, revert
from toolseal.errors import ConfigError


def block_file(content: str) -> tuple[RenderedFile, ...]:
    return (RenderedFile(PurePosixPath("CLAUDE.md"), content, block_managed=True),)


# --- writing -----------------------------------------------------------


def test_created_when_absent(tmp_path: Path) -> None:
    injection = inject(tmp_path, block_file("hello\n"), label="t")

    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert BLOCK_BEGIN in text
    assert BLOCK_END in text
    assert "hello" in text
    assert injection.files[0].created
    assert injection.files[0].backup is None


def test_appended_when_present_without_the_block(tmp_path: Path) -> None:
    original = "# My Project\n\nSome existing instructions I wrote.\n"
    (tmp_path / "CLAUDE.md").write_text(original, encoding="utf-8")

    inject(tmp_path, block_file("toolseal notes\n"), label="t")

    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    # Every original byte survives, untouched, as a prefix.
    assert text.startswith(original)
    assert BLOCK_BEGIN in text
    assert "toolseal notes" in text


def test_appending_records_created_false_and_full_backup(tmp_path: Path) -> None:
    original = "# mine\n"
    (tmp_path / "CLAUDE.md").write_text(original, encoding="utf-8")

    injection = inject(tmp_path, block_file("new\n"), label="t")

    item = injection.files[0]
    assert not item.created
    assert item.backup == original


def test_block_replaced_in_place_no_duplication(tmp_path: Path) -> None:
    original = "# My Project\n\nMy own notes.\n"
    (tmp_path / "CLAUDE.md").write_text(original, encoding="utf-8")

    inject(tmp_path, block_file("first version\n"), label="t")
    after_first = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")

    inject(tmp_path, block_file("second version\n"), label="t")
    after_second = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")

    # Only one block marker pair, in the same place, with updated contents.
    assert after_second.count(BLOCK_BEGIN) == 1
    assert after_second.count(BLOCK_END) == 1
    assert "first version" not in after_second
    assert "second version" in after_second
    # The block did not move to the end or duplicate the surrounding prose.
    assert after_second.index(BLOCK_BEGIN) == after_first.index(BLOCK_BEGIN)
    assert after_second.startswith("# My Project\n\nMy own notes.\n")


def test_replacing_the_block_keeps_content_that_follows_it(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("before\n", encoding="utf-8")
    inject(tmp_path, block_file("v1\n"), label="t")

    # A user adds their own notes after toolseal's block.
    with (tmp_path / "CLAUDE.md").open("a", encoding="utf-8") as handle:
        handle.write("\nmy notes after the block\n")

    inject(tmp_path, block_file("v2\n"), label="t2")

    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "v2" in text
    assert "v1" not in text
    assert "my notes after the block" in text
    assert text.startswith("before\n")


# --- revert --------------------------------------------------------------


def test_revert_removes_only_the_block(tmp_path: Path) -> None:
    original = "# My Project\n\nMy own notes.\n"
    (tmp_path / "CLAUDE.md").write_text(original, encoding="utf-8")

    inject(tmp_path, block_file("toolseal stuff\n"), label="t")
    revert(tmp_path)

    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == original


def test_revert_deletes_a_file_that_had_nothing_but_the_block(tmp_path: Path) -> None:
    inject(tmp_path, block_file("only this\n"), label="t")

    revert(tmp_path)

    assert not (tmp_path / "CLAUDE.md").exists()


def test_revert_leaves_the_file_when_other_content_remains(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("keep me\n", encoding="utf-8")
    inject(tmp_path, block_file("temporary\n"), label="t")

    revert(tmp_path)

    assert (tmp_path / "CLAUDE.md").exists()
    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "keep me\n"


# --- hash discipline: prose around the block vs. inside it ---------------


def test_editing_prose_around_the_block_does_not_block_revert(tmp_path: Path) -> None:
    original = "# My Project\n\nOriginal notes.\n"
    (tmp_path / "CLAUDE.md").write_text(original, encoding="utf-8")
    inject(tmp_path, block_file("managed content\n"), label="t")

    # The user edits their own prose above the block, leaving the block itself
    # untouched.
    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    text = text.replace("Original notes.", "Rewritten notes, entirely my own.")
    (tmp_path / "CLAUDE.md").write_text(text, encoding="utf-8")

    plan = revert(tmp_path)  # must not raise, even without --force

    assert "CLAUDE.md" not in plan.modified_since
    restored = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    assert "Rewritten notes, entirely my own." in restored
    assert BLOCK_BEGIN not in restored


def test_editing_inside_the_block_blocks_revert(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# mine\n", encoding="utf-8")
    inject(tmp_path, block_file("managed content\n"), label="t")

    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    text = text.replace("managed content", "managed content, but I changed it")
    (tmp_path / "CLAUDE.md").write_text(text, encoding="utf-8")

    with pytest.raises(ConfigError, match="have changed since"):
        revert(tmp_path)

    # The edit is not discarded by the refused revert.
    assert "I changed it" in (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")


def test_force_reverts_over_an_edit_inside_the_block(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# mine\n", encoding="utf-8")
    inject(tmp_path, block_file("managed content\n"), label="t")

    text = (tmp_path / "CLAUDE.md").read_text(encoding="utf-8")
    text = text.replace("managed content", "tampered")
    (tmp_path / "CLAUDE.md").write_text(text, encoding="utf-8")

    revert(tmp_path, force=True)

    assert (tmp_path / "CLAUDE.md").read_text(encoding="utf-8") == "# mine\n"


def test_removing_the_markers_is_detected_as_a_change(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# mine\n", encoding="utf-8")
    inject(tmp_path, block_file("managed content\n"), label="t")

    (tmp_path / "CLAUDE.md").write_text("# mine\n\nmanaged content\n", encoding="utf-8")

    plan = plan_revert(tmp_path, load(tmp_path) or pytest.fail("no manifest"))

    assert "CLAUDE.md" in plan.modified_since
