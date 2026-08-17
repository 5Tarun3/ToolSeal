"""Writing into a project that already exists, reversibly.

`init` creates a directory and owns everything in it. Configuring an existing
project is a different and more dangerous act: the files being touched are
someone else's, some of them already exist, and the user has to be able to undo
it without reconstructing their own configuration from memory.

Three rules make that safe, and each is enforced rather than documented:

**Everything written is recorded.** A manifest at ``.toolseal/injection.json``
lists every path touched, the hash of what was written, and - for a file that
already existed - a verbatim backup of what was there before.

**Revert never overwrites later work.** Before restoring a file, its current
content is hashed against what was injected. If they differ the user has edited
it since, and the revert refuses rather than discarding their change. `--force`
overrides, deliberately requiring a second decision.

**A created file is deleted, a modified file is restored.** Conflating the two
would either leave debris behind or destroy a file that existed before toolseal
ever ran.

A fourth rule covers files toolseal only partly owns, like ``CLAUDE.md``: an
existing project already has instructions there, and replacing the whole file
would destroy them. For those, :attr:`~toolseal.core.adapters.base.RenderedFile.block_managed`
switches ``inject`` into **managed-block mode**: toolseal's content is wrapped
in ``<!-- toolseal:begin -->`` / ``<!-- toolseal:end -->`` markers and written
as a block rather than as the whole file.

* Absent file: created, containing only the block.
* Present without the block: the block is appended; every existing byte stays
  exactly where it was.
* Present with the block already: only the text between the markers is
  replaced, in place - not moved to the end, not duplicated.

Hash verification still runs at revert, but it compares the *block* rather
than the whole file: the digest recorded is of the marker block alone, and at
revert time the block is re-extracted from the current file and hashed the
same way. A user editing their own prose around the block does not change what
gets extracted, so revert does not refuse. A user editing text between the
markers does change it, so revert refuses exactly as it would for a fully-owned
file. Deleting or mangling the markers themselves also changes what gets
extracted - there is nothing left to reliably locate - so that is treated as an
edit too, and revert refuses.

Reverting therefore does not restore a stored backup the way a fully-owned
file does: a backup is a snapshot from before injection, and writing it back
would discard any edit the user made to their own prose *after* injection -
exactly the loss this mode exists to prevent. Instead, revert strips the block
back out of whatever the file currently contains and keeps the rest, whatever
it now says. If nothing is left once the block is gone, the file is deleted
rather than left behind empty.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final

from toolseal.core.adapters.base import RenderedFile
from toolseal.errors import ConfigError

MANIFEST_DIR: Final = ".toolseal"
MANIFEST_NAME: Final = "injection.json"
MANIFEST_VERSION: Final = 1

BLOCK_BEGIN: Final = "<!-- toolseal:begin (managed block - edits here are not preserved) -->"
BLOCK_END: Final = "<!-- toolseal:end -->"


def digest(content: str) -> str:
    """A stable hash of file content, used to detect edits since injection."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _block_text(content: str) -> str:
    """The self-contained block toolseal writes for managed-block content.

    Always begins with :data:`BLOCK_BEGIN` and ends with :data:`BLOCK_END`
    followed by exactly one newline, so it can be located and re-extracted
    byte-for-byte later.
    """
    body = content if content.endswith("\n") else content + "\n"
    return f"{BLOCK_BEGIN}\n{body}{BLOCK_END}\n"


def _find_block(text: str) -> tuple[int, int] | None:
    """The ``(start, end)`` span of toolseal's block within *text*, if present.

    ``end`` is exclusive and includes one trailing newline after
    :data:`BLOCK_END`, matching exactly what :func:`_block_text` produces -
    that symmetry is what lets a written block be re-extracted and hashed
    identically at revert time.
    """
    start = text.find(BLOCK_BEGIN)
    if start == -1:
        return None
    end_marker = text.find(BLOCK_END, start)
    if end_marker == -1:
        return None
    end = end_marker + len(BLOCK_END)
    if end < len(text) and text[end] == "\n":
        end += 1
    return start, end


def _separator(existing: str) -> str:
    """Whitespace to insert between untouched existing content and a new block."""
    if existing == "" or existing.endswith("\n\n"):
        return ""
    if existing.endswith("\n"):
        return "\n"
    return "\n\n"


def merge_block(existing: str | None, content: str) -> str:
    """The full file text after writing *content*'s block into *existing*.

    ``existing=None`` means the file does not exist yet, so the result is the
    block alone. Otherwise, an existing block is replaced in place; a file
    without one gets the block appended, with every prior byte untouched.
    """
    block = _block_text(content)
    if existing is None:
        return block

    found = _find_block(existing)
    if found is None:
        return existing + _separator(existing) + block

    start, end = found
    return existing[:start] + block + existing[end:]


def _strip_block(current_text: str) -> str | None:
    """*current_text* with toolseal's block removed, or ``None`` if nothing else remains.

    Used by revert, not by writing: it operates on whatever the file
    currently says, so a user's edits to their own prose - made any time,
    including after injection - are kept rather than rolled back. Only
    trims the blank-line separator :func:`merge_block` adds before an
    appended block, and only when nothing follows the block, so a plain
    append-then-revert round-trips byte-for-byte.
    """
    found = _find_block(current_text)
    if found is None:
        return current_text or None

    start, end = found
    before, after = current_text[:start], current_text[end:]
    if not after:
        before = before.rstrip("\n")
        if before:
            before += "\n"

    remainder = before + after
    return remainder or None


def _comparable(current_text: str, *, block_managed: bool) -> str:
    """What to hash when checking whether a managed file changed since injection.

    A fully-owned file is compared whole. A block-managed file is compared by
    its block alone, extracted the same way it was written - so edits to the
    surrounding content a user owns do not register as a change, while edits
    inside the block, or damage to the markers that makes the block
    unlocatable, do.
    """
    if not block_managed:
        return current_text
    found = _find_block(current_text)
    if found is None:
        # The markers are gone or broken: there is nothing to reliably extract,
        # so the whole content is compared. It will not match a block-only
        # digest, which correctly reads as "changed".
        return current_text
    start, end = found
    return current_text[start:end]


@dataclass(frozen=True)
class InjectedFile:
    """One file toolseal wrote into a project it did not create."""

    path: str
    written_digest: str
    created: bool
    """True when the file did not exist before. Decides delete versus restore."""

    backup: str | None = None
    """Verbatim prior content, for a file that already existed."""

    block_managed: bool = False
    """True when only a delimited block of this file is toolseal's.

    Decides how ``written_digest`` was computed and how it must be re-derived
    at revert time: the whole file for an ordinary managed file, just the
    marker block for one written in managed-block mode.
    """

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "written_digest": self.written_digest,
            "created": self.created,
            "backup": self.backup,
            "block_managed": self.block_managed,
        }

    @classmethod
    def from_dict(cls, data: Any) -> InjectedFile:
        if not isinstance(data, dict):
            message = "injection manifest entry must be an object"
            raise ConfigError(message)
        try:
            return cls(
                path=str(data["path"]),
                written_digest=str(data["written_digest"]),
                created=bool(data["created"]),
                backup=data.get("backup"),
                block_managed=bool(data.get("block_managed", False)),
            )
        except KeyError as exc:
            message = f"injection manifest entry is missing {exc.args[0]!r}"
            raise ConfigError(message) from None


@dataclass(frozen=True)
class Injection:
    """Everything one `add` wrote, and how to undo it."""

    label: str
    files: tuple[InjectedFile, ...] = ()
    recorded_at: str = ""
    extras: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_version": MANIFEST_VERSION,
            "label": self.label,
            "recorded_at": self.recorded_at or datetime.now(UTC).isoformat(timespec="seconds"),
            "files": [item.to_dict() for item in self.files],
            "extras": dict(sorted(self.extras.items())),
        }

    @classmethod
    def from_dict(cls, data: Any) -> Injection:
        if not isinstance(data, dict):
            message = "injection manifest must be an object"
            raise ConfigError(message)

        version = data.get("manifest_version")
        if version != MANIFEST_VERSION:
            message = (
                f"unsupported injection manifest version {version!r}; expected {MANIFEST_VERSION}"
            )
            raise ConfigError(message)

        entries = data.get("files")
        if not isinstance(entries, list):
            message = "injection manifest field 'files' must be a list"
            raise ConfigError(message)

        return cls(
            label=str(data.get("label", "")),
            files=tuple(InjectedFile.from_dict(item) for item in entries),
            recorded_at=str(data.get("recorded_at", "")),
            extras={str(k): str(v) for k, v in (data.get("extras") or {}).items()},
        )


def manifest_path(root: Path) -> Path:
    return root / MANIFEST_DIR / MANIFEST_NAME


def load(root: Path) -> Injection | None:
    """The recorded injection for *root*, or ``None`` if nothing was injected."""
    path = manifest_path(root)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        message = f"cannot read {MANIFEST_DIR}/{MANIFEST_NAME}: {exc}"
        raise ConfigError(message) from None
    return Injection.from_dict(data)


def _resolve(root: Path, relative: str) -> Path:
    """Resolve *relative* under *root*, refusing anything that escapes it."""
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        message = f"refusing to touch a path outside the project: {relative}"
        raise ConfigError(message)

    target = (root / candidate).resolve()
    if not target.is_relative_to(root.resolve()):
        message = f"refusing to touch a path outside the project: {relative}"
        raise ConfigError(message)
    return target


def inject(root: Path, files: tuple[RenderedFile, ...], *, label: str) -> Injection:
    """Write *files* into an existing project and record how to undo it.

    Backs up prior content before writing, so a revert restores the user's
    configuration exactly rather than approximating it.
    """
    if not root.is_dir():
        message = f"not a directory: {root}"
        raise ConfigError(message)

    recorded: list[InjectedFile] = []
    for item in files:
        target = _resolve(root, str(item.path))
        existed = target.is_file()
        backup = target.read_text(encoding="utf-8") if existed else None

        target.parent.mkdir(parents=True, exist_ok=True)
        if item.block_managed:
            to_write = merge_block(backup, item.content)
            written_digest = digest(_block_text(item.content))
        else:
            to_write = item.content
            written_digest = digest(item.content)
        target.write_text(to_write, encoding="utf-8", newline="\n")

        recorded.append(
            InjectedFile(
                path=str(item.path),
                written_digest=written_digest,
                created=not existed,
                backup=backup,
                block_managed=item.block_managed,
            )
        )

    injection = Injection(
        label=label,
        files=tuple(recorded),
        recorded_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    save(root, injection)
    return injection


def save(root: Path, injection: Injection) -> None:
    path = manifest_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(injection.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )


@dataclass(frozen=True)
class RevertPlan:
    """What a revert would do, resolved but not yet applied."""

    to_delete: tuple[str, ...] = ()
    to_restore: tuple[str, ...] = ()
    modified_since: tuple[str, ...] = ()
    """Files the user has edited since injection. Blocks a revert unless forced."""

    missing: tuple[str, ...] = ()
    """Files already gone. Not an error - the end state is the same."""

    @property
    def is_safe(self) -> bool:
        return not self.modified_since


def plan_revert(root: Path, injection: Injection) -> RevertPlan:
    """Work out what reverting would do, without doing any of it."""
    to_delete: list[str] = []
    to_restore: list[str] = []
    modified: list[str] = []
    missing: list[str] = []

    for item in injection.files:
        target = _resolve(root, item.path)
        if not target.is_file():
            missing.append(item.path)
            continue

        current_text = target.read_text(encoding="utf-8")
        current = _comparable(current_text, block_managed=item.block_managed)
        if digest(current) != item.written_digest:
            modified.append(item.path)
            continue

        if item.block_managed:
            would_remain = _strip_block(current_text)
            (to_delete if would_remain is None else to_restore).append(item.path)
        else:
            (to_delete if item.created else to_restore).append(item.path)

    return RevertPlan(
        to_delete=tuple(to_delete),
        to_restore=tuple(to_restore),
        modified_since=tuple(modified),
        missing=tuple(missing),
    )


def _delete_and_prune(target: Path, root: Path) -> None:
    """Delete *target*, and the directory this injection created for it, if empty."""
    target.unlink()
    parent = target.parent
    if parent != root and parent.is_dir() and not any(parent.iterdir()):
        parent.rmdir()


def revert(root: Path, *, force: bool = False) -> RevertPlan:
    """Undo the recorded injection.

    Refuses when a file has changed since it was written, because reverting
    would silently discard the user's edit. ``force`` overrides, which is a
    second and separate decision.
    """
    injection = load(root)
    if injection is None:
        message = f"nothing to revert: no {MANIFEST_DIR}/{MANIFEST_NAME} in {root}"
        raise ConfigError(message)

    plan = plan_revert(root, injection)
    if not plan.is_safe and not force:
        listed = ", ".join(plan.modified_since)
        message = (
            f"these files have changed since toolseal wrote them: {listed}. "
            "Reverting would discard those edits. Re-run with --force to do it anyway."
        )
        raise ConfigError(message)

    for item in injection.files:
        target = _resolve(root, item.path)
        if not target.is_file():
            continue
        current_text = target.read_text(encoding="utf-8")
        current = _comparable(current_text, block_managed=item.block_managed)
        if not force and digest(current) != item.written_digest:
            continue

        if item.block_managed:
            remainder = _strip_block(current_text)
            if remainder is None:
                _delete_and_prune(target, root)
            else:
                target.write_text(remainder, encoding="utf-8", newline="\n")
        elif item.created:
            _delete_and_prune(target, root)
        elif item.backup is not None:
            target.write_text(item.backup, encoding="utf-8", newline="\n")

    manifest_path(root).unlink(missing_ok=True)
    holder = manifest_path(root).parent
    if holder.is_dir() and not any(holder.iterdir()):
        holder.rmdir()

    return plan
