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


def digest(content: str) -> str:
    """A stable hash of file content, used to detect edits since injection."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class InjectedFile:
    """One file toolseal wrote into a project it did not create."""

    path: str
    written_digest: str
    created: bool
    """True when the file did not exist before. Decides delete versus restore."""

    backup: str | None = None
    """Verbatim prior content, for a file that already existed."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "written_digest": self.written_digest,
            "created": self.created,
            "backup": self.backup,
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
        target.write_text(item.content, encoding="utf-8", newline="\n")

        recorded.append(
            InjectedFile(
                path=str(item.path),
                written_digest=digest(item.content),
                created=not existed,
                backup=backup,
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

        if digest(target.read_text(encoding="utf-8")) != item.written_digest:
            modified.append(item.path)
            continue

        (to_delete if item.created else to_restore).append(item.path)

    return RevertPlan(
        to_delete=tuple(to_delete),
        to_restore=tuple(to_restore),
        modified_since=tuple(modified),
        missing=tuple(missing),
    )


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
        if not force and digest(target.read_text(encoding="utf-8")) != item.written_digest:
            continue

        if item.created:
            target.unlink()
            # Remove a directory this injection created, but never one that has
            # anything else in it.
            parent = target.parent
            if parent != root and parent.is_dir() and not any(parent.iterdir()):
                parent.rmdir()
        elif item.backup is not None:
            target.write_text(item.backup, encoding="utf-8", newline="\n")

    manifest_path(root).unlink(missing_ok=True)
    holder = manifest_path(root).parent
    if holder.is_dir() and not any(holder.iterdir()):
        holder.rmdir()

    return plan
