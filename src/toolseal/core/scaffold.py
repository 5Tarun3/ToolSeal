"""Writing a rendered project to disk.

Adapters produce :class:`RenderedFile` values and touch nothing. This module is
the only place that writes, which keeps the dangerous part small enough to read
in one sitting.

Three rules govern it:

* **Nothing is overwritten silently.** A scaffolder that clobbers uncommitted
  work is worse than one that refuses.
* **Nothing escapes the target directory.** Rendered paths are relative by
  construction, but they are validated anyway - a path is exactly the sort of
  thing that becomes attacker-controlled once the registry starts supplying
  descriptors.
* **Either all of it lands or none of it does.** Every write is planned and
  checked first, so a conflict on the last file does not leave a half-scaffolded
  tree behind.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from toolseal.core.adapters.base import (
    Framework,
    Provider,
    RenderedFile,
    ScaffoldSpec,
    framework_registry,
    provider_registry,
)
from toolseal.core.credentials import PRECOMMIT_CONFIG, merge_gitignore
from toolseal.core.manifest import MANIFEST_NAME, Manifest
from toolseal.errors import ConfigError


@dataclass(frozen=True)
class ScaffoldPlan:
    """What would be written, resolved but not yet applied."""

    root: Path
    files: tuple[RenderedFile, ...]
    conflicts: tuple[PurePosixPath, ...]

    @property
    def is_applicable(self) -> bool:
        return not self.conflicts


def _resolve_target(root: Path, relative: PurePosixPath) -> Path:
    """Resolve *relative* under *root*, refusing anything that escapes it."""
    if relative.is_absolute() or ".." in relative.parts:
        message = f"refusing to write outside the project: {relative}"
        raise ConfigError(message)

    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()):
        message = f"refusing to write outside the project: {relative}"
        raise ConfigError(message)
    return target


def build_plan(spec: ScaffoldSpec, *, force: bool = False) -> ScaffoldPlan:
    """Resolve every file the scaffold would write, without writing any.

    Separating planning from application is what makes `init` inspectable and
    testable, and what allows the whole operation to be refused as a unit.
    """
    provider: Provider = provider_registry.get(spec.provider_id)
    framework: Framework = framework_registry.get(spec.framework_id)

    files = list(framework.render(spec, provider))
    files.extend(_project_hygiene_files(spec, provider, framework))

    root = spec.workspace_root
    conflicts = []
    for item in files:
        target = _resolve_target(root, item.path)
        if target.exists() and not item.overwrite and not force:
            conflicts.append(item.path)

    return ScaffoldPlan(root=root, files=tuple(files), conflicts=tuple(conflicts))


def _project_hygiene_files(
    spec: ScaffoldSpec, provider: Provider, framework: Framework
) -> list[RenderedFile]:
    """Files every scaffolded project gets, regardless of framework."""
    existing_gitignore = ""
    gitignore_path = spec.workspace_root / ".gitignore"
    if gitignore_path.is_file():
        existing_gitignore = gitignore_path.read_text(encoding="utf-8")

    manifest = Manifest(
        project_name=spec.project_name,
        provider_id=provider.id,
        framework_id=framework.id,
        model=spec.model or provider.default_model,
    )

    return [
        # A2: merged rather than replaced, so a user's own rules survive and a
        # second run does not append a duplicate block.
        RenderedFile(
            PurePosixPath(".gitignore"),
            merge_gitignore(existing_gitignore),
            overwrite=True,
        ),
        RenderedFile(PurePosixPath(".pre-commit-config.yaml"), PRECOMMIT_CONFIG),
        RenderedFile(PurePosixPath(MANIFEST_NAME), manifest.to_toml()),
    ]


def apply_plan(plan: ScaffoldPlan) -> tuple[Path, ...]:
    """Write the planned files. Refuses outright if anything would be clobbered."""
    if not plan.is_applicable:
        listed = ", ".join(str(path) for path in plan.conflicts)
        message = (
            f"these files already exist and would be overwritten: {listed}. "
            "Re-run with --force to replace them."
        )
        raise ConfigError(message)

    written: list[Path] = []
    for item in plan.files:
        target = _resolve_target(plan.root, item.path)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_text(item.content, encoding="utf-8", newline="\n")
        except OSError as exc:
            message = f"cannot write {item.path}: {exc.strerror}"
            raise ConfigError(message) from None
        _apply_mode(target, item)
        written.append(target)

    return tuple(written)


def _apply_mode(target: Path, item: RenderedFile) -> None:
    """Restrict permissions on sensitive files where the platform supports it.

    Windows does not express POSIX modes, and pretending otherwise would give
    false assurance; the audit reports on file *content*, which is portable.
    """
    # `os.name` rather than `sys.platform`: the latter is a literal mypy narrows
    # on, which makes everything after it unreachable on one platform.
    if not item.is_sensitive or os.name == "nt":
        return
    try:
        target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Permission tightening is best-effort. Failing the whole scaffold over
        # a filesystem that cannot express modes would be disproportionate.
        return
