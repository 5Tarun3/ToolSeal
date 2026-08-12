"""Turning a directory on disk into a :class:`ProjectModel`.

This is the only component that reads a user's project, and every check depends
on it being both accurate and cheap. Two decisions shape it:

**Tracked status comes from git when git is present.** Whether a file is
committed is the difference between a local mistake and a permanent one, and
only git can answer it. When there is no repository, files are reported as
untracked and the checks say so rather than pretending.

**Ignored status is deliberately shallow.** Full gitignore semantics are
surprisingly deep, and a wrong answer here suppresses findings - the worst
failure direction for a security tool. Only exact-name and simple suffix rules
are honoured; anything more elaborate is treated as *not* ignored, so the check
runs and reports rather than staying silent.
"""

from __future__ import annotations

import re
import subprocess
import tomllib
from pathlib import Path, PurePosixPath
from typing import Final

from toolseal.core.manifest import Manifest
from toolseal.core.model import (
    Dependency,
    DependencySet,
    ProjectFile,
    ProjectModel,
    ProviderBinding,
    RuntimeConfig,
)
from toolseal.errors import ConfigError

SKIPPED_DIRECTORIES: Final = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".tox",
    }
)

LOCKFILE_NAMES: Final = ("uv.lock", "poetry.lock", "requirements.lock", "Pipfile.lock")
SBOM_NAMES: Final = ("sbom.json", "sbom.xml", "bom.json", "cyclonedx.json")

REQUIREMENT: Final = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*?)\s*$"
)

# Evidence that a project redacts credentials from its own logs (check A4).
REDACTION_MARKERS: Final = ("RedactingFilter", "redact(", "REDACTED")

# Evidence that calls are bounded (check E3). Both are needed: a timeout
# without a loop bound still permits an agent that never terminates.
TIMEOUT_MARKERS: Final = ("timeout", "REQUEST_TIMEOUT")
# Each framework spells the loop bound differently; a marker list that knows
# only one of them reports every other framework as unbounded.
# Evidence that child processes get an allowlisted environment rather than a
# copy of the parent's (check E2).
ENVIRONMENT_MARKERS: Final = ("minimal_environment", "ALLOWED_ENVIRONMENT")

LOOP_BOUND_MARKERS: Final = (
    "recursion_limit",
    "RECURSION_LIMIT",
    "max_iterations",
    "MAX_ITERATIONS",
    "max_iter",
)


def _git_tracked(root: Path) -> frozenset[PurePosixPath] | None:
    """Paths git knows about, or ``None`` when this is not a repository."""
    if not (root / ".git").exists():
        return None
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z"],  # noqa: S607 - resolved from PATH by design
            cwd=root,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None

    listed = completed.stdout.decode("utf-8", errors="replace").split("\0")
    return frozenset(PurePosixPath(item) for item in listed if item)


def _ignore_rules(root: Path) -> tuple[frozenset[str], tuple[str, ...]]:
    """Exact names and `*.ext` suffixes from .gitignore. Deliberately shallow."""
    path = root / ".gitignore"
    if not path.is_file():
        return frozenset(), ()

    names: set[str] = set()
    suffixes: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if line.startswith("*.") and "/" not in line:
            suffixes.append(line[1:])
        else:
            names.add(line.rstrip("/"))
    return frozenset(names), tuple(suffixes)


def _is_ignored(relative: PurePosixPath, names: frozenset[str], suffixes: tuple[str, ...]) -> bool:
    if any(part in names for part in relative.parts):
        return True
    return any(relative.name.endswith(suffix) for suffix in suffixes)


def _collect_files(root: Path) -> tuple[ProjectFile, ...]:
    tracked = _git_tracked(root)
    names, suffixes = _ignore_rules(root)

    entries: list[ProjectFile] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            relative = PurePosixPath(path.relative_to(root).as_posix())
        except ValueError:
            continue
        if any(part in SKIPPED_DIRECTORIES for part in relative.parts):
            continue

        entries.append(
            ProjectFile(
                path=relative,
                tracked=tracked is not None and relative in tracked,
                ignored=_is_ignored(relative, names, suffixes),
            )
        )
    return tuple(entries)


def _parse_requirements(text: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = REQUIREMENT.match(line)
        if match is None:
            continue

        specifier = match.group("spec") or ""
        pinned = specifier.startswith("==")
        dependencies.append(
            Dependency(
                name=match.group("name"),
                specifier=specifier,
                pinned=pinned,
                resolved_version=specifier[2:].strip() if pinned else None,
            )
        )
    return dependencies


def _parse_pyproject(path: Path) -> list[Dependency]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError):
        return []
    declared = (data.get("project") or {}).get("dependencies") or []
    return _parse_requirements("\n".join(str(item) for item in declared))


def _collect_dependencies(root: Path) -> DependencySet:
    declared: list[Dependency] = []

    requirements = root / "requirements.txt"
    if requirements.is_file():
        declared += _parse_requirements(requirements.read_text(encoding="utf-8", errors="replace"))

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        declared += _parse_pyproject(pyproject)

    lockfile = next(
        (PurePosixPath(name) for name in LOCKFILE_NAMES if (root / name).is_file()), None
    )
    sbom = next((PurePosixPath(name) for name in SBOM_NAMES if (root / name).is_file()), None)

    return DependencySet(declared=tuple(declared), lockfile=lockfile, sbom=sbom)


def _sources(root: Path) -> list[str]:
    """Every Python source in the project, skipping vendored trees."""
    contents: list[str] = []
    for path in root.rglob("*.py"):
        if any(part in SKIPPED_DIRECTORIES for part in path.parts):
            continue
        try:
            contents.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return contents


def _bounded(sources: list[str]) -> bool:
    """Whether both a request timeout and a loop bound are configured."""
    joined = "\n".join(sources)
    return any(m in joined for m in TIMEOUT_MARKERS) and any(
        m in joined for m in LOOP_BOUND_MARKERS
    )


def _detects_redaction(root: Path) -> bool:
    for path in root.rglob("*.py"):
        if any(part in SKIPPED_DIRECTORIES for part in path.parts):
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if any(marker in content for marker in REDACTION_MARKERS):
            return True
    return False


def extract(root: Path) -> ProjectModel:
    """Build the model a check sees, from the directory at *root*."""
    resolved = root.resolve()
    if not resolved.is_dir():
        message = f"not a directory: {root}"
        raise ConfigError(message)

    manifest = Manifest.load(resolved)
    providers: tuple[ProviderBinding, ...] = ()
    if manifest is not None:
        providers = (ProviderBinding(provider_id=manifest.provider_id, model=manifest.model),)

    sources = _sources(resolved)
    redacts = any(marker in source for source in sources for marker in REDACTION_MARKERS)
    restricts_environment = any(
        marker in source for source in sources for marker in ENVIRONMENT_MARKERS
    )

    return ProjectModel(
        root=resolved,
        files=_collect_files(resolved),
        dependencies=_collect_dependencies(resolved),
        providers=providers,
        runtime=RuntimeConfig(
            redacts_credentials=redacts,
            logs_tool_invocations=redacts,
            approval_required_for_destructive=(
                manifest.approval_required_for_destructive if manifest else False
            ),
            inherits_host_environment=not restricts_environment,
            default_timeout_seconds=60.0 if _bounded(sources) else None,
        ),
    )
