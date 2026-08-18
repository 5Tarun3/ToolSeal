"""Sealing the resolved policy: tamper-evident, not tamper-proof (spec §8).

`toolseal policy enforce` derives the policy the same way `policy check`
already does - active profiles resolved, relaxations parsed from
`toolseal.toml` - and writes the result to `.toolseal/policy.lock`, then sets
the file read-only. `toolseal policy verify` re-derives the same thing from
the project as it stands *today* and compares.

**What this promises, and what it does not.** Setting a file's read-only
attribute is a speed bump, not a lock in the security sense: anyone who can
run the agent can clear the read-only bit and edit the file underneath, on
Windows exactly as on POSIX. This module does not, and cannot, prevent that.
What it makes possible is *noticing* - `verify` names precisely which check's
severity changed, which relaxation was added, removed or edited, and whether
the lock file's own recorded hash still matches its own recorded content.
That is what "tamper-evident" means here, and every string this module or its
CLI commands print says exactly that, never "tamper-proof" or "immutable".

The enforcement point that actually holds is CI, where the developer has no
write access to the repository checkout to begin with. `toolseal policy
verify` is meant to run there unconditionally - exit 0 with nothing sealed,
exit 0 with no drift, non-zero the moment either check fails - which is why
it is also the natural pre-commit hook: catching a hand-edited `toolseal.toml`
or a directly-edited `policy.lock` before it is ever pushed, not only after.

**Hashing reuses `core/injection.py`'s `digest()`** rather than calling
`hashlib` a second time in this package: it is the same "hash content, detect
whether it changed" primitive `injection.py` already implements and tests for
its own hash-verified, refuse-without-force files. Writing and reverting
`policy.lock` is not routed through `injection.inject()`/`revert()` directly,
though, because those manage a *different* lifecycle - `.toolseal/injection.json`
tracks every file `add`/`revert` wrote, with backups and restoration of prior
content. A policy lock has no "prior content" to restore and its own command
surface (`enforce`/`enforce --release`), so it reuses the hashing primitive
and the same refuse-without-explicit-intent shape, not the injection manifest
itself.

Dependency direction: this module depends on `policy/profile.py` and
`policy/relax.py` (§3 of the spec names `lock` as depending on `profile`;
relaxations are pulled in too because a sealed policy that ignored them could
not detect a hand-edited `[policy.relax.*]` block as drift).
"""

from __future__ import annotations

import json
import stat
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Final

from toolseal.core.injection import digest
from toolseal.core.manifest import MANIFEST_NAME, Manifest
from toolseal.core.policy.profile import load_profile
from toolseal.core.policy.profile import resolve as resolve_profiles
from toolseal.core.policy.relax import Relaxation, parse_relaxations
from toolseal.errors import ConfigError

LOCK_DIR: Final = ".toolseal"
LOCK_NAME: Final = "policy.lock"
LOCK_VERSION: Final = 1

TAMPER_EVIDENT_NOTICE: Final = (
    "A read-only file is not a security boundary; anyone who can run the agent "
    "can clear the read-only bit. This lock makes tampering detectable and "
    "attributable, not impossible. The check that actually holds is CI, where "
    "`toolseal policy verify` runs with no write access to override."
)
"""The exact honesty statement spec §8 requires. Reused verbatim by the CLI
rather than re-worded per call site, so the claim never drifts between one
command's output and another's."""

CI_VERIFY_STEP_EXAMPLE: Final = """\
      - name: Verify the policy lock has not drifted
        run: uv run toolseal policy verify
"""
"""A copy-pasteable CI step, printed by `enforce` and quoted in the
project's own documentation. `toolseal policy verify` exits 0 with nothing
sealed, so this is safe to add before a project has ever run `enforce` -
it starts enforcing itself the moment it does."""


def lock_path(root: Path) -> Path:
    return root / LOCK_DIR / LOCK_NAME


# --- the sealed record -----------------------------------------------------


def _relaxations_to_list(relaxations: tuple[Relaxation, ...]) -> list[dict[str, Any]]:
    return [
        {
            "check_id": r.check_id,
            "reason": r.reason,
            "expires": r.expires.isoformat(),
            "tools": list(r.tools),
        }
        for r in sorted(relaxations, key=lambda item: item.check_id)
    ]


def _canonical_policy(
    profiles: tuple[str, ...],
    severities: dict[str, str],
    relaxations: tuple[Relaxation, ...],
    non_relaxable: tuple[str, ...],
) -> dict[str, Any]:
    """The deterministic shape that gets hashed and compared.

    Nothing here depends on the moment it is computed. In particular, a
    relaxation's *declared* expiry date is included, but whether it is
    currently expired is not - that is computed against "today" by
    `relax.py`, and would otherwise make an untouched project drift on the
    calendar alone. `sealed_at` (a real timestamp) never enters this
    function; it is metadata on `PolicyLock`, not part of what gets hashed.
    """
    return {
        "profiles": list(profiles),
        "severities": dict(sorted(severities.items())),
        "relaxations": _relaxations_to_list(relaxations),
        "non_relaxable": sorted(non_relaxable),
    }


def _hash_policy(canonical: dict[str, Any]) -> str:
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return digest(encoded)


@dataclass(frozen=True)
class PolicyLock:
    """What `enforce` sealed: the resolved policy, its hash, and what it locked.

    `policy_hash` is computed over `profiles`, `severities`, `relaxations` and
    `non_relaxable` only (`_canonical_policy`) - `sealed_at` is informational
    and deliberately excluded, so re-sealing an unchanged project on a
    different day never itself counts as drift.
    """

    policy_hash: str
    profiles: tuple[str, ...]
    severities: dict[str, str]
    relaxations: tuple[Relaxation, ...]
    non_relaxable: tuple[str, ...]
    """Check ids `relax` refuses to act on while this lock exists. `enforce`
    seals the whole resolved policy, so today this is every check id in
    `severities` - recorded explicitly anyway, so a reader (and `relax`) never
    has to re-derive "which checks are sealed" from the fact that a lock file
    merely exists."""

    sealed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "lock_version": LOCK_VERSION,
            "sealed_at": self.sealed_at,
            "policy_hash": self.policy_hash,
            "profiles": list(self.profiles),
            "severities": dict(sorted(self.severities.items())),
            "relaxations": _relaxations_to_list(self.relaxations),
            "non_relaxable": sorted(self.non_relaxable),
        }

    @classmethod
    def from_dict(cls, data: Any) -> PolicyLock:
        if not isinstance(data, dict):
            message = f"{LOCK_NAME} must be a JSON object"
            raise ConfigError(message)

        version = data.get("lock_version")
        if version != LOCK_VERSION:
            message = f"unsupported {LOCK_NAME} version {version!r}; expected {LOCK_VERSION}"
            raise ConfigError(message)

        try:
            severities = {str(k): str(v) for k, v in data["severities"].items()}
            relaxations = tuple(
                Relaxation(
                    check_id=str(item["check_id"]),
                    reason=str(item["reason"]),
                    expires=date.fromisoformat(str(item["expires"])),
                    tools=tuple(str(t) for t in item.get("tools", ())),
                )
                for item in data["relaxations"]
            )
            return cls(
                policy_hash=str(data["policy_hash"]),
                profiles=tuple(str(p) for p in data["profiles"]),
                severities=severities,
                relaxations=relaxations,
                non_relaxable=tuple(str(c) for c in data["non_relaxable"]),
                sealed_at=str(data.get("sealed_at", "")),
            )
        except (KeyError, TypeError, ValueError) as exc:
            message = f"{LOCK_DIR}/{LOCK_NAME} is malformed: {exc}"
            raise ConfigError(message) from None


# --- reading -----------------------------------------------------------------


def load(root: Path) -> PolicyLock | None:
    """The sealed lock at *root*, or `None` when nothing is sealed."""
    path = lock_path(root)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        message = f"cannot read {LOCK_DIR}/{LOCK_NAME}: {exc}"
        raise ConfigError(message) from None
    return PolicyLock.from_dict(data)


def is_sealed(root: Path) -> bool:
    return lock_path(root).is_file()


def sealed_check(root: Path, check_id: str) -> PolicyLock | None:
    """The lock sealing *check_id*, if any. `None` means `relax` may act on it."""
    existing = load(root)
    if existing is None or check_id not in existing.non_relaxable:
        return None
    return existing


# --- deriving the live policy -------------------------------------------------


def _current_state(root: Path) -> tuple[tuple[str, ...], dict[str, str], tuple[Relaxation, ...]]:
    """The resolved policy as the project stands *right now* - the same shape
    `seal` records, so sealing twice on an untouched project, or verifying
    right after sealing, produces identical results."""
    manifest = Manifest.load(root)
    profile_ids = manifest.profiles if manifest is not None else ()
    profiles = [load_profile(pid) for pid in profile_ids]
    resolution = resolve_profiles(profiles)
    severities = {check.id: check.severity.value for check in resolution.checks}

    manifest_path = root / MANIFEST_NAME
    text = manifest_path.read_text(encoding="utf-8") if manifest_path.is_file() else ""
    relaxations = parse_relaxations(text) if text else ()

    return profile_ids, severities, relaxations


# --- sealing / releasing ------------------------------------------------------


def seal(root: Path) -> PolicyLock:
    """Derive the resolved policy, hash it, write it, and set it read-only.

    Refuses when a lock already exists: replacing a sealed lock is always a
    second, explicit decision (`enforce --release` first), never something a
    repeated `enforce` does by accident - the same discipline
    `injection.revert` applies to overwriting a file that changed since it
    was written.
    """
    if Manifest.load(root) is None:
        message = f"no {MANIFEST_NAME} found in {root}; run `toolseal init` first"
        raise ConfigError(message)

    path = lock_path(root)
    if path.is_file():
        message = (
            f"{LOCK_DIR}/{LOCK_NAME} already exists; run `toolseal policy enforce "
            "--release` first, or `toolseal policy verify` to check it"
        )
        raise ConfigError(message)

    profile_ids, severities, relaxations = _current_state(root)
    non_relaxable = tuple(sorted(severities))
    canonical = _canonical_policy(profile_ids, severities, relaxations, non_relaxable)

    sealed = PolicyLock(
        policy_hash=_hash_policy(canonical),
        profiles=profile_ids,
        severities=severities,
        relaxations=relaxations,
        non_relaxable=non_relaxable,
        sealed_at=datetime.now(UTC).isoformat(timespec="seconds"),
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(sealed.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
        newline="\n",
    )
    # `stat.S_IREAD` is what actually toggles the Windows read-only file
    # attribute - `os.chmod`/`Path.chmod` on Windows has no concept of
    # separate owner/group/other bits, only "is the write bit present at
    # all", so this is the one mode value that reliably works on both
    # platforms rather than a POSIX permission literal that Windows ignores.
    path.chmod(stat.S_IREAD)
    return sealed


def release(root: Path) -> None:
    """Unseal: clear the read-only bit and remove the lock.

    Requires the lock to already exist. There is no implicit unsealing path -
    `--release` on the CLI is the explicit intent this makes safe.
    """
    path = lock_path(root)
    if not path.is_file():
        message = f"no {LOCK_DIR}/{LOCK_NAME} found in {root}; nothing to release"
        raise ConfigError(message)

    path.chmod(stat.S_IWRITE)
    path.unlink()
    if path.parent.is_dir() and not any(path.parent.iterdir()):
        path.parent.rmdir()


# --- verifying -----------------------------------------------------------------


@dataclass(frozen=True)
class DriftReport:
    """What `verify` found when it re-derived the policy and compared it
    against what `enforce` sealed. Every *_changes tuple names the specific
    field that differs - `verify`'s exit code says *that* something drifted,
    this says *what*."""

    sealed: bool
    """`False` when there is no `policy.lock` at all - nothing to verify, and
    `drifted` is always `False` in that case."""

    drifted: bool

    lock_tampered: bool
    """The lock file's own recorded `policy_hash` does not match a fresh hash
    of its own recorded `severities`/`relaxations`/`profiles`/`non_relaxable` -
    it was edited directly rather than produced by `enforce`."""

    profile_changes: tuple[str, ...]
    severity_changes: tuple[str, ...]
    relaxation_changes: tuple[str, ...]
    non_relaxable_changes: tuple[str, ...]


def _diff_relaxations(
    locked: tuple[Relaxation, ...], current: tuple[Relaxation, ...]
) -> tuple[str, ...]:
    locked_by_id = {r.check_id: r for r in locked}
    current_by_id = {r.check_id: r for r in current}

    changes: list[str] = []
    for check_id in sorted(set(locked_by_id) | set(current_by_id)):
        before = locked_by_id.get(check_id)
        after = current_by_id.get(check_id)
        if before == after:
            continue
        if before is None and after is not None:
            changes.append(f"{check_id}: relaxation added since sealing (reason: {after.reason})")
        elif after is None and before is not None:
            changes.append(f"{check_id}: relaxation removed since sealing (was: {before.reason})")
        elif before is not None and after is not None:
            changes.append(
                f"{check_id}: relaxation changed since sealing "
                f"(reason {before.reason!r} -> {after.reason!r}, "
                f"expires {before.expires} -> {after.expires}, "
                f"tools {list(before.tools)} -> {list(after.tools)})"
            )
    return tuple(changes)


def verify(root: Path) -> DriftReport:
    """Re-derive the policy from *root* as it stands today and compare it
    against what was sealed. Never raises for drift - drift is the expected,
    reportable outcome; only a malformed or unreadable lock file raises."""
    existing = load(root)
    if existing is None:
        return DriftReport(
            sealed=False,
            drifted=False,
            lock_tampered=False,
            profile_changes=(),
            severity_changes=(),
            relaxation_changes=(),
            non_relaxable_changes=(),
        )

    recorded_canonical = _canonical_policy(
        existing.profiles, existing.severities, existing.relaxations, existing.non_relaxable
    )
    lock_tampered = _hash_policy(recorded_canonical) != existing.policy_hash

    profile_ids, severities, relaxations = _current_state(root)
    non_relaxable = tuple(sorted(severities))
    current_canonical = _canonical_policy(profile_ids, severities, relaxations, non_relaxable)
    current_hash = _hash_policy(current_canonical)

    drifted = lock_tampered or current_hash != existing.policy_hash

    profile_changes: tuple[str, ...] = ()
    if profile_ids != existing.profiles:
        profile_changes = (
            f"profiles: {list(existing.profiles)} (locked) -> {list(profile_ids)} (current)",
        )

    severity_changes = tuple(
        f"{check_id}: {existing.severities.get(check_id, 'unmapped')} (locked) -> "
        f"{severities.get(check_id, 'unmapped')} (current)"
        for check_id in sorted(set(existing.severities) | set(severities))
        if existing.severities.get(check_id) != severities.get(check_id)
    )

    relaxation_changes = _diff_relaxations(existing.relaxations, relaxations)

    non_relaxable_changes: tuple[str, ...] = ()
    if set(existing.non_relaxable) != set(non_relaxable):
        non_relaxable_changes = (
            f"non_relaxable: {sorted(existing.non_relaxable)} (locked) -> "
            f"{sorted(non_relaxable)} (current)",
        )

    return DriftReport(
        sealed=True,
        drifted=drifted,
        lock_tampered=lock_tampered,
        profile_changes=profile_changes,
        severity_changes=severity_changes,
        relaxation_changes=relaxation_changes,
        non_relaxable_changes=non_relaxable_changes,
    )
