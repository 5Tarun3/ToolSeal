"""The policy lock: sealing, verifying, and the honesty requirement (spec §8).

`toolseal policy enforce` writes `.toolseal/policy.lock` and sets it
read-only; `toolseal policy verify` re-derives the resolved policy and
compares. Every test here proves one load-bearing property:

* the round trip is **stable** - sealing an untouched project and verifying
  it, twice, reports no drift both times. If this were false the lock would
  be worse than useless (manufactured confidence, not evidence);
* tampering is **detected and named**, whether it happens to the lock file
  itself or to the underlying `toolseal.toml`;
* the read-only bit actually blocks a plain write, on this platform;
* nothing here claims the lock is tamper-*proof* - only tamper-*evident*.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from toolseal.core.manifest import MANIFEST_NAME, Manifest
from toolseal.core.policy import lock
from toolseal.errors import ConfigError


def _init(tmp_path: Path, *, profile: str | None = None) -> Path:
    """A minimal scaffolded project `enforce`/`verify` can act on, without
    going through the CLI's `init` (kept fast and dependency-free - `lock.py`
    only needs a manifest, not a whole rendered project)."""
    root = tmp_path / "demo"
    root.mkdir()
    manifest = Manifest(
        project_name="demo",
        provider_id="ollama",
        framework_id="langgraph",
        model="llama3",
        profiles=(profile,) if profile else (),
    )
    (root / MANIFEST_NAME).write_text(manifest.to_toml(), encoding="utf-8")
    return root


# --- sealing -------------------------------------------------------------------


def test_seal_writes_a_lock_file(tmp_path: Path) -> None:
    root = _init(tmp_path)

    sealed = lock.seal(root)

    assert lock.lock_path(root).is_file()
    assert sealed.policy_hash
    assert sealed.non_relaxable  # every baseline check id


def test_seal_without_a_manifest_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="toolseal init"):
        lock.seal(tmp_path)


def test_seal_twice_without_release_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)

    with pytest.raises(ConfigError, match="--release"):
        lock.seal(root)


def test_seal_records_declared_relaxations(tmp_path: Path) -> None:
    root = _init(tmp_path)
    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    text += '\n[policy.relax.B2]\nreason = "needs shell"\nexpires = "2026-12-31"\n'
    (root / MANIFEST_NAME).write_text(text, encoding="utf-8")

    sealed = lock.seal(root)

    (relaxation,) = sealed.relaxations
    assert relaxation.check_id == "B2"
    assert relaxation.reason == "needs shell"


# --- read-only ------------------------------------------------------------------


def test_sealed_lock_file_is_read_only(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)
    path = lock.lock_path(root)

    mode = path.stat().st_mode
    assert not (mode & stat.S_IWRITE)

    with pytest.raises(OSError):
        path.write_text("tampered", encoding="utf-8")


def test_released_lock_file_is_writable_again(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)
    lock.release(root)

    assert not lock.lock_path(root).exists()


def test_release_without_a_lock_is_refused(tmp_path: Path) -> None:
    root = _init(tmp_path)

    with pytest.raises(ConfigError, match="nothing to release"):
        lock.release(root)


def test_seal_after_release_works_again(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)
    lock.release(root)

    sealed = lock.seal(root)

    assert lock.lock_path(root).is_file()
    assert sealed.policy_hash


# --- determinism: the property the whole feature depends on --------------------


def test_seal_verify_verify_reports_no_drift(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")
    lock.seal(root)

    first = lock.verify(root)
    second = lock.verify(root)

    assert first.sealed
    assert not first.drifted
    assert not first.lock_tampered
    assert first.severity_changes == ()
    assert first.relaxation_changes == ()
    assert first.profile_changes == ()
    assert not second.drifted
    assert first == second


def test_reseal_after_release_on_an_unchanged_project_hashes_identically(
    tmp_path: Path,
) -> None:
    root = _init(tmp_path, profile="hipaa")
    first = lock.seal(root)
    lock.release(root)
    second = lock.seal(root)

    assert first.policy_hash == second.policy_hash


def test_verify_with_nothing_sealed_reports_no_drift(tmp_path: Path) -> None:
    root = _init(tmp_path)

    report = lock.verify(root)

    assert not report.sealed
    assert not report.drifted


# --- break case: tamper with the lock file directly -----------------------------


def _rewrite_lock(root: Path, mutate: object) -> None:
    """Simulate hand-editing `.toolseal/policy.lock`: clear read-only, apply
    *mutate* to the parsed JSON, write it back, re-seal read-only."""
    path = lock.lock_path(root)
    path.chmod(stat.S_IWRITE)
    data = json.loads(path.read_text(encoding="utf-8"))
    mutate(data)  # type: ignore[operator]
    path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    path.chmod(stat.S_IREAD)


def test_verify_detects_a_tampered_severity_and_names_the_check(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)

    _rewrite_lock(root, lambda data: data["severities"].__setitem__("B2", "low"))

    report = lock.verify(root)

    assert report.drifted
    assert any("B2" in line for line in report.severity_changes)


def test_verify_detects_a_hash_only_tamper(tmp_path: Path) -> None:
    """The recorded content is left honest, but the hash field itself is
    edited - a subtler tamper than changing a visible value, still caught."""
    root = _init(tmp_path)
    lock.seal(root)

    _rewrite_lock(root, lambda data: data.__setitem__("policy_hash", "0" * 64))

    report = lock.verify(root)

    assert report.drifted
    assert report.lock_tampered


def test_verify_detects_a_removed_non_relaxable_entry(tmp_path: Path) -> None:
    """Shrinking `non_relaxable` to quietly exempt one check is exactly the
    tamper the lock exists to catch, not just a severity edit."""
    root = _init(tmp_path)
    sealed = lock.seal(root)
    victim = sealed.non_relaxable[0]

    _rewrite_lock(root, lambda data: data["non_relaxable"].remove(victim))

    report = lock.verify(root)

    assert report.drifted
    assert report.non_relaxable_changes


# --- break case: the underlying policy changes, not the lock file --------------


def test_verify_detects_a_profile_removed_from_the_manifest(tmp_path: Path) -> None:
    root = _init(tmp_path, profile="hipaa")
    lock.seal(root)

    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    edited = text.replace('profiles = ["hipaa"]', "profiles = []")
    assert edited != text
    (root / MANIFEST_NAME).write_text(edited, encoding="utf-8")

    report = lock.verify(root)

    assert report.drifted
    assert report.profile_changes
    assert any(severity_line for severity_line in report.severity_changes)


def test_verify_detects_a_relaxation_added_after_sealing(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)

    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    text += '\n[policy.relax.B2]\nreason = "added after sealing"\nexpires = "2026-12-31"\n'
    (root / MANIFEST_NAME).write_text(text, encoding="utf-8")

    report = lock.verify(root)

    assert report.drifted
    assert any("B2" in line and "added" in line for line in report.relaxation_changes)


def test_verify_detects_a_relaxation_edited_after_sealing(tmp_path: Path) -> None:
    root = _init(tmp_path)
    text = (root / MANIFEST_NAME).read_text(encoding="utf-8")
    text += '\n[policy.relax.B2]\nreason = "original"\nexpires = "2026-12-31"\n'
    (root / MANIFEST_NAME).write_text(text, encoding="utf-8")
    lock.seal(root)

    edited = (root / MANIFEST_NAME).read_text(encoding="utf-8").replace("original", "changed")
    (root / MANIFEST_NAME).write_text(edited, encoding="utf-8")

    report = lock.verify(root)

    assert report.drifted
    assert any("B2" in line and "changed" in line for line in report.relaxation_changes)


# --- sealed_check: what `relax` consults ----------------------------------------


def test_sealed_check_is_none_before_enforce(tmp_path: Path) -> None:
    root = _init(tmp_path)

    assert lock.sealed_check(root, "B2") is None


def test_sealed_check_names_the_lock_once_enforced(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)

    found = lock.sealed_check(root, "B2")

    assert found is not None


def test_sealed_check_is_none_again_after_release(tmp_path: Path) -> None:
    root = _init(tmp_path)
    lock.seal(root)
    lock.release(root)

    assert lock.sealed_check(root, "B2") is None


# --- the honesty requirement (spec §8) -------------------------------------------


def test_the_tamper_evident_notice_never_claims_immutability() -> None:
    lowered = lock.TAMPER_EVIDENT_NOTICE.lower()
    assert "tamper-proof" not in lowered
    assert "tamperproof" not in lowered
    assert "immutable" not in lowered
    assert "tamper-evident" in lowered or "detectable and attributable" in lowered
