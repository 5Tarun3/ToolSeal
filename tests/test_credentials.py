"""Credential handling, tested for what it refuses as much as what it does.

The failure modes that matter are silent ones: degrading to a file when no
keychain exists, storing a placeholder that fails much later, or echoing a value
into an error message. Each has a test.

No test here touches the real OS keychain. Writing to a developer's actual
credential store from a test suite would be indefensible, so the backend is
faked throughout.
"""

from __future__ import annotations

from typing import Any, ClassVar

import pytest

from toolseal.core.credentials import (
    GITIGNORE_ENTRIES,
    NULL_BACKENDS,
    PRECOMMIT_CONFIG,
    KeyringStore,
    environment_reference,
    is_placeholder,
    merge_gitignore,
)
from toolseal.errors import ConfigError


class FakeBackend:
    """Stands in for a working keyring backend."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}


class FakeKeyringModule:
    def __init__(self, backend: Any) -> None:
        self._backend = backend
        self.store: dict[tuple[str, str], str] = {}
        self.raise_on: str | None = None

    def get_keyring(self) -> Any:
        return self._backend

    def set_password(self, service: str, account: str, value: str) -> None:
        if self.raise_on == "set":
            raise RuntimeError(f"backend exploded and echoed {value}")
        self.store[(service, account)] = value

    def get_password(self, service: str, account: str) -> str | None:
        if self.raise_on == "get":
            raise RuntimeError("backend exploded")
        return self.store.get((service, account))

    def delete_password(self, service: str, account: str) -> None:
        if self.raise_on == "delete":
            raise RuntimeError("backend exploded")
        self.store.pop((service, account), None)


@pytest.fixture
def working_keyring(monkeypatch: pytest.MonkeyPatch) -> FakeKeyringModule:
    module = FakeKeyringModule(FakeBackend())
    monkeypatch.setitem(__import__("sys").modules, "keyring", module)
    return module


# --- availability ----------------------------------------------------------


def test_reports_available_with_a_real_backend(working_keyring: FakeKeyringModule) -> None:
    assert KeyringStore().available()


def test_reports_unavailable_when_the_null_backend_is_selected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Keyring:
        """Impersonates keyring's null backend by qualified name."""

    # A class defined inside a function carries a <locals> qualname, so both
    # halves of the identity have to be set for the impersonation to be exact.
    Keyring.__module__ = "keyring.backends.fail"
    Keyring.__qualname__ = "Keyring"

    monkeypatch.setitem(__import__("sys").modules, "keyring", FakeKeyringModule(Keyring()))

    assert not KeyringStore().available()


def test_null_backend_is_matched_by_qualified_name() -> None:
    # The detection must not depend on importing keyring a second time, which
    # is what previously made a working keychain report itself as missing.
    assert "keyring.backends.fail.Keyring" in NULL_BACKENDS


def test_reports_unavailable_for_an_empty_chainer(monkeypatch: pytest.MonkeyPatch) -> None:
    class EmptyChainer:
        backends: ClassVar[list[Any]] = []

    monkeypatch.setitem(__import__("sys").modules, "keyring", FakeKeyringModule(EmptyChainer()))
    assert not KeyringStore().available()


def test_refuses_rather_than_falling_back_to_a_file(monkeypatch: pytest.MonkeyPatch) -> None:
    # The central guarantee: no keychain means stop, not write plaintext.
    monkeypatch.setattr(KeyringStore, "available", lambda self: False)

    with pytest.raises(ConfigError, match="no OS keychain is available"):
        KeyringStore().set("anthropic", "sk-real-looking-value-1234")


def test_unavailable_message_suggests_the_environment_instead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(KeyringStore, "available", lambda self: False)

    with pytest.raises(ConfigError) as caught:
        KeyringStore().get("anthropic")

    assert "environment" in str(caught.value)


# --- round trip ------------------------------------------------------------


def test_round_trip(working_keyring: FakeKeyringModule) -> None:
    store = KeyringStore()
    store.set("anthropic", "sk-ant-a-real-looking-value")

    assert store.get("anthropic") == "sk-ant-a-real-looking-value"


def test_absent_account_returns_none(working_keyring: FakeKeyringModule) -> None:
    assert KeyringStore().get("never-stored") is None


def test_delete_is_idempotent(working_keyring: FakeKeyringModule) -> None:
    store = KeyringStore()
    store.set("openai", "sk-a-real-looking-value")
    store.delete("openai")
    store.delete("openai")

    assert store.get("openai") is None


def test_backend_errors_never_echo_the_value(working_keyring: FakeKeyringModule) -> None:
    # Some backends put the value they were handed into their exception text.
    # Propagating that would defeat the entire module.
    working_keyring.raise_on = "set"

    with pytest.raises(ConfigError) as caught:
        KeyringStore().set("anthropic", "sk-ant-super-secret-value")

    message = str(caught.value)
    assert "sk-ant-super-secret-value" not in message
    assert "RuntimeError" in message


# --- placeholder rejection -------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "<your-api-key>",
        "your-api-key",
        "YOUR_API_KEY_HERE",
        "xxxxxx",
        "change-me",
        "...",
    ],
)
def test_placeholders_are_recognised(value: str) -> None:
    assert is_placeholder(value)


@pytest.mark.parametrize("value", ["sk-ant-api03-abcdef", "ghp_abcdefghij", "a-real-password-42"])
def test_real_looking_values_are_not_placeholders(value: str) -> None:
    assert not is_placeholder(value)


def test_placeholder_is_refused_before_storage(working_keyring: FakeKeyringModule) -> None:
    with pytest.raises(ConfigError, match="looks like a placeholder"):
        KeyringStore().set("anthropic", "<your-api-key>")

    assert working_keyring.store == {}


# --- gitignore -------------------------------------------------------------


def test_all_entries_added_to_an_empty_file() -> None:
    result = merge_gitignore("")

    for entry in GITIGNORE_ENTRIES:
        assert entry in result.splitlines()


def test_merge_preserves_existing_rules() -> None:
    existing = "# my rules\n__pycache__/\nbuild/\n"

    result = merge_gitignore(existing)

    assert "__pycache__/" in result
    assert "build/" in result
    assert ".env" in result.splitlines()


def test_merge_is_idempotent() -> None:
    once = merge_gitignore("__pycache__/\n")
    twice = merge_gitignore(once)

    assert once == twice


def test_merge_adds_only_what_is_missing() -> None:
    existing = ".env\n*.pem\n"

    result = merge_gitignore(existing)

    assert result.count(".env\n") == 1
    assert result.count("*.pem") == 1
    assert "credentials.json" in result


def test_negation_of_the_example_file_is_included() -> None:
    # Without `!.env.example` the `.env.*` rule would hide the file the project
    # needs tracked.
    assert "!.env.example" in GITIGNORE_ENTRIES
    assert GITIGNORE_ENTRIES.index(".env.*") < GITIGNORE_ENTRIES.index("!.env.example")


# --- generated project hygiene ---------------------------------------------


def test_precommit_config_detects_private_keys() -> None:
    assert "detect-private-key" in PRECOMMIT_CONFIG


def test_environment_reference_carries_no_value() -> None:
    assert environment_reference("ANTHROPIC_API_KEY") == "ANTHROPIC_API_KEY="
