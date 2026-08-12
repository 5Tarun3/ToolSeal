"""ToolGate name resolution (check C3).

The verdict that matters is the one this module refuses to give: an unreachable
registry must raise, never return PHANTOM. Treating a network blip as "this name
is unclaimed" would turn connectivity noise into a squatting signal, and would
let an offline machine mark every real package as phantom.
"""

from __future__ import annotations

import pytest

from toolseal.core.net import HttpError, NotFoundError
from toolseal.core.registry.resolve import (
    Channel,
    Resolution,
    classify_installed,
    levenshtein,
    nearest_known,
    resolve,
)
from toolseal.errors import ResolutionError

KNOWN = frozenset({"requests", "langchain", "modelcontextprotocol", "pydantic"})


@pytest.mark.parametrize(
    ("left", "right", "distance"),
    [
        ("requests", "requests", 0),
        ("requests", "requsets", 2),
        ("requests", "request", 1),
        ("requests", "reqeusts", 2),
        ("", "abc", 3),
        ("abc", "", 3),
    ],
)
def test_levenshtein(left: str, right: str, distance: int) -> None:
    assert levenshtein(left, right) == distance


def test_typo_of_a_known_name_is_found() -> None:
    assert nearest_known("requsets", KNOWN) == "requests"


def test_an_exact_name_is_not_its_own_typo() -> None:
    assert nearest_known("requests", KNOWN) is None


def test_unrelated_names_are_not_matched() -> None:
    assert nearest_known("completely-different", KNOWN) is None


def test_short_names_are_not_typo_checked() -> None:
    # Two edits from a four-character name reaches unrelated packages, so the
    # check would produce noise rather than signal.
    assert nearest_known("abc", frozenset({"abd", "abe"})) is None


def test_exact_hit_is_verified(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("toolseal.core.registry.resolve.exists", lambda url, **_: "requests" in url)

    result = resolve("requests", channels=(Channel.PYPI,), known=KNOWN)

    assert result.resolution is Resolution.EXISTS
    assert result.is_verified
    assert result.channel is Channel.PYPI


def test_absent_but_typo_shaped_name_is_a_lookalike(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("toolseal.core.registry.resolve.exists", lambda url, **_: False)

    result = resolve("requsets", channels=(Channel.PYPI,), known=KNOWN)

    assert result.resolution is Resolution.LOOKALIKE
    assert result.resembles == "requests"
    assert not result.is_verified


def test_absent_and_unlike_anything_is_a_phantom(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("toolseal.core.registry.resolve.exists", lambda url, **_: False)

    result = resolve("totally-invented-name", channels=(Channel.PYPI,), known=KNOWN)

    assert result.resolution is Resolution.PHANTOM
    assert not result.is_verified


def test_unreachable_registry_raises_rather_than_reporting_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreachable(url: str, **_: object) -> bool:
        message = "network down"
        raise HttpError(message)

    monkeypatch.setattr("toolseal.core.registry.resolve.exists", unreachable)

    with pytest.raises(ResolutionError, match="no registry could be reached"):
        resolve("requests", channels=(Channel.PYPI,), known=KNOWN)


def test_one_reachable_channel_is_enough_to_reach_a_verdict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def flaky(url: str, **_: object) -> bool:
        if "npmjs" in url:
            message = "npm down"
            raise HttpError(message)
        return False

    monkeypatch.setattr("toolseal.core.registry.resolve.exists", flaky)

    result = resolve("invented", channels=(Channel.NPM, Channel.PYPI), known=frozenset())

    assert result.resolution is Resolution.PHANTOM


def test_empty_name_is_refused() -> None:
    with pytest.raises(ResolutionError, match="empty name"):
        resolve("   ")


def test_scoped_npm_names_are_url_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []

    def record(url: str, **_: object) -> bool:
        seen.append(url)
        return True

    monkeypatch.setattr("toolseal.core.registry.resolve.exists", record)
    resolve("@modelcontextprotocol/server-postgres", channels=(Channel.NPM,))

    assert "%2f" in seen[0]
    assert "/server-postgres" not in seen[0].split("registry.npmjs.org/")[1]


def test_installed_lookalike_is_flagged_even_though_it_resolves() -> None:
    # The dangerous case for something already installed is resemblance, not
    # absence: it works, and it is not what was meant.
    result = classify_installed("langchian", KNOWN)

    assert result.resolution is Resolution.LOOKALIKE
    assert result.resembles == "langchain"


def test_installed_exact_name_is_clean() -> None:
    assert classify_installed("requests", KNOWN).resolution is Resolution.EXISTS


def test_not_found_is_a_subclass_of_http_error() -> None:
    # Callers that only care about failure should not have to name both.
    assert issubclass(NotFoundError, HttpError)
