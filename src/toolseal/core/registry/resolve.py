"""ToolGate - verifying a tool name before anything installs it.

This is check `C3`, and the piece of the project that comes straight from the
slopsquatting literature. Al-Zofi's review names *"no real-time package-existence
validation in coding tools"* as an open gap, and it is worse in the agentic case
than in the case that literature studied: an agent resolving a name it produced
itself has no human between the suggestion and the install.

Three outcomes, and the middle one matters most:

* ``EXISTS`` - the name resolves in a channel we trust.
* ``LOOKALIKE`` - it resolves, but it is a near-miss of an established name.
  This is the shape a successful typosquat takes: the install works, so nothing
  looks wrong.
* ``PHANTOM`` - it resolves nowhere. Today that is a broken install; tomorrow it
  is whatever the first person to register the name decides it should be.

A network failure is never reported as a verdict. "We could not check" and "we
checked and it is fine" are different states, and conflating them would make the
check actively dangerous.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from toolseal.core.net import HttpError, exists
from toolseal.errors import ResolutionError

NPM_REGISTRY: Final = "https://registry.npmjs.org"
PYPI_REGISTRY: Final = "https://pypi.org/pypi"
MCP_REGISTRY: Final = "https://registry.modelcontextprotocol.io/v0/servers"

# Distance at which a name stops being a plausible typo and becomes a different
# name. Two edits covers transposition, a doubled letter, and a dropped one -
# the mistakes that actually happen - without matching every short name to
# every other short name.
MAX_TYPO_DISTANCE: Final = 2

# Names short enough that two edits would reach unrelated packages.
MIN_LENGTH_FOR_TYPO_CHECK: Final = 5


class Resolution(StrEnum):
    EXISTS = "exists"
    LOOKALIKE = "lookalike"
    PHANTOM = "phantom"


class Channel(StrEnum):
    NPM = "npm"
    PYPI = "pypi"
    MCP = "mcp"


@dataclass(frozen=True)
class ResolutionResult:
    """What a name resolved to, and why that verdict was reached."""

    name: str
    resolution: Resolution
    channel: Channel | None = None
    resembles: str | None = None
    detail: str = ""

    @property
    def is_verified(self) -> bool:
        """Only an exact hit in a trusted channel counts as verified."""
        return self.resolution is Resolution.EXISTS


def levenshtein(left: str, right: str) -> int:
    """Edit distance between two strings.

    Written out rather than pulled from a dependency: it is twelve lines, and a
    supply-chain tool taking a dependency for twelve lines is a poor advert for
    itself.
    """
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, a in enumerate(left, start=1):
        current = [i]
        for j, b in enumerate(right, start=1):
            current.append(
                min(
                    previous[j] + 1,  # deletion
                    current[j - 1] + 1,  # insertion
                    previous[j - 1] + (a != b),  # substitution
                )
            )
        previous = current
    return previous[-1]


def nearest_known(name: str, known: frozenset[str]) -> str | None:
    """The established name *name* most plausibly typos, if any."""
    if len(name) < MIN_LENGTH_FOR_TYPO_CHECK:
        return None

    candidates = [
        (levenshtein(name, candidate), candidate)
        for candidate in known
        if candidate != name and abs(len(candidate) - len(name)) <= MAX_TYPO_DISTANCE
    ]
    if not candidates:
        return None

    distance, closest = min(candidates)
    return closest if 0 < distance <= MAX_TYPO_DISTANCE else None


def _npm_url(name: str) -> str:
    # Scoped names (@scope/pkg) must have the slash escaped for the registry API.
    return f"{NPM_REGISTRY}/{name.replace('/', '%2f')}"


def _channel_url(channel: Channel, name: str) -> str:
    if channel is Channel.NPM:
        return _npm_url(name)
    if channel is Channel.PYPI:
        return f"{PYPI_REGISTRY}/{name}/json"
    return f"{MCP_REGISTRY}?search={name}"


def resolve(
    name: str,
    *,
    channels: tuple[Channel, ...] = (Channel.NPM, Channel.PYPI),
    known: frozenset[str] = frozenset(),
) -> ResolutionResult:
    """Classify *name* against the given channels.

    Raises :class:`ResolutionError` when no channel could be reached, rather
    than returning ``PHANTOM``. An unreachable registry is not evidence of
    absence, and letting it look like one would make every network blip
    register a name as squattable.
    """
    if not name.strip():
        message = "cannot resolve an empty name"
        raise ResolutionError(message)

    reachable = False
    failures: list[str] = []

    for channel in channels:
        try:
            found = exists(_channel_url(channel, name))
        except HttpError as exc:
            failures.append(f"{channel}: {exc}")
            continue

        reachable = True
        if found:
            return ResolutionResult(
                name=name,
                resolution=Resolution.EXISTS,
                channel=channel,
                detail=f"resolved in {channel}",
            )

    if not reachable:
        message = f"no registry could be reached to verify {name!r}: {'; '.join(failures)}"
        raise ResolutionError(message)

    resembles = nearest_known(name, known)
    if resembles is not None:
        return ResolutionResult(
            name=name,
            resolution=Resolution.LOOKALIKE,
            resembles=resembles,
            detail=f"does not exist and is within {MAX_TYPO_DISTANCE} edits of {resembles!r}",
        )

    return ResolutionResult(
        name=name,
        resolution=Resolution.PHANTOM,
        detail="resolves in no channel checked",
    )


def classify_installed(name: str, known: frozenset[str]) -> ResolutionResult:
    """Classify a name that already resolves, looking only for a near-miss.

    The dangerous case for an *installed* package is not absence but
    resemblance: it installed, it works, and it is not what was meant.
    """
    resembles = nearest_known(name, known)
    if resembles is not None:
        return ResolutionResult(
            name=name,
            resolution=Resolution.LOOKALIKE,
            resembles=resembles,
            detail=f"resolves, but is within {MAX_TYPO_DISTANCE} edits of {resembles!r}",
        )
    return ResolutionResult(name=name, resolution=Resolution.EXISTS, detail="exact match")
