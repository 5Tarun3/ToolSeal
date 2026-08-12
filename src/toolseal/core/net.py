"""A small, deliberate HTTP client.

Built on the standard library rather than on `requests` or `httpx`, for reasons
that matter more than convenience: this is a supply-chain security tool, and
every dependency it adds is one more thing it must then audit in itself. The
surface needed here - JSON GET and POST with a timeout - is about forty lines.

Three properties are enforced rather than assumed:

* **https only.** `urlopen` honours `file:` and other schemes, so a URL that
  becomes configurable later must not turn into a local file read.
* **Bounded.** Every request has a timeout and a response size cap. A registry
  that hangs, or answers with a gigabyte, must not take the audit with it.
* **Identified.** Requests carry a user agent naming the tool, so registry
  operators can see who is crawling them and rate-limit rather than block.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Final

from toolseal import __version__

USER_AGENT: Final = f"toolseal/{__version__} (+https://github.com/5Tarun3/ToolSeal)"
DEFAULT_TIMEOUT: Final = 15.0
MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024


class HttpError(RuntimeError):
    """A request failed, or the response could not be used."""


class NotFoundError(HttpError):
    """The resource does not exist. Distinct because absence is often the answer."""


# Loopback is exempt from the https requirement, matching check D1. Plaintext
# to localhost never traverses a network, and refusing it makes the client
# unusable against exactly the local runtimes this project targets - which is
# how a whole study came back with every sample "excluded" for the wrong reason.
LOOPBACK_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _is_loopback(parsed: urllib.parse.ParseResult) -> bool:
    return (parsed.hostname or "") in LOOPBACK_HOSTS


def _require_https(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return
    if parsed.scheme == "http" and _is_loopback(parsed):
        return
    message = f"refusing a non-https request: {url}"
    raise HttpError(message)


def _open(url: str, *, data: bytes | None, timeout: float) -> bytes:
    _require_https(url)

    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"

    # S310: _require_https above rejects every scheme but https, so the
    # file:/custom-scheme concern this rule exists for cannot reach here.
    request = urllib.request.Request(url, data=data, headers=headers)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return bytes(response.read(MAX_RESPONSE_BYTES))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            message = f"not found: {url}"
            raise NotFoundError(message) from None
        message = f"{url} returned HTTP {exc.code}"
        raise HttpError(message) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        message = f"{url} was unreachable ({type(exc).__name__})"
        raise HttpError(message) from None


def get_json(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> Any:
    """GET *url* and parse the body as JSON."""
    return _parse(_open(url, data=None, timeout=timeout), url)


def post_json(url: str, payload: Any, *, timeout: float = DEFAULT_TIMEOUT) -> Any:
    """POST *payload* as JSON to *url* and parse the response."""
    body = json.dumps(payload).encode("utf-8")
    return _parse(_open(url, data=body, timeout=timeout), url)


def _parse(raw: bytes, url: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        message = f"{url} did not return valid JSON"
        raise HttpError(message) from None


def exists(url: str, *, timeout: float = DEFAULT_TIMEOUT) -> bool:
    """Whether *url* resolves.

    A transport failure is re-raised rather than reported as absence: treating
    "the network is down" as "this package does not exist" would turn a
    connectivity blip into a verification result.
    """
    try:
        _open(url, data=None, timeout=timeout)
    except NotFoundError:
        return False
    return True
