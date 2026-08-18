"""The templates harness: fetch is faked, root-file lookup and parsing are real."""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any

from bench.mcp_servers import Candidate
from bench.templates import fetch_root_file, run

from toolseal.core.net import HttpError

CANDIDATE = Candidate(
    full_name="acme/agent-starter",
    html_url="https://github.com/acme/agent-starter",
    stargazers_count=10,
    fork=False,
    archived=False,
    pushed_at="2026-06-01T00:00:00Z",
)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def test_root_file_present_is_fetched_and_decoded() -> None:
    def fetch_json(url: str) -> Any:
        assert url.endswith("/contents/requirements.txt")
        return {"content": _b64("crewai\n")}

    assert fetch_root_file(CANDIDATE, "requirements.txt", fetch_json=fetch_json) == "crewai\n"


def test_root_file_absent_returns_none_rather_than_inventing_one() -> None:
    def fetch_json(url: str) -> Any:
        raise HttpError("not found")

    assert fetch_root_file(CANDIDATE, "pyproject.toml", fetch_json=fetch_json) is None


def test_run_materialises_readme_plus_present_root_files(tmp_path: Path) -> None:
    readme = '```agent.py\nprint("hi")\n```\n'
    search_item = {
        "full_name": "acme/agent-starter",
        "html_url": "https://github.com/acme/agent-starter",
        "stargazers_count": 10,
        "fork": False,
        "archived": False,
        "pushed_at": "2026-06-01T00:00:00Z",
    }

    def fetch_json(url: str) -> Any:
        if "search/repositories" in url:
            return {"items": [search_item]}
        if url.endswith("/readme"):
            return {"content": _b64(readme)}
        if url.endswith("/contents/requirements.txt"):
            return {"content": _b64("crewai\n")}
        raise HttpError("not found")  # pyproject.toml, .env.example absent

    artefacts, skipped = run(tmp_path, fetch_json=fetch_json)

    assert skipped == []
    assert len(artefacts) == 1
    assert artefacts[0].materialised
    assert set(artefacts[0].files) == {"agent.py", "requirements.txt"}


def test_absent_root_files_are_not_invented(tmp_path: Path) -> None:
    readme = '```agent.py\nprint("hi")\n```\n'
    search_item = {
        "full_name": "acme/agent-starter",
        "html_url": "https://github.com/acme/agent-starter",
        "stargazers_count": 10,
        "fork": False,
        "archived": False,
        "pushed_at": "2026-06-01T00:00:00Z",
    }

    def fetch_json(url: str) -> Any:
        if "search/repositories" in url:
            return {"items": [search_item]}
        if url.endswith("/readme"):
            return {"content": _b64(readme)}
        raise HttpError("not found")

    artefacts, _skipped = run(tmp_path, fetch_json=fetch_json)

    assert set(artefacts[0].files) == {"agent.py"}
