"""The interactive `init` flow, exercised without touching the filesystem."""

from __future__ import annotations

import io

from rich.console import Console

from toolseal.cli.wizard import Option, choose

OPTIONS = (
    Option("ollama", "Ollama", "Local runtime."),
    Option("openai", "OpenAI", "Hosted API."),
)


def recording_console() -> tuple[Console, io.StringIO]:
    buffer = io.StringIO()
    return Console(file=buffer, width=80, markup=False, highlight=False), buffer


def test_a_number_selects_that_option() -> None:
    out, _ = recording_console()
    assert choose("Provider?", OPTIONS, default="ollama", out=out, answers=iter(["2"])) == "openai"


def test_empty_input_takes_the_default() -> None:
    out, _ = recording_console()
    assert choose("Provider?", OPTIONS, default="ollama", out=out, answers=iter([""])) == "ollama"


def test_the_value_may_be_typed_in_full() -> None:
    out, _ = recording_console()
    chosen = choose("Provider?", OPTIONS, default="ollama", out=out, answers=iter(["openai"]))
    assert chosen == "openai"


def test_a_bad_answer_reprompts_rather_than_failing() -> None:
    out, buffer = recording_console()
    chosen = choose("Provider?", OPTIONS, default="ollama", out=out, answers=iter(["9", "1"]))
    assert chosen == "ollama"
    assert "not one of the options" in buffer.getvalue()


def test_the_menu_names_every_option_and_its_summary() -> None:
    out, buffer = recording_console()
    choose("Provider?", OPTIONS, default="ollama", out=out, answers=iter([""]))
    rendered = buffer.getvalue()
    assert "[1] ollama" in rendered
    assert "Local runtime." in rendered
    assert "[2] openai" in rendered
    assert "Hosted API." in rendered
    assert rendered.isascii()
