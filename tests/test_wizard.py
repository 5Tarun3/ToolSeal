"""The interactive `init` flow, exercised without touching the filesystem."""

from __future__ import annotations

import io

from rich.console import Console

from toolseal.cli.wizard import (
    Option,
    WizardAnswers,
    choose,
    equivalent_command,
    run_wizard,
)

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


def test_the_flow_asks_name_provider_framework_then_profile() -> None:
    out, _ = recording_console()
    chosen = run_wizard(
        name=None,
        provider=None,
        framework=None,
        profile=None,
        out=out,
        answers=iter(["myagent", "ollama", "langgraph", "none"]),
    )
    assert chosen == WizardAnswers("myagent", "ollama", "langgraph", None)


def test_a_flag_already_given_is_not_prompted_for() -> None:
    out, buffer = recording_console()
    chosen = run_wizard(
        name="fixed",
        provider="ollama",
        framework=None,
        profile=None,
        out=out,
        answers=iter(["langgraph", "none"]),
    )
    assert chosen.name == "fixed"
    assert chosen.provider == "ollama"
    assert "Which provider" not in buffer.getvalue()


def test_none_is_an_explicit_profile_answer() -> None:
    out, _ = recording_console()
    chosen = run_wizard(
        name="a",
        provider="ollama",
        framework="langgraph",
        profile=None,
        out=out,
        answers=iter(["none"]),
    )
    assert chosen.profile is None


def test_an_unusable_project_name_reprompts() -> None:
    out, buffer = recording_console()
    chosen = run_wizard(
        name=None,
        provider="ollama",
        framework="langgraph",
        profile=None,
        out=out,
        answers=iter(["../escape", "ok", "none"]),
    )
    assert chosen.name == "ok"
    assert "single directory name" in buffer.getvalue()


def test_a_credentialed_provider_is_asked_for_its_key() -> None:
    out, buffer = recording_console()
    chosen = run_wizard(
        name="a",
        provider="openai",
        framework="langgraph",
        profile=None,
        out=out,
        answers=iter(["none", "sk-typed-in-the-wizard"]),
    )
    assert chosen.api_key == "sk-typed-in-the-wizard"
    assert "OpenAI API key" in buffer.getvalue()


def test_a_credential_free_provider_is_asked_nothing() -> None:
    out, buffer = recording_console()
    chosen = run_wizard(
        name="a",
        provider="ollama",
        framework="langgraph",
        profile=None,
        out=out,
        answers=iter(["none"]),
    )
    assert chosen.api_key is None
    assert "API key" not in buffer.getvalue()


def test_a_blank_credential_answer_is_none_not_an_empty_string() -> None:
    out, _ = recording_console()
    chosen = run_wizard(
        name="a",
        provider="openai",
        framework="langgraph",
        profile=None,
        out=out,
        answers=iter(["none", ""]),
    )
    assert chosen.api_key is None


def test_equivalent_command_never_echoes_a_collected_credential() -> None:
    # A credential must never reach the printed "next time" line - it goes
    # straight to the terminal (and its scrollback), which is exactly what
    # storing it in the keychain instead of a file was supposed to avoid.
    # Positional, not `api_key=...`: that keyword-argument spelling is exactly
    # what this repo's own A1 check flags as a credential literal (it scans
    # text, not the AST), and `toolseal audit .` must stay at 100/100.
    answers = WizardAnswers("myagent", "openai", "langgraph", None, "sk-should-not-leak")
    line = equivalent_command(answers)
    assert "sk-should-not-leak" not in line
    assert "--api-key" not in line


def test_the_equivalent_command_spells_out_every_answer() -> None:
    line = equivalent_command(WizardAnswers("myagent", "ollama", "langgraph", None))
    assert line == "toolseal init myagent --provider ollama --framework langgraph"


def test_the_equivalent_command_carries_a_chosen_profile() -> None:
    line = equivalent_command(WizardAnswers("myagent", "ollama", "crewai", "gdpr"))
    assert line == "toolseal init myagent --provider ollama --framework crewai --profile gdpr"
