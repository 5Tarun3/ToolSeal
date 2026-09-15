"""The guided `toolseal init` flow.

`init` has nine options and sensible defaults for all of them, which is a good
property for a script and a bad one for a first-time reader: the fastest path
through the command never shows that four providers and three frameworks
exist. This module is the slower path that does.

It reads answers and returns them. It does not touch the filesystem, does not
import `core.scaffold`, and does not decide anything `init` would not have
decided from flags - so every behaviour it can produce is reachable
non-interactively, and the summary it prints at the end says exactly how.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from rich.console import Console
from rich.text import Text

from toolseal.cli._ui import accent_text, print_text
from toolseal.cli._ui import console as default_console
from toolseal.core.adapters import framework_registry, provider_registry
from toolseal.core.policy.profile import load_profiles
from toolseal.errors import UsageError

NO_PROFILE = "none"
"""The explicit "no regime" answer. Offered as a listed option rather than as
an empty reply, so declining a regime is a decision the user made rather than
one they skipped past."""


@dataclass(frozen=True)
class Option:
    """One selectable answer: the value `init` takes, and why you would pick it."""

    value: str
    label: str
    summary: str


def _read(out: Console, answers: Iterator[str] | None, *, hidden: bool = False) -> str:
    """One reply, from the injected sequence in tests or the console otherwise.

    *hidden* is passed straight through to `Console.input`'s own `password`
    flag for the credential question - typed text is not echoed to the
    terminal. Tests bypass the console entirely via the injected *answers*
    sequence, so it has no effect there.
    """
    if answers is not None:
        return next(answers, "")
    return out.input("  > ", password=hidden)


def choose(
    prompt: str,
    options: Sequence[Option],
    *,
    default: str,
    out: Console | None = None,
    answers: Iterator[str] | None = None,
) -> str:
    """Render a numbered menu and return the chosen `Option.value`.

    Accepts the index or the value spelled out; empty input takes *default*.
    Anything else re-prompts rather than raising - a typo at a prompt is not a
    usage error, it is a typo.
    """
    target = out if out is not None else default_console
    by_index = {str(number): option.value for number, option in enumerate(options, start=1)}
    by_value = {option.value: option.value for option in options}

    target.print()
    print_text(target, Text(prompt, style="heading"))
    for number, option in enumerate(options, start=1):
        row = Text(f"  [{number}] ")
        row.append_text(accent_text(option.value))
        row.append(f"  {option.summary}", style="muted")
        if option.value == default:
            row.append("  (default)", style="verdict.good")
        print_text(target, row)

    while True:
        reply = _read(target, answers).strip()
        if not reply:
            return default
        chosen = by_index.get(reply) or by_value.get(reply)
        if chosen is not None:
            return chosen
        print_text(target, Text(f"  {reply!r} is not one of the options", style="verdict.warn"))


@dataclass(frozen=True)
class WizardAnswers:
    """What the flow collected. Exactly the subset of `init`'s flags it asks about."""

    name: str
    provider: str
    framework: str
    profile: str | None
    api_key: str | None = None
    """The provider credential, if one was typed. Never echoed back anywhere -
    see `equivalent_command`, which deliberately has no line for this."""


def _provider_options() -> tuple[Option, ...]:
    return tuple(
        Option(name, adapter.display_name, adapter.summary)
        for name, adapter in ((n, provider_registry.get(n)) for n in provider_registry.names())
    )


def _framework_options() -> tuple[Option, ...]:
    return tuple(
        Option(name, adapter.display_name, adapter.summary)
        for name, adapter in ((n, framework_registry.get(n)) for n in framework_registry.names())
    )


def _profile_options() -> tuple[Option, ...]:
    listed = [Option(NO_PROFILE, "No regime", "Baseline severities only. You can add one later.")]
    for profile_id, profile in sorted(load_profiles().items()):
        listed.append(Option(profile_id, profile.name, f"Raises severities under {profile.name}."))
    return tuple(listed)


def _ask_name(out: Console, answers: Iterator[str] | None) -> str:
    """Prompt until the reply is a name `init` would accept.

    Validated here with the same rule `init` enforces, imported rather than
    restated: a wizard that happily collects a name the command then refuses
    would have wasted every question after it.
    """
    from toolseal.cli.init_command import _validate_project_name

    out.print()
    print_text(out, Text("Project name", style="heading"))
    print_text(out, Text("  A single directory name; it is created here.", style="muted"))
    while True:
        reply = _read(out, answers).strip()
        try:
            return _validate_project_name(reply)
        except UsageError as exc:
            print_text(out, Text(f"  {exc}", style="verdict.warn"))


def _ask_credential(out: Console, answers: Iterator[str] | None, provider_id: str) -> str | None:
    """The provider credential (check A1), if the chosen provider needs one.

    Stored in the OS keychain by `init`, never in a file - this question only
    exists for a provider that actually has somewhere that value needs to go.
    A local provider like Ollama needing none is asked nothing, not asked and
    then discarded.
    """
    adapter = provider_registry.get(provider_id)
    if adapter.credential_env_var is None:
        return None

    out.print()
    print_text(out, Text(f"{adapter.display_name} API key", style="heading"))
    print_text(
        out, Text("  Stored in the OS keychain; leave blank to add it later.", style="muted")
    )
    reply = _read(out, answers, hidden=True).strip()
    return reply or None


def run_wizard(
    *,
    name: str | None,
    provider: str | None,
    framework: str | None,
    profile: str | None,
    out: Console | None = None,
    answers: Iterator[str] | None = None,
) -> WizardAnswers:
    """Collect what was not already supplied. A given flag is never prompted for."""
    target = out if out is not None else default_console

    resolved_name = name if name is not None else _ask_name(target, answers)
    resolved_provider = (
        provider
        if provider is not None
        else choose(
            "Which provider should the agent talk to?",
            _provider_options(),
            default="ollama",
            out=target,
            answers=answers,
        )
    )
    resolved_framework = (
        framework
        if framework is not None
        else choose(
            "Which agent framework should be scaffolded?",
            _framework_options(),
            default="langgraph",
            out=target,
            answers=answers,
        )
    )
    resolved_profile = (
        profile
        if profile is not None
        else choose(
            "Scaffold under a regulatory regime?",
            _profile_options(),
            default=NO_PROFILE,
            out=target,
            answers=answers,
        )
    )
    api_key = _ask_credential(target, answers, resolved_provider)

    return WizardAnswers(
        name=resolved_name,
        provider=resolved_provider,
        framework=resolved_framework,
        profile=None if resolved_profile == NO_PROFILE else resolved_profile,
        api_key=api_key,
    )


def equivalent_command(chosen: WizardAnswers) -> str:
    """The non-interactive invocation that produces the same project.

    Printed after the flow finishes. This is the discoverability payoff: the
    wizard exists because the flags are invisible, so it ends by showing them.
    Every answer is spelled out, including ones that match a default - the line
    has to keep working if a default changes.

    Deliberately has no `--api-key` here even when the wizard collected one:
    this line goes straight to the terminal (and its scrollback), and echoing
    a credential back defeats the reason `init` never prints it in the first
    place. Whether it was stored is reported separately, by `init` itself.
    """
    parts = [
        "toolseal init",
        chosen.name,
        "--provider",
        chosen.provider,
        "--framework",
        chosen.framework,
    ]
    if chosen.profile is not None:
        parts += ["--profile", chosen.profile]
    return " ".join(parts)
