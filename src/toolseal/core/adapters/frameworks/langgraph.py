"""LangGraph: the reference framework adapter.

Renders a project whose defaults already satisfy the taxonomy, so a freshly
scaffolded tree audits clean without anyone editing it. That is the whole
product claim in one function, which is why the generated source carries check
ids inline rather than being silently correct.

Provider integration packages are resolved here rather than by the provider,
because they are named after the *pairing* (`langchain-ollama`,
`langchain-anthropic`). A provider guessing its own integration package would be
right for exactly one framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from toolseal.core.adapters.base import Provider as ProviderProtocol
from toolseal.core.adapters.base import RenderedFile, ScaffoldSpec
from toolseal.core.translate.lattice import profile
from toolseal.errors import UsageError
from toolseal.templates import langgraph as tpl

# Pinned exactly, not floated. A generated project must satisfy C1 the moment
# it is created, and these are the versions the cell was verified against.
# Updating them is a deliberate act with a test run behind it.
FRAMEWORK_PACKAGES: Final = (
    "langchain==1.3.15",
    "langgraph==1.2.11",
)


@dataclass(frozen=True)
class _Integration:
    """How this framework reaches one provider."""

    package: str
    chat_module: str
    chat_class: str


# Adding a provider means adding a row here and nothing else.
_INTEGRATIONS: Final[dict[str, _Integration]] = {
    "ollama": _Integration("langchain-ollama==1.1.0", "langchain_ollama", "ChatOllama"),
    "openai": _Integration("langchain-openai==1.1.0", "langchain_openai", "ChatOpenAI"),
    "anthropic": _Integration("langchain-anthropic==1.1.0", "langchain_anthropic", "ChatAnthropic"),
}


def _package_name(project_name: str) -> str:
    """A logger name derived from the project name, safe as a Python identifier."""
    cleaned = "".join(char if char.isalnum() else "_" for char in project_name.strip().lower())
    cleaned = cleaned.strip("_") or "agent"
    return f"_{cleaned}" if cleaned[0].isdigit() else cleaned


class LangGraphFramework:
    """Renders a LangGraph project with secure defaults."""

    id: Final = "langgraph"
    display_name: Final = "LangGraph"

    def _integration(self, provider: ProviderProtocol) -> _Integration:
        try:
            return _INTEGRATIONS[provider.id]
        except KeyError:
            known = ", ".join(sorted(_INTEGRATIONS))
            message = (
                f"{self.display_name} has no integration for provider {provider.id!r}; "
                f"available: {known}"
            )
            raise UsageError(message) from None

    def packages(self, provider: ProviderProtocol) -> tuple[str, ...]:
        """Framework, integration and provider requirements, all constrained.

        Ordering is deterministic so that a regenerated `requirements.txt`
        produces an empty diff rather than a reshuffled one.
        """
        integration = self._integration(provider)
        return (*FRAMEWORK_PACKAGES, integration.package, *provider.packages())

    def expressible_properties(self) -> frozenset[str]:
        """Taken from the lattice, which P0 measured. Not restated here.

        Two copies of this set would eventually disagree, and the copy that
        disagreed would be the one deciding whether a guard gets emitted.
        """
        return frozenset(str(prop) for prop in profile("langchain").expressible)

    def render(self, spec: ScaffoldSpec, provider: ProviderProtocol) -> tuple[RenderedFile, ...]:
        """Produce every file of the project. Touches no filesystem."""
        integration = self._integration(provider)
        model = spec.model or provider.default_model

        if not provider.supports_model(model):
            message = f"{provider.display_name} does not accept model {model!r}"
            raise UsageError(message)

        package_name = _package_name(spec.project_name)
        substitutions = {
            "project_name": spec.project_name,
            "package_name": package_name,
            "model": model,
            "base_url": provider.default_base_url,
            "chat_module": integration.chat_module,
            "chat_class": integration.chat_class,
        }

        requirements = "\n".join(self.packages(provider)) + "\n"

        return (
            RenderedFile(PurePosixPath("agent.py"), tpl.AGENT_PY.substitute(substitutions)),
            RenderedFile(PurePosixPath("tools.py"), tpl.TOOLS_PY.substitute(substitutions)),
            RenderedFile(PurePosixPath("guards.py"), tpl.GUARDS_PY.substitute(substitutions)),
            RenderedFile(PurePosixPath("requirements.txt"), requirements),
            RenderedFile(
                PurePosixPath(".env.example"),
                tpl.ENV_EXAMPLE.substitute(env_body=_env_body(provider)),
            ),
            RenderedFile(
                PurePosixPath("README.md"),
                tpl.README_MD.substitute(
                    project_name=spec.project_name,
                    framework_name=self.display_name,
                    provider_name=provider.display_name,
                    provider_note=_provider_note(provider),
                ),
            ),
            # Keeps `workspace/` present in a fresh checkout, so the B3-confined
            # filesystem tool has somewhere to read from on first run.
            RenderedFile(PurePosixPath("workspace/.gitkeep"), ""),
        )


def _env_body(provider: ProviderProtocol) -> str:
    """Placeholders only - never a value.

    A provider needing no credential gets a comment saying so, rather than an
    empty file that reads like something is missing.
    """
    if provider.credential_env_var is None:
        return (
            f"# {provider.display_name} runs locally and needs no API key.\n"
            f"# Override the endpoint only if it is not on the default host.\n"
            f"# {provider.id.upper()}_HOST={provider.default_base_url}"
        )
    return (
        f"# Set by `toolseal init` in the OS keychain; this line documents the name only.\n"
        f"{provider.credential_env_var}="
    )


def _provider_note(provider: ProviderProtocol) -> str:
    if provider.credential_env_var is None:
        return (
            f"{provider.display_name} must be running locally at "
            f"`{provider.default_base_url}`, with the model pulled."
        )
    return (
        f"Requires `{provider.credential_env_var}`. `toolseal init` stores it in the OS "
        "keychain rather than in a file."
    )
