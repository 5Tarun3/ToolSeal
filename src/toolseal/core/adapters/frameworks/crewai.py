"""CrewAI: the framework where translation actually costs something.

LangGraph proves the pipeline works. CrewAI proves it is needed. Probe P0
measured that `crewai-tools` drops all fifteen annotation properties and
rewrites every tool description, so a tool its author marked destructive arrives
here indistinguishable from a read-only one.

That makes this adapter the second target the expressiveness lattice needs. With
one target, "lossless translation" is untested by construction; with two that
differ, lowering has to make a real decision and the compensating guards have
something to compensate for.

Model naming differs from every other framework here: CrewAI routes through
LiteLLM, which identifies a model as `provider/model`. That prefix is added at
render time rather than stored on the provider, because it is CrewAI's
convention and no other framework wants it.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from toolseal.core.adapters.base import Provider as ProviderProtocol
from toolseal.core.adapters.base import RenderedFile, ScaffoldSpec
from toolseal.core.adapters.frameworks.langgraph import _env_body, _package_name, _provider_note
from toolseal.core.translate.lattice import profile
from toolseal.errors import UsageError
from toolseal.templates import common
from toolseal.templates import crewai as tpl

# Pinned exactly, not floated: a generated project must satisfy C1 the moment it
# is created, and these are the versions the cell was verified against.
FRAMEWORK_PACKAGES: Final = ("crewai==1.15.14",)


@dataclass(frozen=True)
class _Integration:
    """How CrewAI reaches one provider through LiteLLM."""

    litellm_prefix: str
    packages: tuple[str, ...] = ()


# LiteLLM identifies models as `provider/model`. Adding a provider means adding
# a row here and nothing else.
_INTEGRATIONS: Final[dict[str, _Integration]] = {
    "ollama": _Integration(litellm_prefix="ollama"),
    "openai": _Integration(litellm_prefix="openai"),
    "anthropic": _Integration(litellm_prefix="anthropic"),
}


class CrewAIFramework:
    """Renders a CrewAI project with secure defaults."""

    id: Final = "crewai"
    display_name: Final = "CrewAI"

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
        """Framework and provider requirements, all constrained.

        CrewAI reaches providers through LiteLLM, which it already depends on,
        so unlike LangGraph there is no per-provider integration package.
        """
        integration = self._integration(provider)
        return (*FRAMEWORK_PACKAGES, *integration.packages, *provider.packages())

    def expressible_properties(self) -> frozenset[str]:
        """Taken from the lattice, which P0 measured against a live adapter.

        This set is deliberately small - CrewAI can carry input constraints and
        nothing else - and that is what forces lowering to emit guards.
        """
        return frozenset(str(prop) for prop in profile("crewai").expressible)

    def render(self, spec: ScaffoldSpec, provider: ProviderProtocol) -> tuple[RenderedFile, ...]:
        """Produce every file of the project. Touches no filesystem."""
        integration = self._integration(provider)
        model = spec.model or provider.default_model

        if not provider.supports_model(model):
            message = f"{provider.display_name} does not accept model {model!r}"
            raise UsageError(message)

        substitutions = {
            "project_name": spec.project_name,
            "package_name": _package_name(spec.project_name),
            "crewai_model": f"{integration.litellm_prefix}/{model}",
            "base_url": spec.base_url or provider.default_base_url,
        }

        requirements = "\n".join(self.packages(provider)) + "\n"

        return (
            RenderedFile(PurePosixPath("agent.py"), tpl.AGENT_PY.substitute(substitutions)),
            RenderedFile(PurePosixPath("tools.py"), tpl.TOOLS_PY.substitute(substitutions)),
            RenderedFile(
                PurePosixPath("guards.py"),
                common.GUARDS_PY.substitute(substitutions),
            ),
            RenderedFile(PurePosixPath("requirements.txt"), requirements),
            RenderedFile(
                PurePosixPath(".env.example"),
                common.ENV_EXAMPLE.substitute(env_body=_env_body(provider)),
            ),
            RenderedFile(
                PurePosixPath("README.md"),
                common.README_MD.substitute(
                    project_name=spec.project_name,
                    framework_name=self.display_name,
                    provider_name=provider.display_name,
                    provider_note=_provider_note(provider),
                ),
            ),
            RenderedFile(PurePosixPath("workspace/.gitkeep"), ""),
        )
