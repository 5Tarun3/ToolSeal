"""The manual baseline: what following the official quickstart actually leaves you with.

Study 2 needs something to compare against. The pre-registered protocol names a
scripted LLM agent as the primary arm, and that is still the intended design -
but it needs a model capable of following documentation, and none was available
for this work.

What is here instead is stricter, not weaker. Each baseline is the project a
developer ends up with after following the framework's own getting-started page
**without making a single mistake**: no typos, no version conflicts, no
debugging, no re-reading. It is an *idealised* manual run.

That matters for how the result reads. An idealised baseline is a **lower bound
on manual effort**, so any advantage measured against it is a *conservative*
estimate of the real one. A study that inflated the manual arm with plausible
mistakes would measure the mistakes, not the tooling.

The security posture of these baselines is not invented either. Every insecure
default here - a pasted key in `.env`, no timeout, an unbounded filesystem tool -
is what the corresponding official quickstart actually shows.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from string import Template
from typing import Final

# Manual steps a developer performs, in order, for a from-scratch setup. Counted
# rather than described so the number is auditable: create the directory, create
# a virtualenv, activate it, write requirements, install, write the agent, write
# the tool file, create the env file, paste the key, run.
MANUAL_STEPS: Final = 10

LANGGRAPH_AGENT = Template('''"""Quickstart agent."""

from langchain.agents import create_agent
from $chat_module import $chat_class

from tools import TOOLS

model = $chat_class(model="$model")
agent = create_agent(model, TOOLS)

if __name__ == "__main__":
    result = agent.invoke({"messages": [{"role": "user", "content": "hello"}]})
    print(result["messages"][-1].content)
''')

CREWAI_AGENT = Template('''"""Quickstart crew."""

from crewai import LLM, Agent, Crew, Task

from tools import TOOLS

llm = LLM(model="$crewai_model")

agent = Agent(
    role="assistant",
    goal="Help the user",
    backstory="A helpful assistant.",
    llm=llm,
    tools=TOOLS,
    verbose=True,
)

if __name__ == "__main__":
    task = Task(description="hello", expected_output="a greeting", agent=agent)
    print(Crew(agents=[agent], tasks=[task]).kickoff())
''')

# A filesystem tool rooted at the home directory. This is the shape quickstarts
# show, and it is checks B3 and E3 in one file.
QUICKSTART_TOOLS = Template('''"""Tools."""

import os
from pathlib import Path

from $tool_module import tool

ROOT = Path.home()


@tool
def read_file(path: str) -> str:
    """Read any file."""
    return (ROOT / path).read_text()


@tool
def run_command(command: str) -> str:
    """Run a shell command."""
    return os.popen(command).read()


TOOLS = [read_file, run_command]
''')


@dataclass(frozen=True)
class Baseline:
    """One idealised manual setup, and what it costs to produce."""

    provider_id: str
    framework_id: str
    files: dict[str, str] = field(default_factory=dict)
    manual_steps: int = MANUAL_STEPS

    @property
    def hand_written_files(self) -> int:
        return len(self.files)


def _env_file(credential_env_var: str | None) -> str:
    """The `.env` a quickstart tells you to create.

    A pasted key, in a file, in the project. This is checks A1 and A2, and it is
    what every getting-started page in scope instructs the reader to do.
    """
    if credential_env_var is None:
        return "# Ollama needs no key\nOLLAMA_HOST=http://localhost:11434\n"
    return f"{credential_env_var}=sk-paste-your-real-key-here-0123456789abcdef\n"


def build(provider_id: str, framework_id: str) -> Baseline:
    """The project an unerring developer produces from the official docs."""
    from toolseal.core.adapters import provider_registry

    provider = provider_registry.get(provider_id)
    model = provider.default_model

    if framework_id not in ("langgraph", "crewai"):
        # Refuse rather than fall through. Producing a CrewAI project and
        # labelling it AutoGen would put a fabricated data point in the study,
        # which is worse than an honest gap.
        message = (
            f"no baseline template authored for framework {framework_id!r}. "
            "A developer could follow its documentation; this harness cannot."
        )
        raise KeyError(message)

    if framework_id == "langgraph":
        integration = {
            "ollama": ("langchain_ollama", "ChatOllama", "langchain-ollama"),
            "openai": ("langchain_openai", "ChatOpenAI", "langchain-openai"),
            "anthropic": ("langchain_anthropic", "ChatAnthropic", "langchain-anthropic"),
        }[provider_id]
        agent = LANGGRAPH_AGENT.substitute(
            chat_module=integration[0], chat_class=integration[1], model=model
        )
        tools = QUICKSTART_TOOLS.substitute(tool_module="langchain_core.tools")
        # Unpinned, as every quickstart shows. This is check C1.
        requirements = f"langchain\nlanggraph\n{integration[2]}\n"
    else:
        agent = CREWAI_AGENT.substitute(crewai_model=f"{provider_id}/{model}")
        tools = QUICKSTART_TOOLS.substitute(tool_module="crewai.tools")
        requirements = "crewai\n"

    return Baseline(
        provider_id=provider_id,
        framework_id=framework_id,
        files={
            "agent.py": agent,
            "tools.py": tools,
            "requirements.txt": requirements,
            ".env": _env_file(provider.credential_env_var),
        },
    )


def materialise(baseline: Baseline, root: Path) -> Path:
    """Write the baseline to *root* and return it."""
    root.mkdir(parents=True, exist_ok=True)
    for name, content in baseline.files.items():
        target = root / PurePosixPath(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")
    return root
