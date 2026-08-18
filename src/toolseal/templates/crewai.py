"""Source templates for a CrewAI project.

CrewAI is the target where translation actually costs something. Probe P0
measured that its MCP adapter drops every annotation hint and rewrites every
tool description, so a tool lowered into CrewAI arrives without the
`destructiveHint` its author declared.

The generated project is therefore shaped to make that recoverable: it imports
the same `guards.py` every framework gets, so the approval decorator the
translation layer emits as a compensating guard is already available, and the
author's description is kept verbatim where a reviewer can see it.
"""

from __future__ import annotations

from string import Template

AGENT_PY = Template('''"""Entry point for $project_name.

Generated with secure defaults. Lines marked with a check id are the reason this
project audits clean; changing them is allowed, and `toolseal audit` will notice.
"""

from __future__ import annotations

import logging
import sys

from crewai import LLM, Agent, Crew, Task

from agent_config import BASE_URL, MODEL
from guards import configure_logging
from tools import TOOLS

log = logging.getLogger("$package_name")

# E3: a wall-clock bound on every provider call. Without one, a hung endpoint
# hangs the crew forever and there is no way to notice from inside.
REQUEST_TIMEOUT_SECONDS = 60.0

# E3: bounds the tool-calling loop. An agent that cannot terminate is a
# resource-exhaustion bug (OWASP LLM10 Unbounded Consumption).
MAX_ITERATIONS = 15

# CrewAI routes through LiteLLM, which identifies a model as `provider/model`.
# The prefix is CrewAI's own convention, fixed for this provider at scaffold
# time; the model id itself comes from `agent_config`, which reads it from
# `toolseal.toml` rather than from a value frozen into this file.
LITELLM_PREFIX = "$litellm_prefix"


def build_llm() -> LLM:
    """Construct the LLM binding.

    The model and its endpoint come from `agent_config`, which reads
    `toolseal.toml` - the one place this project records them - rather than
    from a value frozen into this file when it was scaffolded.
    """
    return LLM(
        model=f"{LITELLM_PREFIX}/{MODEL}",
        base_url=BASE_URL,
        temperature=0,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )


def build_agent() -> Agent:
    """Construct the agent with an explicit, minimal tool set."""
    return Agent(
        role="$project_name assistant",
        goal="Answer the request using only the tools provided.",
        backstory="A focused assistant that prefers its tools over guessing.",
        llm=build_llm(),
        # B1: an explicit tool list, not every tool in scope. Binding everything
        # to every agent is the overprovisioning default this scaffold avoids.
        tools=list(TOOLS),
        # E3: without this the crew can loop until the provider bill notices.
        max_iter=MAX_ITERATIONS,
        allow_delegation=False,
        verbose=False,
    )


def main(argv: list[str] | None = None) -> int:
    configure_logging()

    args = list(sys.argv[1:] if argv is None else argv)
    prompt = " ".join(args).strip()
    if not prompt:
        print("usage: python agent.py <prompt>", file=sys.stderr)
        return 2

    agent = build_agent()
    task = Task(
        description=prompt,
        expected_output="A short, direct answer.",
        agent=agent,
    )

    try:
        result = Crew(agents=[agent], tasks=[task], verbose=False).kickoff()
    except Exception:
        # The provider endpoint is the most common failure and its exceptions
        # can carry request context, so this is logged rather than printed raw.
        log.exception("crew run failed")
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''')


TOOLS_PY = Template('''"""Tools available to $project_name.

Add tools here. Two rules the audit enforces:

* No shell or code-execution tool without a justification recorded in
  `toolseal.toml` (check B2).
* Filesystem tools stay inside the workspace (check B3).

CrewAI rewrites tool descriptions when it registers them, so the text the model
reads is not the text written here. That is check G5, and it is why anything a
reviewer needs to trust belongs in the code rather than in the description.
"""

from __future__ import annotations

from pathlib import Path

from crewai.tools import tool

from agent_config import TOOL_NAMES

# B3: filesystem access is rooted at the project workspace, not at "/" or "~".
WORKSPACE = (Path(__file__).resolve().parent / "workspace").resolve()


@tool("read_workspace_file")
def read_workspace_file(relative_path: str) -> str:
    """Read a UTF-8 text file from the project workspace."""
    target = (WORKSPACE / relative_path).resolve()

    # B3: confinement is enforced after resolution, so `../` and symlinks cannot
    # walk out of the workspace. Checking the string before resolving would not.
    if not target.is_relative_to(WORKSPACE):
        message = f"path escapes the workspace: {relative_path!r}"
        raise ValueError(message)
    if not target.is_file():
        message = f"no such file in workspace: {relative_path!r}"
        raise FileNotFoundError(message)

    return target.read_text(encoding="utf-8")


_ALL_TOOLS = (read_workspace_file,)

# B1: the explicit set bound to the agent, narrowed to the names
# `toolseal.toml` enables so this file agrees with every other framework
# entrypoint in the project rather than keeping its own copy of the decision.
TOOLS = tuple(candidate for candidate in _ALL_TOOLS if candidate.name in TOOL_NAMES)
''')
