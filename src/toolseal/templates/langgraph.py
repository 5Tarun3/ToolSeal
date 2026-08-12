"""Source templates for a LangGraph project.

These are ``string.Template`` rather than f-strings or Jinja, for two reasons.
The output is Python source full of braces, which an ``str.format`` template
would fight; and ``$`` placeholders cannot appear by accident in generated code,
so a substitution bug is a loud :class:`KeyError` rather than a silent literal.

Every security-relevant line in the generated project carries the check id it
satisfies. A developer who deletes one should be able to see what they are
deleting, and `toolseal audit` will say the same thing later.
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

from langchain.agents import create_agent
from $chat_module import $chat_class

from guards import configure_logging
from tools import TOOLS

log = logging.getLogger("$package_name")

# E3: a wall-clock bound on every provider call. Without one, a hung endpoint
# hangs the agent forever and there is no way to notice from inside.
REQUEST_TIMEOUT_SECONDS = 60.0

# E3: bounds the tool-calling loop. An agent that cannot terminate is a
# resource-exhaustion bug (OWASP LLM10 Unbounded Consumption).
RECURSION_LIMIT = 25


def build_agent():
    """Construct the agent with an explicit, minimal tool set."""
    model = $chat_class(
        model="$model",
        base_url="$base_url",
        temperature=0,
        $timeout_kwarg,
    )

    # B1: an explicit tool list, not every tool in scope. Binding everything to
    # every session is the overprovisioning default this scaffold avoids.
    return create_agent(model, list(TOOLS))


def main(argv: list[str] | None = None) -> int:
    configure_logging()

    args = list(sys.argv[1:] if argv is None else argv)
    prompt = " ".join(args).strip()
    if not prompt:
        print("usage: python agent.py <prompt>", file=sys.stderr)
        return 2

    agent = build_agent()
    try:
        result = agent.invoke(
            {"messages": [{"role": "user", "content": prompt}]},
            config={"recursion_limit": RECURSION_LIMIT},
        )
    except Exception:
        # The provider endpoint is the most common failure and its exceptions
        # can carry request context, so this is logged rather than printed raw.
        log.exception("agent run failed")
        return 1

    for message in result["messages"]:
        log.debug("%s: %s", type(message).__name__, message.content)
    print(result["messages"][-1].content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
''')


TOOLS_PY = Template('''"""Tools available to $project_name.

Add tools here. Two rules the audit enforces:

* No shell or code-execution tool without a justification recorded in
  `toolseal.toml` (check B2).
* Filesystem tools stay inside the workspace (check B3).
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.tools import tool

# B3: filesystem access is rooted at the project workspace, not at "/" or "~".
WORKSPACE = (Path(__file__).resolve().parent / "workspace").resolve()


@tool
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


# B1: the explicit set bound to the agent. Adding a tool here is a deliberate
# act, which is the point.
TOOLS = (read_workspace_file,)
''')


# Shared with every other framework: guards, the env example, and the readme
# are not LangGraph-specific, and a second copy would drift.
from toolseal.templates.common import (  # noqa: E402
    ENV_EXAMPLE,
    GUARDS_PY,
    README_MD,
)

__all__ = ["AGENT_PY", "ENV_EXAMPLE", "GUARDS_PY", "README_MD", "TOOLS_PY"]
