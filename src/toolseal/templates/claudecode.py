"""Source templates for a Claude Code project.

Only prose and configuration: Claude Code is a runtime rather than a library, so
there is no generated Python here at all. That is what makes it the clearest
case for the project's argument - every security property is in a settings file.
"""

from __future__ import annotations

from string import Template

INSTRUCTIONS = Template("""# $project_name

Managed by toolseal. Provider: $provider_name.

## Permissions

Tool permissions live in `.claude/settings.json` and are the whole of this
project's security posture - there is no application code to secure.

| Rule set | Purpose | Check |
| --- | --- | --- |
| `allow` | An explicit tool list, not a wildcard | `B1` |
| `ask` | Anything that writes or is destructive | `F2` |
| `deny` | Credential files, paths outside the project, arbitrary execution | `A1`, `B2`, `B3` |

Deny beats allow. Widening `allow` is allowed and `toolseal audit` will report
it; the point is that the change is visible rather than silent.

## Undoing this

toolseal recorded every file it wrote, together with a backup of anything that
already existed:

```bash
toolseal revert
```

It refuses if you have edited a managed file since, so your changes are never
discarded without a second, explicit decision.

## Verifying it

```bash
toolseal audit
```
""")
