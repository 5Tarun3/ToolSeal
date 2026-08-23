"""Source templates for a Claude Code project.

Only prose and configuration: Claude Code is a runtime rather than a library, so
there is no generated Python here at all. That is what makes it the clearest
case for the project's argument - every security property is in a settings file.
"""

from __future__ import annotations

from string import Template

INSTRUCTIONS = Template("""# $project_name

Managed by toolseal. Provider: $provider_name.

## Permissions and the sandbox

Tool permissions live in `.claude/settings.json`. They cover Claude's
built-in file tools (Read, Edit, Write) and Bash commands Claude Code
recognises - `cat`, `head`, `tail`, `sed`, and the three named below - and
that is a real boundary, but not the whole of this project's security
posture: it stops at the edge of what the rules can recognise.

| Rule set | Purpose | Check |
| --- | --- | --- |
| `allow` | An explicit tool list, not a wildcard | `B1` |
| `ask` | Anything that writes or is destructive | `F2` |
| `deny` | Credential files, outside-project paths, `curl`/`wget`/`rm -rf` | `A1`, `B2`, `B3` |

Deny beats allow. Widening `allow` is allowed and `toolseal audit` will report
it; the point is that the change is visible rather than silent.

A permission rule matches command text, not behaviour: it cannot see inside a
subprocess that opens a file itself. `python -c "print(open('.env').read())"`
reads the same file `cat .env` is denied from reading, and the `deny` rule
above never sees it happen. `.claude/settings.json` also declares a
`sandbox` block for exactly this gap - once it is running, every Bash
subprocess and everything it spawns is confined at the operating-system
level, independent of how it touches a file. The sandbox engages on macOS,
Linux and WSL2. **On native Windows it does not engage at all**; the block
is still written so the same settings work unchanged if the project later
runs somewhere the sandbox supports, and `toolseal add framework
claude-code` said so plainly when this project was scaffolded if that was
the platform at the time.

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
