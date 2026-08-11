# Security Policy

## Supported versions

toolseal is pre-alpha. Only the `main` branch receives fixes.

## Reporting a vulnerability

Report privately through GitHub's **Report a vulnerability** button under the
repository's Security tab. This opens a private advisory visible only to
maintainers.

Please do not open a public issue for a suspected vulnerability, and do not
include real credentials in a report — a redacted example is enough.

Useful detail: affected version or commit, reproduction steps, and what an
attacker gains.

## Scope

In scope:

- Credential disclosure by toolseal itself, including through logs or generated
  files.
- Generated configurations that are less restrictive than the taxonomy requires.
- Name resolution accepting an unverified package or MCP server.
- Registry index handling that permits tampering to reach a user.

Out of scope:

- Vulnerabilities in tools that toolseal indexes or scaffolds. Report those to
  their maintainers; tell us if our metadata is wrong.
- Missing checks. That is a feature request, not a vulnerability.
