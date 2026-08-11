# P0 - Translation fidelity probe

Generated: 2026-08-11T20:39:15+00:00

## Versions under test

| package | version |
| --- | --- |
| `mcp` | 1.28.1 |
| `langchain-mcp-adapters` | 0.3.2 |
| `langchain-core` | 1.5.4 |
| `crewai` | 1.15.14 |
| `crewai-tools` | 1.15.14 |
| `pydantic` | 2.12.5 |

## Verdict counts

| adapter / family | preserved | dropped | mutated | unknown |
| --- | --- | --- | --- | --- |
| crewai-tools / annotation | 0 | 15 | 0 | 0 |
| crewai-tools / constraint | 7 | 0 | 0 | 0 |
| crewai-tools / description | 0 | 0 | 3 | 0 |
| langchain-mcp-adapters / annotation | 15 | 0 | 0 | 0 |
| langchain-mcp-adapters / constraint | 7 | 0 | 0 | 0 |
| langchain-mcp-adapters / description | 3 | 0 | 0 | 0 |
| langchain-mcp-adapters / enforcement | 0 | 2 | 0 | 0 |
| langchain-mcp-adapters / error_semantics | 0 | 0 | 2 | 0 |

## Losses and mutations

| adapter | tool | property | verdict | note |
| --- | --- | --- | --- | --- |
| langchain-mcp-adapters | `read_document` | `enforcement.pattern` | **dropped** | no client-side rejection; the invalid call reached the server, which rejected it and returned the error as ordinary tool content |
| langchain-mcp-adapters | `read_document` | `error_semantics.isError` | **mutated** | MCP error result surfaced as tool content, not as an exception |
| langchain-mcp-adapters | `delete_records` | `enforcement.enum` | **dropped** | no client-side rejection; the invalid call reached the server, which rejected it and returned the error as ordinary tool content |
| langchain-mcp-adapters | `delete_records` | `error_semantics.isError` | **mutated** | MCP error result surfaced as tool content, not as an exception |
| crewai-tools | `delete_records` | `annotation.readOnlyHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `delete_records` | `annotation.destructiveHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `delete_records` | `annotation.idempotentHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `delete_records` | `annotation.openWorldHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `delete_records` | `annotation.title` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `delete_records` | `description` | **mutated** | author's text retained but adapter added content around it |
| crewai-tools | `read_document` | `annotation.readOnlyHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `read_document` | `annotation.destructiveHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `read_document` | `annotation.idempotentHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `read_document` | `annotation.openWorldHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `read_document` | `annotation.title` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `read_document` | `description` | **mutated** | author's text retained but adapter added content around it |
| crewai-tools | `search_web` | `annotation.readOnlyHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `search_web` | `annotation.destructiveHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `search_web` | `annotation.idempotentHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `search_web` | `annotation.openWorldHint` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `search_web` | `annotation.title` | **dropped** | no carrier on the translated tool holds this hint |
| crewai-tools | `search_web` | `description` | **mutated** | author's text retained but adapter added content around it |
