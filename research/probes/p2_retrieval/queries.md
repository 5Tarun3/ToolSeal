# P2 - Retrieval evaluation: pre-registered queries

**Fixed in writing before the ranker exists.** As of this commit there is no
BM25 implementation, no tokenizer, and no scoring function in the codebase:
`RegistryIndex.search` is still the substring matcher this evaluation is meant
to measure against. The queries and their expected answers below were written
first, deliberately, so a later reader can check the ranker against a document
that predates it rather than against a judgment set adjusted afterwards to
match whatever the ranker happened to return.

This follows the ordering already used by
[`research/registry-curation-criteria.md`](../../registry-curation-criteria.md)
and `research/studies/s1/selection-criteria.md`.

## Threat to validity, stated up front

The same author wrote these queries and will write the ranker. Committing the
queries first fixes the *temporal* order but not the *authorship*, and no
amount of process makes a self-graded benchmark into an independent one.

Two things reduce, but do not eliminate, the risk:

1. **Queries are phrased as user intent, not as tool vocabulary.** Where a
   query happens to share words with its expected tool's name, that is a
   property of the tool, not a choice made here. Several queries deliberately
   use none of the target tool's name words at all - "close a bug", "why is
   this error happening", "what did I look at recently" - because the
   interesting retrieval cases are the ones where the name does not help.
2. **No query was run against any implementation before being written down.**
   The baseline numbers in `RESULTS.md` are the first execution of this set.

A reader who does not accept those mitigations should treat the headline
numbers as an upper bound and the per-query table as the actual evidence.

## Corpus

The 92 tools captured by probe `P1` from three production MCP servers -
Sentry (9), Notion (28), Linear (55) - in
`research/probes/p1_remote_mcp_annotations/results/`. Tool ids below are
`<server>:<tool name>` exactly as that capture records them.

This corpus is small and vendor-skewed: three servers, all commercial SaaS,
all English. It is enough to measure whether a ranking change helps or hurts.
It is not enough to claim anything about the MCP ecosystem, and no claim of
that kind is made from it.

## Metrics

- **MRR** over `primary` - the reciprocal rank of the single best answer.
- **recall@5** over `relevant` - what fraction of acceptable answers appear in
  the top five.

`primary` is the one tool a user asking that question most likely wants.
`relevant` is every tool that would be a defensible answer, `primary`
included. Relevance is binary; there are no graded scores to tune.

Where a query has more than one genuinely equal answer across servers - "add a
comment" is answerable by both Notion and Linear - `primary` names the one
whose description most directly states that purpose, and the others sit in
`relevant`. Those cases are marked `ambiguous` and reported separately, since
a ranker cannot be faulted for choosing a different reasonable one.

## Queries

| # | Query | Primary | Also relevant | Notes |
| --- | --- | --- | --- | --- |
| 1 | close a bug | `sentry:update_issue` | `linear:save_issue` | neither name contains "close" or "bug" |
| 2 | why is this error happening | `sentry:analyze_issue_with_seer` | `sentry:search_issues` | root-cause intent |
| 3 | search my notes | `notion:notion-search` | `notion:notion-query-meeting-notes` | |
| 4 | upload a file | `notion:notion-create-file-upload` | `notion:notion-create-attachment`, `linear:prepare_attachment_upload`, `linear:create_attachment_from_upload` | ambiguous |
| 5 | who is on my team | `linear:list_users` | `linear:list_teams`, `linear:get_team`, `notion:notion-get-users` | ambiguous |
| 6 | create a new page | `notion:notion-create-pages` | `notion:notion-duplicate-page` | |
| 7 | review a pull request | `linear:submit_diff_review` | `linear:get_diff`, `linear:list_diffs`, `linear:get_diff_threads` | "diff" is Linear's word for PR |
| 8 | merge a PR | `linear:merge_diff` | `linear:get_diff` | |
| 9 | list open tickets | `linear:list_issues` | `linear:list_issue_statuses` | "ticket" appears in no tool |
| 10 | add a comment | `linear:save_comment` | `notion:notion-create-comment`, `linear:save_diff_comment` | ambiguous |
| 11 | query a database with SQL | `notion:notion-query-data-sources` | `notion:notion-create-database`, `notion:notion-update-data-source` | |
| 12 | what did I look at recently | `notion:notion-list-recent-pages` | | no shared words with the name |
| 13 | delete a comment | `linear:delete_comment` | `linear:delete_diff_comment` | |
| 14 | track release progress | `linear:list_releases` | `linear:get_release`, `linear:list_release_pipelines`, `linear:get_status_updates` | ambiguous |
| 15 | how many errors happened this week | `sentry:search_events` | `sentry:search_issues` | counts/statistics intent |
| 16 | assign an issue to someone | `sentry:update_issue` | `linear:save_issue` | ambiguous |
| 17 | read the documentation | `linear:search_documentation` | | |
| 18 | project status report | `linear:get_status_updates` | `linear:save_status_update`, `linear:get_project` | |
| 19 | move a page somewhere else | `notion:notion-move-pages` | `notion:notion-duplicate-page` | |
| 20 | milestones in a project | `linear:list_milestones` | `linear:get_milestone`, `linear:save_milestone` | |

## What would count as failure

Stated in advance so the result cannot be reinterpreted after the fact:

- The substring baseline is expected to score near zero on MRR, because it
  matches only contiguous, correctly-ordered substrings. Queries 1, 9 and 12
  share no contiguous phrase with their target at all.
- A ranker that does not beat the baseline on **both** MRR and recall@5 has
  not justified replacing it.
- Queries 12 and 9 are the honest test. Both ask for a tool whose name shares
  no word with the query. A term-frequency ranker can only find them through
  the description. If those two fail while keyword-heavy queries pass, the
  right conclusion is that the ranker does lexical matching well and nothing
  more - which is a real limit worth reporting, not a bug to tune away.
