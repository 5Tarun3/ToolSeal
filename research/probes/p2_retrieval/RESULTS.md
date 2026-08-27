# P2 - Retrieval evaluation: results

Measured with `bench/retrieval_eval.py` over the twenty queries fixed in
[`queries.md`](queries.md), against the 92 tools captured by
[P1](../p1_remote_mcp_annotations/README.md) from Sentry (9), Notion (28) and
Linear (55).

Reproduce with:

```bash
uv run python bench/retrieval_eval.py
```

## Headline

| Ranker | MRR | recall@5 |
| --- | --- | --- |
| substring (shipped before this work) | **0.000** | 0.042 |
| BM25, as pre-registered | 0.575 | 0.633 |
| BM25 + stopwords (post-hoc) | 0.579 | 0.696 |
| BM25 + stopwords + stemming (post-hoc) | **0.604** | **0.717** |

The baseline scores exactly zero on MRR. That is not a rounding artefact: the
substring matcher tests the whole query as one contiguous, correctly-ordered
needle, and not one of the twenty queries appears verbatim inside any tool's
name or description. `queries.md` predicted "near zero" before the run; the
true figure is zero.

## The stopword change was made after seeing these numbers

`queries.md` was committed before any ranker existed. The BM25 row above is
the result that pre-registration covers. The third row is not, and saying so
is the point of reporting it separately.

After the first run, query 5 ("who is on my team") returned
`sentry:update_issue` as its top hit. The cause was diagnosable rather than
mysterious: across the 92 descriptions, `who` occurs in 2 and `team` in 9, so
idf scored the function word at 3.62 against the content word's 2.28. BM25 was
ranking the query on its least meaningful term, because idf assumes rare
implies informative, which for function words is false.

Dropping a conventional English stopword list - taken as published, not pruned
to suit this corpus - moved the numbers as follows:

- **recall@5: 0.633 to 0.696.** A real improvement. Query 5's top hit becomes
  `linear:get_team`, which is a defensible answer.
- **MRR: 0.575 to 0.579.** Almost nothing.

That asymmetry is the honest summary: removing function words stops the
ranker producing obviously-wrong *top* hits, but it does not make it find the
*right* one. Anyone reading this as "stopwords fixed retrieval" is reading it
wrong.

## Stemming, also post-hoc

Added later still, and prompted by the utility-coverage set rather than by
these queries: "Read, write and search files" did not match the query "file",
so the filesystem server was unreachable by the most obvious thing anyone
would ask it for, and "sprites" against "sprite" hid Aseprite the same way.

The rules are crude on purpose - plurals, `-ing`, `-ed`, with a four-character
floor so short words are not mauled into collisions. They fold `files`/`file`,
`sprites`/`sprite`, `queries`/`query` and `running`/`run`. They do not fold
`managed`/`manage`, which a full Porter stemmer also fails to fold, since its
step 1b restores a trailing `e` only after `at`, `bl` or `iz`.

It moved this pre-registered set as well as the corpus that prompted it -
MRR 0.579 to 0.604, recall@5 0.696 to 0.717. That the improvement shows up on
queries written before any of this existed is the only reason it is reported
as an improvement rather than as fitting.

## Where it still fails, and why

Four queries score 0.00 or near it after both changes. They are not randomly
distributed - three are the cases `queries.md` nominated in advance as the
honest test.

| # | Query | Primary | Top hit | Diagnosis |
| --- | --- | --- | --- | --- |
| 1 | close a bug | `sentry:update_issue` | `notion:notion-create-view` | no tool contains "close" or "bug" |
| 9 | list open tickets | `linear:list_issues` | `notion:notion-create-view` | no tool contains "ticket" |
| 5 | who is on my team | `linear:list_users` | `linear:get_team` | plausible answer, not the primary |
| 14 | track release progress | `linear:list_releases` | `linear:save_release` | right subject, wrong verb |

Queries 1 and 9 are vocabulary mismatches: the user's word for the concept and
the vendor's word for it share no token. A lexical ranker cannot bridge that,
and no amount of weighting will make it. This is the limitation `queries.md`
said would be the real test, and it is a limitation of the *method*, not a bug
in the implementation. Closing it needs either an embedding model - a
dependency and a download this project has ruled out - or vocabulary
enrichment from the tool's own schema and error strings, which is future work
and is not claimed here.

Queries 5 and 14 fail differently and more mildly: the ranker finds the right
*area* and picks a sibling. `get_team` for "who is on my team" and
`save_release` for "track release progress" are both in the relevant set, which
is why recall@5 is much healthier than MRR. Whether that counts as failure
depends on whether the user wanted an answer or a specific tool.

## What this does and does not support

**Supports:** replacing the substring matcher. Zero MRR is not a baseline any
change has to work hard to beat, but the margin here is not marginal, and the
per-query table shows the wins are spread across all three servers rather than
concentrated in one vendor's naming style.

**Does not support:** any claim about retrieval quality on the MCP ecosystem.
Three vendors, all commercial SaaS, all English, 92 tools. The corpus is what
three OAuth accounts could reach, not a sample of anything.

**Does not support** a claim that this ranking is well-tuned. `K1` and `B` are
the textbook defaults and were never adjusted; field weights (name 3.0,
description 1.0, server 0.5) were set by argument, not by search. Tuning either
against these twenty queries would make the numbers better and the evidence
worthless, which is the trade the pre-registration exists to refuse.
