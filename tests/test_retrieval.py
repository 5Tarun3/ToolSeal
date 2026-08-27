"""Term-based retrieval over tool descriptors.

The behaviour being pinned here is the one the substring matcher could not
provide: a query whose terms appear in a document but not as one contiguous,
correctly-ordered phrase must still match. `research/probes/p2_retrieval/
queries.md` measures how well; these tests fix what the ranker is allowed to
do at all.
"""

from __future__ import annotations

from toolseal.core.registry.retrieval import Field, Ranker, stem, tokenize

# --- tokenizing -------------------------------------------------------------


def test_tokenize_lowercases_and_splits_on_non_alphanumerics() -> None:
    # Stemmed on the way out, so "organizations" arrives as its singular -
    # documents and queries must be reduced by identical rules or they can
    # never meet.
    assert tokenize("Find Organizations") == ["find", "organization"]


def test_tokenize_splits_snake_case_and_kebab_case() -> None:
    # Real tool names from the P1 corpus. A tokenizer that keeps these whole
    # cannot match the word a user actually types.
    assert tokenize("save_diff_comment") == ["save", "diff", "comment"]
    assert tokenize("notion-create-pages") == ["notion", "create", "page"]


def test_tokenize_drops_empty_fragments() -> None:
    assert tokenize("  --a__b  ") == ["a", "b"]


def test_tokenize_keeps_digits() -> None:
    assert tokenize("oauth2 v3") == ["oauth2", "v3"]


# --- ranking ----------------------------------------------------------------


def _ranker(*docs: tuple[str, str]) -> Ranker:
    """A ranker over (name, description) pairs, keyed by position."""
    return Ranker(
        [{Field.NAME: name, Field.DESCRIPTION: description} for name, description in docs]
    )


def test_terms_need_not_be_adjacent() -> None:
    # The exact defect this module replaces: the substring matcher returned
    # nothing for "reporting client" even though one document held both words.
    ranker = _ranker(("a", "Affiliate network reporting in your AI client."))

    assert [i for i, _ in ranker.rank("reporting client")] == [0]


def test_term_order_does_not_matter() -> None:
    ranker = _ranker(("a", "Affiliate network reporting."))

    assert [i for i, _ in ranker.rank("network affiliate")] == [0]


def test_a_document_matching_more_query_terms_ranks_higher() -> None:
    ranker = _ranker(
        ("a", "delete a comment"),
        ("b", "delete an attachment"),
    )

    assert next(i for i, _ in ranker.rank("delete comment")) == 0


def test_a_match_in_the_name_outranks_a_match_only_in_the_description() -> None:
    ranker = _ranker(
        ("list milestones", "Retrieve items for a project."),
        ("get project", "Lists the milestones belonging to it."),
    )

    assert next(i for i, _ in ranker.rank("milestones")) == 0


def test_a_rare_term_counts_for_more_than_a_common_one() -> None:
    # "linear" appears everywhere and should discriminate almost nothing;
    # "milestone" appears once and should decide the ranking.
    ranker = _ranker(
        ("a", "linear workspace thing"),
        ("b", "linear workspace milestone"),
        ("c", "linear workspace other"),
    )

    assert next(i for i, _ in ranker.rank("linear milestone")) == 1


def test_a_document_matching_nothing_is_not_returned() -> None:
    ranker = _ranker(("a", "one thing"), ("b", "another thing"))

    assert ranker.rank("kubernetes") == []


def test_an_empty_query_returns_nothing_rather_than_everything() -> None:
    # A ranking with no query has no meaning; the caller decides what to show.
    ranker = _ranker(("a", "one"), ("b", "two"))

    assert ranker.rank("") == []


def test_scores_are_ordered_descending() -> None:
    ranker = _ranker(
        ("comment", "comment comment"),
        ("other", "mentions comment once"),
    )
    scores = [score for _, score in ranker.rank("comment")]

    assert scores == sorted(scores, reverse=True)


def test_limit_truncates_without_reordering() -> None:
    ranker = _ranker(("a", "comment"), ("b", "comment"), ("c", "comment"))

    full = [i for i, _ in ranker.rank("comment")]
    assert [i for i, _ in ranker.rank("comment", limit=2)] == full[:2]


def test_repeated_query_terms_do_not_inflate_a_score() -> None:
    # "comment comment comment" is the same information need as "comment".
    ranker = _ranker(("a", "comment"), ("b", "unrelated"))

    once = dict(ranker.rank("comment"))
    thrice = dict(ranker.rank("comment comment comment"))

    assert once == thrice


def test_a_long_document_is_not_favoured_merely_for_being_long() -> None:
    # BM25 length normalisation: padding a document with unrelated words must
    # not make it beat a short document that is entirely on topic.
    ranker = _ranker(
        ("a", "milestone"),
        ("b", "milestone " + " ".join(f"filler{n}" for n in range(200))),
    )

    assert next(i for i, _ in ranker.rank("milestone")) == 0


# --- stopwords --------------------------------------------------------------


def test_function_words_do_not_decide_the_ranking() -> None:
    # The failure this exists for: "who" occurred in 2 of the 92 captured tool
    # descriptions and "team" in 9, so idf rated the function word as the more
    # informative of the two and ranked the query on it.
    ranker = _ranker(
        ("get team", "Retrieve details of a specific team."),
        ("update issue", "Decide who is assigned, and to whom it reports."),
    )

    assert next(i for i, _ in ranker.rank("who is on my team")) == 0


def test_a_query_of_only_function_words_still_returns_something() -> None:
    # Degenerate, but silently returning nothing would look identical to a
    # broken index. The stopwords are all the query has, so they are used.
    ranker = _ranker(("a", "how do i"), ("b", "unrelated content"))

    assert [i for i, _ in ranker.rank("how do i")] == [0]


# --- stemming ---------------------------------------------------------------


def test_a_plural_in_the_document_matches_a_singular_query() -> None:
    # "Read, write and search files" did not match the query "file", so the
    # filesystem server was unreachable by the most obvious thing to ask for.
    ranker = _ranker(("server filesystem", "Read, write and search files on disk."))

    assert next(i for i, _ in ranker.rank("read a file")) == 0


def test_a_singular_in_the_document_matches_a_plural_query() -> None:
    ranker = _ranker(("a", "Draw and export a sprite."), ("b", "unrelated content"))

    assert next(i for i, _ in ranker.rank("sprites")) == 0


def test_verb_endings_are_folded_together() -> None:
    ranker = _ranker(("a", "Manages running containers."), ("b", "unrelated content"))

    assert next(i for i, _ in ranker.rank("manage container")) == 0


def test_stemming_does_not_maul_short_words() -> None:
    # Over-eager suffix stripping turns "as" into "a" and "is" into "i",
    # collapsing distinct short words into noise.
    assert stem("as") == "as"
    assert stem("is") == "is"
    assert stem("gas") == "gas"


def test_a_y_plural_folds_to_its_singular() -> None:
    assert stem("queries") == stem("query")
    assert stem("repositories") == stem("repository")
