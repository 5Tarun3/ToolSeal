"""Term-based retrieval over tool descriptors.

The registry's first search was a substring test: `query in haystack`, over the
whole query string at once. That only ever matched a contiguous, correctly
ordered phrase, so `"reporting client"` found nothing in a document containing
both words four tokens apart, and `"network affiliate"` found nothing in one
containing `"Affiliate network"`. Measured over the shipped 113-entry set,
every realistic multi-word query returned zero results.

This module replaces it with Okapi BM25 over weighted fields. BM25 rather than
plain term-frequency for two reasons a tool registry feels immediately:

* **Rare terms decide.** Nearly every MCP tool description contains its
  vendor's name. Inverse document frequency makes "linear" worth almost
  nothing and "milestone" worth a great deal, which is the correct weighting
  for a corpus where one vendor contributes most documents.
* **Long descriptions do not win by default.** Some tools document themselves
  in a sentence and some in three paragraphs. Length normalisation stops the
  verbose ones dominating on term count alone.

Written from the published formula rather than taken from a library: the
project's rule is that a tool which counts other people's dependencies should
justify each of its own, and this is roughly eighty lines.

**Scoring is relevance only.** Nothing here reads an audit score, a finding, or
an annotation. A tool's security posture is reported next to a result, and
blocking entries are floored by the caller, but posture never moves a result up
the list - see `index.RegistryIndex.search` for where the two are combined.
Keeping retrieval ignorant of the assessment is what lets the assessment be
reported as evidence rather than as something the ranking already assumed.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from enum import StrEnum
from typing import Final

# Okapi BM25's usual constants. `k1` bounds how much repeating a term inside
# one document can help; `b` sets how strongly length normalisation applies.
# These are the standard defaults and are deliberately not tuned against
# `research/probes/p2_retrieval/queries.md` - fitting them to the evaluation
# set is exactly the circularity that document was written to avoid.
K1: Final = 1.2
B: Final = 0.75

_SPLIT: Final = re.compile(r"[^a-z0-9]+")

# Function words, dropped from queries before scoring.
#
# **Added after the first evaluation run, not before it** - the ordering
# matters and `research/probes/p2_retrieval/RESULTS.md` reports both numbers
# separately for that reason. The failure that prompted it: for the query "who
# is on my team", `who` occurs in 2 of 92 tool descriptions and so earns an idf
# of 3.62, while `team` occurs in 9 and earns 2.28. BM25 ranked the query on
# its least meaningful word, because idf assumes rare implies informative and
# for function words that is simply false.
#
# The list is the conventional English stopword set (the NLTK/Snowball
# lineage), used as published rather than pruned or extended to suit this
# corpus. Choosing which words to include by looking at their effect on the
# evaluation set is precisely the fitting the pre-registered queries exist to
# prevent; taking a standard list wholesale is not.
# fmt: off
_STOPWORD_LIST: Final[tuple[str, ...]] = (
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by", "can",
    "could", "did", "do", "does", "for", "from", "had", "has", "have", "he",
    "her", "him", "his", "how", "i", "if", "in", "into", "is", "it", "its",
    "me", "my", "no", "nor", "not", "of", "on", "or", "our", "out", "she",
    "should", "so", "some", "such", "than", "that", "the", "their", "them",
    "then", "there", "these", "they", "this", "those", "to", "was", "we",
    "were", "what", "when", "where", "which", "who", "whom", "why", "will",
    "with", "would", "you", "your",
)
# fmt: on

_STOPWORDS: Final[frozenset[str]] = frozenset(_STOPWORD_LIST)


def _content_terms(terms: list[str]) -> list[str]:
    """*terms* without function words, unless that would leave nothing.

    A query made entirely of stopwords - "how do i" - still has to return
    something rather than silently nothing, so in that case the stopwords are
    all it has and they are kept. This is a fallback for a degenerate query,
    not a scoring decision.
    """
    content = [term for term in terms if term not in _STOPWORDS]
    return content or terms


class Field(StrEnum):
    """A searchable part of a descriptor, and how much it counts.

    Separate fields rather than one concatenated blob so that a term matching
    a tool's *name* can outweigh the same term buried in prose. `save_comment`
    should win the query "comment" against a document that merely mentions
    commenting.
    """

    NAME = "name"
    DESCRIPTION = "description"
    SERVER = "server"
    PERMISSIONS = "permissions"


# Multipliers applied to a term's frequency per field. A name match counts for
# three ordinary mentions; the owning server's name counts for little, since
# every tool from one server shares it and it therefore discriminates nothing
# within that server.
FIELD_WEIGHTS: Final[Mapping[Field, float]] = {
    Field.NAME: 3.0,
    Field.DESCRIPTION: 1.0,
    Field.SERVER: 0.5,
    Field.PERMISSIONS: 1.0,
}


def stem(token: str) -> str:
    """*token* reduced to a crude stem, folding plurals and common verb endings.

    **Added after the utility-coverage set replaced the alphabetical one**, on
    the same post-hoc footing as the stopword list: the failure was that
    "Read, write and search files" did not match the query "file", so the
    filesystem server - the most obvious thing in the whole index - was
    unreachable by the most obvious thing to ask it for. "sprites" against
    "sprite" hid Aseprite the same way.

    Deliberately crude, and only in the directions that actually failed:
    plurals and `-ing`/`-ed`. A real Porter stemmer is a few hundred lines of
    rules whose behaviour is hard to predict from a call site, and the extra
    conflation it buys is not obviously wanted in a corpus of API verbs where
    `list` and `listing` mean the same thing but `update` and `updated` may
    not be worth merging any harder than this.

    The four-character floor exists because suffix stripping is destructive on
    short words: without it "as" becomes "a", "is" becomes "i", and "gas"
    becomes "ga", which turns distinct words into collisions.
    """
    if len(token) < 4:
        return token

    # `-es` only after a sibilant, which is the environment English actually
    # adds it in: "boxes", "dishes", "searches". Stripping it unconditionally
    # turns "sprites" into "sprit" while "sprite" stays whole, so the plural
    # and the singular stem to different things - the exact failure this
    # function exists to remove, reintroduced one rule later.
    if token.endswith("ies") and len(token) >= 5:
        return token[:-3] + "y"
    if token.endswith("es") and token[:-2].endswith(("s", "x", "z", "ch", "sh")):
        return token[:-2]

    for suffix in ("ing", "ed", "s"):
        if token.endswith(suffix):
            # "ss" is not a plural: "class" must not become "clas".
            if suffix == "s" and token.endswith("ss"):
                return token
            stripped = token[: -len(suffix)]
            # Undouble a consonant exposed by stripping, as Porter's step 1b
            # does: without it "running" stems to "runn" while "run" stems to
            # itself, so the two never meet. "ll" and "ss" are left alone,
            # since English keeps them ("call", "class").
            if (
                suffix != "s"
                and len(stripped) >= 4
                and stripped[-1] == stripped[-2]
                and stripped[-1] not in "lsz"
            ):
                stripped = stripped[:-1]
            # Never strip past three characters: "used" -> "us" collides with
            # an unrelated word, and so does "uses".
            if len(stripped) >= 3:
                return stripped
    return token


def tokenize(text: str) -> list[str]:
    """Lowercase alphanumeric terms, split on everything else, stemmed.

    Splitting on non-alphanumerics is what makes `save_diff_comment` and
    `notion-create-pages` reachable by the words a person actually types. A
    tokenizer that kept those whole would make most tool names unsearchable,
    since almost no tool in the corpus is named as a single word.

    Stemming is applied here rather than at the call sites so that documents
    and queries can never be tokenized by different rules - a mismatch that
    would silently retrieve nothing and look like an empty index.
    """
    return [stem(token) for token in _SPLIT.split(text.lower()) if token]


class Ranker:
    """BM25 over a fixed set of documents.

    Built once per search rather than persisted: the index is a few hundred
    entries read from JSON, and rebuilding costs less than the parse that
    produced it. Persisting term statistics would add a cache to keep correct
    across `registry sync` for no measurable gain at this size.
    """

    def __init__(self, documents: Sequence[Mapping[Field, str]]) -> None:
        # Frequencies are floats, not counts: a term in a weighted field
        # contributes its field's weight rather than 1, so `Counter` (whose
        # values are ints) is the wrong container even though the shape fits.
        self._frequencies: list[dict[str, float]] = []
        self._lengths: list[float] = []

        for document in documents:
            weighted: dict[str, float] = {}
            length = 0.0
            for field, text in document.items():
                weight = FIELD_WEIGHTS.get(field, 1.0)
                for token in tokenize(text):
                    weighted[token] = weighted.get(token, 0.0) + weight
                    length += weight
            self._frequencies.append(weighted)
            self._lengths.append(length)

        self._count = len(documents)
        self._average_length = (sum(self._lengths) / self._count) if self._count else 0.0

        document_frequency: Counter[str] = Counter()
        for frequencies in self._frequencies:
            document_frequency.update(frequencies.keys())
        self._document_frequency = document_frequency

    def _idf(self, term: str) -> float:
        """Inverse document frequency, in the form that cannot go negative.

        The textbook BM25 idf turns negative for a term appearing in more than
        half the corpus, which would let a common term *subtract* from a score
        and rank a matching document below a non-matching one. The +1 inside
        the logarithm is the standard fix and keeps every contribution >= 0.
        """
        seen = self._document_frequency.get(term, 0)
        return math.log(1.0 + (self._count - seen + 0.5) / (seen + 0.5))

    def rank(self, query: str, *, limit: int | None = None) -> list[tuple[int, float]]:
        """Documents matching *query*, best first, as `(index, score)` pairs.

        Terms are deduplicated: asking for "comment comment" is the same
        information need as asking for "comment", and repeating a word in the
        query should not multiply its influence.

        A document matching no query term is omitted entirely rather than
        returned with a zero score - "no results" and "results that match
        nothing" are different answers, and the caller should be able to tell
        a user which one happened. An empty query likewise returns nothing:
        a ranking with no query has no meaning, so what to show instead is the
        caller's decision, not this module's.
        """
        terms = set(_content_terms(tokenize(query)))
        if not terms or not self._count:
            return []

        scored: list[tuple[int, float]] = []
        for index, frequencies in enumerate(self._frequencies):
            score = 0.0
            for term in terms:
                frequency = frequencies.get(term, 0.0)
                if not frequency:
                    continue
                normalisation = (
                    1
                    - B
                    + B
                    * (self._lengths[index] / self._average_length if self._average_length else 1.0)
                )
                score += self._idf(term) * (frequency * (K1 + 1)) / (frequency + K1 * normalisation)
            if score > 0.0:
                scored.append((index, score))

        # Index breaks ties so the order is deterministic: a rebuilt index must
        # produce the same ranking, or a regression test cannot tell a scoring
        # change from a dictionary-ordering change.
        scored.sort(key=lambda pair: (-pair[1], pair[0]))
        return scored[:limit] if limit is not None else scored
