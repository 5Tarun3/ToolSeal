# Disclosure Policy

`SECURITY.md` covers reports made *to* this project. This is the reverse: what
this project does when its own studies find a problem in someone else's
quickstart, README, template repository, or MCP server.

It exists before any scanning does. A policy written after seeing the results
gets shaped by what was found and who it embarrasses; this one was not.

## 1. Two kinds of finding, handled differently

**A class-level weakness.** A quickstart that tells the reader to paste a key
into `.env`, a template that binds every tool unconditionally, an MCP server
README with no timeout guidance. This is a defect in guidance, and it affects
every reader who follows it, not one repository's history. It is reported like
a normal finding: named, described, embargoed, published.

**A specific compromised artefact.** One repository with a credential actually
committed to it. This is not a documentation defect — it is a live incident for
whoever owns that key. It follows §5 instead, in full, before anything else in
this document applies to it.

Every finding this project produces is one or the other. Which one determines
the rest of this document.

## 2. Who gets told, and how

In this order:

1. The project's own stated security contact — a `SECURITY.md`, a
   `security.txt` per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116), or a
   GitHub **Report a vulnerability** advisory. Used privately, the same way
   this project asks to be contacted.
2. If none exists but the project is on GitHub: a private GitHub Security
   Advisory can be opened against the repository directly — this works even
   without a `SECURITY.md`.
3. If neither exists: a maintainer contact published in package metadata
   (PyPI, npm, the repository's own listed maintainer).
4. If none of the above is reachable: a minimal public issue, containing only
   enough to let a maintainer find the problem — never exploit detail, never a
   credential value, never more than the check id and the affected file or
   page.

Step 4 is the floor, not the default. It is used only when steps 1–3 genuinely
fail, and only for a class-level weakness (§1) — never for a live credential
(§5), which does not wait for an issue queue.

## 3. Embargo

**90 days** from first successful contact (or from the report landing, for a
channel that does not confirm receipt), before anything about the finding
that names the artefact is published.

This follows [Google Project Zero's 90-day
policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html)
rather than inventing a number. Ninety days is longer than CERT/CC's 45-day
norm because the targets here are mostly volunteer-maintained documentation and
templates, not funded security teams, and this project has no exploit to hold
back that would justify a shorter window.

**If the embargo lapses with no response:** the aggregate figures are
published regardless — they always are, per §4. A named finding is published
too, marked with the date reported and "no response received." The artefact is
still not re-fetched or re-verified past its snapshot; it is reported exactly
as it was found, dated.

**If the maintainer responds and fixes it within the window:** the finding is
published as resolved, with the fix noted, once 90 days have passed or the fix
is confirmed, whichever is sooner. There is no reason to hold a fixed problem
back for the full window.

## 4. What gets published

**Always, unconditionally:** aggregate figures — score distributions, per-check
failure rates, the proportion of the corpus with a critical finding. These
identify no artefact and need no embargo.

**Naming a specific artefact** — this quickstart, that template repository —
requires the embargo in §3 to have run its course, one way or another
(response and fix, or lapse). Even then, what is published is the defect
category and enough to make the finding reproducible against the snapshot: not
raw file contents, not a reproduction of the offending line.

**Absolute, no exception:** a live committed credential's value never appears
in the paper, in any repository this project controls, or in a results file.
Not raw. Not partially masked. Not after the embargo lapses. Not after the
owner rotates it. A rotated key is still evidence that a key existed; the paper
can say a live secret was found and disclosed, and nothing more.

## 5. A live secret

A committed, working credential is not a research finding. It is someone's
compromised key, and it is handled before anything else in this document,
starting the moment it is recognised — no embargo, no queue, no waiting for a
scanning pass to finish:

1. **Stop.** Scan no further than needed to confirm the shape (this project's
   own `A1` check already distinguishes a credential shape from a placeholder —
   the same judgement applies here). Do not fetch anything to test whether the
   key still works.
2. **Do not persist the value.** Not in a commit, not in a private note, not in
   a draft of this project's own results. What is recorded is that a secret was
   found — check id, provider/shape, file path, date — never the literal
   string. `bench/generated.py` and `bench/harness.py` already serialise only
   check ids for exactly this reason; §6 of this policy's companion audit
   verified nothing in this project's harness carries a matched value into a
   committed file (see the report for P38).
3. **Tell the owner immediately**, by the fastest channel in §2, with
   revocation instructions specific to the credential's shape (which
   provider's dashboard, which rotation flow) — the same remediation `A1`
   itself gives: *"it must be treated as compromised."*
4. **Note, but do not rely on, automatic scanning.** Some providers run
   partner secret-scanning programs (e.g. GitHub's) that may already have
   revoked a recognised key shape. That coverage is not guaranteed for every
   provider or every credential shape this project's checks recognise, so
   direct notification happens regardless.
5. **Never publish it.** §4's absolute rule applies without exception, forever,
   independent of whether the owner ever responds.

## 6. Corrections

**A finding turns out to be wrong.** Retract it through the same channel and
with the same visibility it was disclosed through — a private report gets a
private retraction, a published finding gets a published correction. Anything
already in the paper or a results file is corrected with a dated note, the same
discipline `research/evaluation-protocol.md` uses for its own deviations.

**The artefact changes after the snapshot.** The evaluation protocol already
requires every fetched artefact to be stored with a retrieval timestamp and a
content hash, and every analysis to run against that snapshot. A correction
never re-audits the live page — it states what was true of the snapshot, dated,
and if a later note is warranted (the maintainer fixed it, or made it worse),
that note carries its own date and does not silently replace the original
figure.

## Scope

This governs findings from studies this project runs against artefacts it does
not author — official framework docs, MCP server READMEs, template
repositories, and anything else materialised for `research/studies/`. It does
not cover vulnerabilities in `toolseal` itself; those go through `SECURITY.md`.

No individual is named as a contact or a finder anywhere this policy produces —
channels and roles only, matching the rest of this project.
