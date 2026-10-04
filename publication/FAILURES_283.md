# The instrument errors of this round — F170–F173 (not one of them deleted)

_Continuation of the list F140–F169 (rounds 276–282). The round-283 work searched for the
mechanism behind the loss of 15 fragments from the round-281 paper. What changed was not the
paper and not the audit, but the **instrument**: four errors, all of one class, and all four
found only because every control had a state in which it is obliged to go red. The class:
**the instrument measured a different object than the one it named**._

## F170 — "the PDF" instead of "the English part of the PDF"

The first run of `f158_check.py` looked for the missing names across the whole text layer of
`paper/main.pdf` and declared `BEGIN OPENSSH PRIVATE KEY` present. Formally the instrument was
right: the string is in the PDF. But not in the English text — it is in **Appendix A, printed
in Russian** (pages 11–14, 2177 Cyrillic characters). The instrument called this "the PDF"
while it was measuring a document part of which is in another language and of another origin.
Fixed by splitting the PDF into the English part (pages without Cyrillic) and the appendix;
after that, 17/17.

As a side effect this produced a substantive finding: **the English paper of round 281 carries
a Russian appendix** (§1 of the report, `FINDINGS_283.md`). No instrument of round 281 saw it:
`paper_check.py` checked the numbers, `layout_check.py` the boxes, and `scan_cyrillic.py` did
not exist yet.

## F171 — a control that did not happen, and therefore "did not fire"

The control "a fragment typed back into the `.tex` must appear in the rebuilt PDF" went red in
the right place, but for the wrong reason: I substituted `\code{d2i_PKCS8_PRIV_KEY_INFO}` with
**unescaped underscores** (in LaTeX that is an error), and chose as the anchor the line
`and the same number of`, which is not in the file — it is broken by a line break. So the file
did not change at all, while the control reported a build failure. The class: **green/red with
no state that distinguishes "it did not fire" from "it did not happen"**. Fixed: the anchor is
checked (`assert anchor in t`), the underscores are escaped, and the control looks at the
**English part** of the rebuilt PDF.

## F172 — an exact string where the subject was the name of an artifact

The route "what did the round-282 revision do" looked in the round-282 source for the **exact**
forms of the lost fragments and found 7 of 17, reporting that ten "had not come back". They had
come back — but in a shortened form (`publication/paper_check.py` → `paper_check.py`). The
instrument was comparing strings where the subject was the **name of an artifact**. Fixed:
three groups are measured separately — back verbatim (8), back in a shortened form (6), not
back (3) — and the third group is named one by one.

## F173 — text counts as "neighbouring" when something stands between it

The normalisation used for the search removes **all** whitespace, so lines with a whole sentence
between them become "neighbouring": a name is assembled from pieces that stand in different
places on the page. This produced no false positives in this round (the planted name was not
found, and the six control names were found exactly where they stand), but the instrument has
no separate control for exactly this risk. Recorded as an **open defect of the route**, not as
a verified property: the right control is a name assembled from two real but non-neighbouring
pieces, which must **not** be found.
