# Instrument errors of this round — F161–F166 (not one of them deleted)

_Continuation of the F140–F160 list (rounds 276–279). Here are six errors of round 281: three of
them are **foreign** numbers (recorded in earlier reports) that the re-verification caught, and
three are errors of the instruments built in this round. The class is the same for all of them:
**the instrument measured a different representation than the one it printed**, so green was
indistinguishable from "read the wrong thing". That is exactly why in this round every number of
the paper is derived again from the artifact bytes instead of being quoted._

## F161 — the private-key block: an offset read as a length

Reports 277/278 said "the key block is 501 B" and "471 base64 characters between BEGIN and END".
Re-verification from the raw bytes (`audit/verify_findings.py`, checks D4/D4b) gives
**504 B** and **435 characters**. 471 is the offset at which the closing line begins — that is,
**an offset that entered the report as a length**; 501 is a count taken without the closing line.
Class: a length and an offset in one type.

## F162 — the `sshd_config` offset: 740 736 525 instead of 740 733 952

The value recorded in reports 278/280 lies **2573 bytes inside** the file (the size, 3094, was
right). The true start — 740 733 952 — is confirmed by two independent routes: through the `tar`
table of contents (the offset of the member data) and through the text of the file (it begins with
`# Package generated configuration file`). Class: a number taken from a search window instead of
from the boundary of the object.

## F163 — the key inventory: "4 `PUBLIC KEY` blocks", "5 RSA keys"

Report 278 said "4 `PUBLIC KEY` blocks" and "5 distinct public RSA keys". Re-verification over the
whole stream with my own parser: **8** `BEGIN PUBLIC KEY` armor blocks (one of them a literal with
no body, that is, a string table) and **6** distinct RSA moduli (3071 ×2, 3072 ×3, 2048 ×1).
Class: counting over one region, and counting **literals** instead of objects — the same class as
F153/F155 in round 278.

## F164 — the body-offset check compared file bytes against plain-text magic

The paper's number instrument (`publication/numrules.py`) locates the offset of the `FDAT` body and
verifies it by searching for the `UDTRFIRM` magic **in the file bytes**. But that region is
encrypted: the magic only appears after decryption with the public key. The check could never have
gone green — that is, it checked nothing. Fixed: the offset is now compared against the decrypted
window. Class: an instrument with no state in which it is green.

## F165 — the live-session witness is overwritten by a run of the instrument itself

`FINGERPRINT_RESULT.txt` in the project folder was **overwritten at 18:02** by a run of
`MAC_FINGERPRINT.sh --selftest` (verdict `UNREACHABLE`), because the instrument writes its report
next to itself and the file name does not depend on the mode. That is, **the evidence of a live
measurement can be destroyed by a later, non-live run of the same tool**. The consequence is
fixed: the paper's numbers are bound to the witness copy
`publication/live_witness/FINGERPRINT_RESULT_2026-10-04_1743.txt`, whose sha256 matches the copy on
the volume (441ec13…6043f). The mechanism (a file name that does not distinguish modes) is
unchanged and is recorded as open.

## F166 — `\seqsplit` with a macro inside its argument broke the build, and the PDF stayed truncated

An attempt to let long strings break through `\seqsplit` tore apart the argument
`\hx{dbdd8b02\ldots c9eb}` (it had a macro inside); the build failed — **but xelatex had already
written a 7-page PDF instead of 14**, and the log shows it only as `Runaway argument`.
The layout instrument would not have caught this (a truncated PDF is "clean" by itself): what
caught it was the number binding — some numbers were not found in the printed PDF. Fixed: line
breaks are inserted as explicit `\allowbreak` (with no argument parsing), and the paper is 14 pages
again. (Round 282 replaced the type — DejaVu Serif 11 pt -> TeX Gyre Pagella 12 pt — and the paper
is now 15 pages; the number in the sentence above is the count of the round-281 revision.)
Class: **a silent partial build**; a check that looks at the whole artefact rather than at
the builder's exit code turned out to be stronger than the builder here.
