# VERIFICATION — the re-verification report (round 281)

What was checked: **everything that was done** in the audit of the Sony ILCE-7SM3 firmware update
file (`/work/SONY_A7SIII_UPDATE`, rounds 276–281) and **everything that was found** — again, from
the raw bytes, by instruments rather than by retelling. Plus the paper: every one of its numbers
is bound to an artifact.

The subject was not changed: `BODYDATA.DAT`, 743 818 632 bytes, sha256
`dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb` — the same as recorded in the
first report.

---

## 1. The audit instruments, run afresh (their output is in `verification_runs/`)

| instrument | non-control | controls (must go red) | result |
|---|---|---|---|
| `audit/checks.py` | 15/15 | 3/3 red | ALL MATCHED |
| `audit/report_check.py` | 2/2 | 3/3 red | ALL MATCHED |
| `audit/round277_check.py` | 13/13 | 5/5 red | ALL MATCHED |
| `audit/round278_check.py` | 17/17 | 5/5 red | ALL MATCHED |
| `audit/round279_check.py` | 28/29 | 2/2 red | **1 SKIP: the camera does not answer** |
| `audit/parser_bounds.py` | — | — | the bounds of the format, as described |
| `audit/verify_findings.py` | 47/47 | 5/5 red | ALL MATCHED |

The `round279_check.py` row is a measurement, not a caveat: the live half (C22–C25: the MISMATCH
verdict, the algorithm set, the match with the owner's key) is **not executed today**, because the
camera `192.168.1.102` does not answer from this container. The instrument prints `SKIP`, not
green: SKIP is not "passed". The live measurements are preserved separately (§4).

## 2. Re-verification of the findings by a separate instrument

`audit/verify_findings.py` — 47 statements, each derived again from the raw bytes with **its own**
code: its own container parse, its own unpacking of 726 385 frames, its own `tar` walk, its own
`openssh-key-v1` parse, its own P-256 arithmetic (double-and-add), its own `crc32`. Result:

* **47/47** non-control green;
* **5/5** controls went red as they must (a search for a certainly absent string; a corrupted
  header prefix; a corrupted key scalar; a corrupted frame; a read past the end of the stream).

Reproduced among others: 726 385 frames, 0 bad; the padding of the last frame is 572 × 0xff;
`4 × 726 385 + 572 = 2 906 112` (that was the "unexplained remainder"); the stream is 740 912 128 B,
sha256 `11880291…1e66`; the ECB run of identical blocks — 1 run, start 6, length 26 (the prediction
from the header matched the measurement); the key satisfies `d·G = Q`; the fingerprint
`SHA256:J8L9aBLE…NODI` was confirmed by a third-party `ssh-keygen`; the tail is 272 = 16 + 256 and
its IV matched the one the stream was opened with; the 2048-bit key yields no PKCS#1 v1.5
structure (`m[0:2] = 49 7f`).

## 3. What the re-verification found: four corrections to our own reports

| what was recorded | measured now | class of error |
|---|---|---|
| key block 501 B, body 471 base64 characters | **504 B**, body **435** characters | an offset read as a length (F161) |
| `sshd_config` at offset 740 736 525 | **740 733 952** (through the `tar` table of contents and the text) | a number from a search window, not from the boundary of the object (F162) |
| 4 `BEGIN PUBLIC KEY` blocks, 5 RSA keys | **8** blocks (one a literal with no body), **6** RSA moduli | literals counted instead of objects (F163) |
| the `FDAT` body at byte 100 | the length field at 100, **the body at 108** | the coordinates of a block and of its body (found while building the number instrument) |

Not one of the corrections changed a conclusion; all four changed numbers that had already been
sent out in delivered packages. The instrument errors of this round are F161–F166, not one of them
deleted: `FAILURES_281.md`.

## 4. What could not be re-verified today (and why)

| not re-verified | reason | what covers it |
|---|---|---|
| the camera's live host key | `192.168.1.102` does not answer from this container (camera off / off the network) | two witness files in `live_witness/`; the copy on the volume was compared by sha256 |
| the owner's run on the Mac | the owner's file is not attached here | its lines are quoted in the round-280 report; the paper uses them and names the owner as the one who measured |
| whether the key changes on reboot | a power-cycle of the camera is needed | an open question; the instrument is `MAC_FINGERPRINT.sh` |
| the camera's behaviour (signature, anti-rollback, interrupt, debug) | a loader dump or service mode is needed | §8 of the paper, the "not established" list |

Separately, as a fact of this round: **the witness of a live measurement was overwritten** at 18:02
by a `--selftest` run of the same instrument (it writes its report next to itself and the file name
does not depend on the mode). That is why the paper's numbers are bound to the **witness copy**
rather than to the file in the project root — F165.

## 5. The paper: what its content is checked by

* **98 numbers** are derived again from the artifact bytes (`paper_check.py`): **66** from raw bytes
  (the subject, the stream, the squashfs image, the unpacked tree, the witness file of the live
  run), **16** from saved instrument output (`verification_runs/*`), **16** constants with a named
  source in `numbers.json` (the stream frames, the `tar` member count, external measurements). The
  split is printed, not hidden: a constant is not "measured", it has a named source.
* **the sha256 of all 12 artifacts** is compared: drift is caught (controls M2/M3 in the self-test).
* **every number is found both in the paper's source and in the printed PDF** (token boundaries are
  checked: "15" is not found inside "1253376").
* **Appendix A is printed from `numbers.json`**, never typed by hand: the list of numbers cannot
  drift away from the check.
* Result: **5/5** checks green, **1/1** control (a deliberately corrupted number is not found) went
  red. The `selftest_paper.py` self-test: corrupting a number in the text -> red, corrupting an
  artifact -> red, deleting an artifact -> the instrument refuses to run, restoring -> green again
  (M0–M4).

## 6. Layout: "the words do not run into each other"

`layout_check.py` — two routes of different nature:

* **A. word boxes from the PDF itself** (`pdftotext -bbox-layout`): **all pairs** of boxes on a page
  that overlap in both x and y are compared (not only neighbours within a line — the letters of one
  table cell lie on top of the letters of the next, and that is the same defect); the same route
  counts overflow past the type area;
* **B. raster ink** (`pdftoppm` at 150 dpi -> PIL): the bounding box of the page's non-empty pixels
  must not leave the 36 pt safe frame.

Result on the shipped paper: **0 overlaps, 0 overflows past the margin, 0 pages with ink outside the
safe frame** (14 pages, 6415 words).

The instrument is calibrated by measurement, not by eye (`selftest_layout.py`): an ordinary document
goes green; two cells placed at the same point go red (`OVERLAP … OVERLAPTWO | OVERLAPONE`); a
250-character word goes red on two routes (`OVERFLOW … x1=598.2 against a margin of 529.0` and
`INK`). The thresholds: overlap > 1.0 pt, overflow > 4.0 pt (microtype's optical protrusion reaches
2.3 pt — measured).

And this is not a formality: **on its first run the instrument found 79 overlaps and 3 overflows** —
numbers and hashes were coming out of the columns of Appendix A's table and out of the paragraph
about `sshd_config`, so the letters really were lying on top of other letters and past the margin.
Fixed with explicit break points (`\allowbreak`), after which 0/0/0.

## 6b. Typography (round 282): the type was changed, and re-checked

The first edition was set in **DejaVu Serif** 11 pt, which is wide and heavy on the page. The owner
asked for a readable face, so the paper now uses **TeX Gyre Pagella** (a palatino-style face with a
large x-height and open counters) with **TeX Gyre Pagella Math** for the formulas, and keeps
**DejaVu Sans Mono** for the hex dumps and hashes, where the full ASCII range at a legible weight
matters more than style. The body is 12 pt.

Measured before and after, on the same machine, with the same instruments:

| | old (DejaVu Serif 11 pt) | new (Pagella 12 pt) |
|---|---|---|
| pages | 14 | 15 at first, **14** after the appendix was regrouped (§6d) |
| mean characters per prose line | 73.7 | 76.6 |
| ink coverage, body page 2 (mean grey < 128) | 4.217 % | 3.411 % |

The change is not cosmetic-only and had to be paid for: with the new metrics one long unbreakable
token ran out of the type area — `localhost:15740` on page 6, 9.6 pt past the margin — and the layout
instrument caught it (`route A (word boxes): overflows past the margin 1`). Explicit break points were
added after the colon (`localhost:\allowbreak15740`), which adds no printed character, and the
document is clean again (0/0/0). Every number stayed bound: `paper_check.py` 5/5 green with its
control red, on the rebuilt PDF.

## 6c. The names (round 282): a second kind of check, added after F167

The owner read the printed text of the paper and found holes in it. A systematic search showed that
**fifteen inline fragments were missing from the source, in twelve sentences** — config paths, the
`HostKey` line, the script and command that create the camera host key, a member name, two config
directives, an OpenSSL symbol, and the names of the instruments themselves. Every one of the 98 numbers
was still present, so `paper_check.py` stayed green, and `layout_check.py` measures the boxes that exist
— missing text has no box. The gap is now covered by `publication/string_check.py` in three routes:
**46 names** must be present in the source (A) and in the text extracted from the printed PDF (B), and
the source is scanned for the artefacts of a dropped token (C), each route with a control. It is green
(46/46, route C 0, controls firing), and `selftest_string.py` shows routes A and B going red on a
source-only removal (`source=False pdf=True`) and on a removal that reaches the rebuilt PDF
(`source=False pdf=False`). The error is recorded as F167 in `FAILURES_282.md`; the round-281 delivered
PDF has the same holes in those twelve sentences.

## 6d. The appendix (round 282): a table that had to be made readable

The owner reported that the appendix pages of the printed PDF had degenerated into a grid of digits.
Measured on that PDF, the four-column table at `\scriptsize` gave one mono character 5.038 pt, so its
number column held 22 characters per line: 294 text lines for 98 rows (2.88 lines per row), with the
sha256 column printing its digits as fragments at one x. `layout_check.py` is blind to that by design —
it looks for overlaps and overflow, and a narrow table has neither. The generator now groups the numbers
by artifact into two wide columns; the printed result measures **1.93 lines per row, tallest row 3
lines**, on pages 13–14. Two checks cover it from now on: the estimate inside `make_numbers.py` (which
stops the build if a cell would need more than two lines, control included) and
`publication/appendix_density.py`, which measures the printed table and builds its own over-full
control document. Recorded as F169 in `FAILURES_282.md`.

## 7. How to reproduce it in one command

```sh
cd /work/SONY_A7SIII_UPDATE/publication && sh run_all.sh      # ~14 minutes
# 1) the audit instruments -> verification_runs/   2) the numbers -> numbers.json
# 3) building main.pdf   4) binding the numbers    5) layout   6-7) self-tests   8) manifest
# any red step stops the run; at the end it prints RUN_ALL_PUBLICATION_OK
```

Separately: `python3 paper_check.py` (the numbers), `python3 layout_check.py` (layout),
`./env/venv/bin/python3 audit/verify_findings.py` (re-verification of the findings),
`python3 audit/round279_check.py` (the live device; needs `paramiko`).

## 8. What this report does not claim

* That "the protection is unbreakable" or that "there is no signature": what is measured is that
  **nothing inside the file can confirm the signature** — the verification key is not in the file
  (these are different statements).
* That the paper's live measurements were made today: they were made on 2026-10-04 between 17:06
  and 17:43 and are kept as witness files; today the camera is unreachable.
* That "the layout is clean in general": it was checked on **this** PDF, by two routes and with a
  calibration; this check does not cover another PDF, it has to be run again.
* That the 27 instrument errors are all the errors: they are the ones recorded and not deleted; an
  error nobody noticed is not on the list by definition.
