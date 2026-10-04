# Round 284 — the three remaining fragments put back, the package rebuilt and delivered

Commission: put back `d2i_PKCS8_PRIV_KEY_INFO`, `BEGIN ENCRYPTED PRIVATE KEY` and
`kex: host key algorithm: (no match)`; rebuild the round-282 edition; deliver the package with a
manifest and `sha256sum -c` on the volume; F158 closed; F170–F173 recorded in `FAILURES_283.md`;
no further digging.

---

## 0. In one paragraph

Three one-line insertions into `publication/paper/main.tex`, in exactly the places the Russian
source has them and nowhere else. The whole chain was then run again
(`publication/run_all.sh`, exit 0, 813 s) and every stage is green, including the stage that
looked at the **names** — which had been blind to exactly these three until this round: the check
now requires **49** names instead of 46 and was **red before the rebuild** and green after it,
which is the control that the three entries really bite. F158 is closed by measurement, not by
assertion: the round-283 instrument now measures two editions — the frozen one of round 282,
where the three are still absent (route E1, 3/3), and the live source of this round, where they
are back (route E2, 3/3). The package's language property was also restored: the two round-283
records were still in Russian, they are now in English, and the tree carries **0 files with
Cyrillic out of 106 scanned** (control: a planted Russian line is found). Delivery:
`/work/transcend/SONY_A7SIII_ENGLISH_284`, `sha256sum -c` on the volume green, every file read
back from the volume and compared.

## 1. The three holes, and the exact edits

The holes were located by the round-283 instrument. Each was a **gap in a sentence, with debris
left behind** (a line beginning with a space, a space before a full stop), not a deleted sentence.

| hole | before | after |
|---|---|---|
| `d2i_PKCS8_PRIV_KEY_INFO` (line 285) | `\lc{Camellia\_cbc\_encrypt} and \code{CMS\_EncryptedData\_it}, with its own` | `\lc{Camellia\_cbc\_encrypt},` + new line `\lc{d2i\_PKCS\allowbreak 8\_PRIV\_K\allowbreak EY\_INFO} and \code{CMS\_EncryptedData\_it}, with its own` |
| `BEGIN ENCRYPTED PRIVATE KEY` (line 542) | `the same is true of the single` + new line ` literal.` | `the same is true of the single` + new line `literal \lc{BEGIN EN\allowbreak CRYPTED \allowbreak PRIVATE \allowbreak KEY}.` |
| `kex: host key algorithm: (no match)` (line 585) | `Parsing the line` + new line ` yielded the word \code{match)}, and` | `Parsing the line` + new line `\lc{kex: hos\allowbreak t key al\allowbreak gorithm:\allowbreak (no mat\allowbreak ch)} yielded the word \code{match)}, and` |

`diff` against the state before this round shows **three hunks, insertions only, not one
deletion**: `main.tex` 37 813 → 38 026 bytes, sha256
`66a143eedf3de1c80c00becd04479a34ab0c1f1b6c05a9cc0f064ac9d94e3586` →
`212323d2e46f778c74cc0bd708a2d6183980a059e4e29550bc968a1b6f73b082`.

The `\allowbreak`s are not decoration: they are what the Russian source uses to let a 30-character
token straddle a line without overflowing the column, and the layout instrument goes red without
them. The internal spaces are single spaces on purpose — a double space is itself an artefact of
a dropped token and the name check reports it (route C).

## 2. The rebuild

`publication/run_all.sh`, one command, exit 0, 813 s, stdout sha256 `9c06e908…`. Its stages:

| stage | verdict |
|---|---|
| audit instruments, afresh | `checks.py` 15 non-control + 3 controls; `report_check.py` 2 + 3; `round277_check.py` 13 + 5; `round278_check.py` 17 + 5; `verify_findings.py` 47 + 5 — all matched |
| the live-device instrument | `round279_check.py` **28/29 with 1 SKIP** — the camera does not answer from this container (a skip is not a pass); controls 2/2 |
| the paper's numbers | 98 numbers, 12 artifacts, 5/5 green + 1 control red |
| layout | 14 pages, 6426 words, overlaps 0, overflows past the margin 0, ink outside the safe frame 0 |
| the cited names | 49/49 present in the source **and** in the printed PDF; route C (artefacts of a dropped token) 0, control fires |
| appendix density | 2 pages, tallest row 3 lines, mean 1.93; control fires |
| self-tests | name check M0–M3, number check M0–M4, layout self-test — all as required |
| manifest | `ARTIFACTS.md`: 39 files, `MANIFEST_OK` |

The printed paper: `paper/main.pdf`, 14 pages (same as round 282), sha256
`f38a8293998857ce98a4254d3a67b5ca5cb5bf08bd6b2680c7fa40349b896ea5` →
`99ede4c33c39968a8ad40f4652db5cbe9f3022cc755d4021cb3a33c6b9b1fedc`.

**One measured caveat about that hash.** Three builds of the same source give 106 299, 106 293
and 106 297 bytes, while their **text layers are byte-identical** (38 093 characters each, compared
with `cmp`). The PDF's *byte size* is therefore not reproducible — the document is. That is why
the number instrument binds the numbers to the **text**, and why a delivered copy is hashed as
frozen bytes instead of being rebuilt on the way.

## 3. What now guards the three names (the point of the round)

`publication/string_check.py` had **46** required names, and the three lost fragments were none of
them: they are technical strings, not artifact names — that is exactly why neither the owner's
list nor the instrument's list had caught them.

They are now required names 47, 48 and 49, each with the reason it must be in print and the
artifact it comes from. The instrument was run **before** the rebuild, on purpose: it reported
`46/49`, with the three rows reading `source=True pdf=False` — in the source, absent from the
printed page. That is a live control, not a claimed one: the three new entries are shown to bite,
and the very next run is green (`49/49`). Route C (0 dropped-token artefacts) and the planted-string
control are green in both runs.

`selftest_string.py` still proves the check can go red: M1 deletes a cited name from the source
(source route red), M2 deletes it and rebuilds the PDF (both routes red), M3 restores it (green).

## 4. F158: closed, and by what measurement

The round-283 instrument `f158_check.py` was pointed at **two** sources on purpose:

* route **E1** now measures the edition of round 282 **as delivered and frozen** on the volume
  (`/work/transcend/SONY_A7SIII_ENGLISH_282/publication/paper/main.tex`, sha256 `66a143ee…`) —
  there the three fragments really are absent, 3/3. The round-283 finding stays reproducible;
  it must not move because the live file has since changed.
* route **E2** (new this round) measures the live source: the three fragments are back, 3/3.

Result: **10 non-control checks green out of 10, 5 controls red out of 5**.
The round-283 output is frozen in the round-283 delivery
(`/work/transcend/SONY_A7SIII_F158_283/f158_result.json`, sha256 `6fc63720…`); the copy that used
to sit in the tree was removed once I regenerated the file, because the frozen one is on the
volume and byte-identical to it.

## 5. The package's language property, restored (an extra step, with the reason)

The round-282 delivery was English-only, and that was an explicit commission. Between then and
now, round 283 put two Russian documents into `publication/`: `FINDINGS_283.md` and
`FAILURES_283.md`. Shipping the package as it stood would have shipped a bilingual package while
describing it as the English edition. So both documents were translated, keeping every F-number,
table row, number and conclusion.

How the translation was checked (this is the defect class F158 belongs to — a translation step
that quietly drops long inline tokens):

* **Every code-like token of the Russian originals must be present in the English ones.**
  `FINDINGS_283.md`: 49 code-like tokens, 48 present; `FAILURES_283.md`: 9 of 9. The single
  deviation is deliberate and named: inside the fragment `./MAC_FINGERPRINT.sh --ip <...>` the
  placeholder is two Russian words (meaning "camera address") in the source, and it is written in
  English as `--ip <address of the camera>`. The exact Russian bytes of the original are not lost:
  they are in the frozen round-283 records and in `f158_result.json`, where the fragment is stored
  in escaped form (`\u0430\u0434\u0440\u0435\u0441 ...`). Controls on the same route: three real
  tokens (`audit/verify_findings.py`, `paper/main.tex`, `write_file`) are found, a fabricated token
  (`f284_no_such_token_anywhere`) is not.
* **No prose token was smuggled back in Russian.** The four deviations in total are:
  the Russian conjunction (a single character, "and") → `and`; the table legend
  `RU=Y ENsource=N PDF(...)=N`, whose last column is labelled in
  Russian in the original and now reads `PDF(English part)=N`; `xelatex ×2` → `` `xelatex` ×2 ``
  (the `×2` moved outside the code span); and the placeholder above. Each is a
  translation of prose, not a loss of a name, and each is listed here so it can be checked.
* **Cyrillic left in the tree: 0 files out of 106 text files scanned**, with the instrument's
  control (a planted Russian line) found — `python3 publication/scan_cyrillic.py` →
  `RESULT: THE PACKAGE CARRIES NO RUSSIAN TEXT`. An independent walk of the same tree, written
  separately, agrees: 0 files.
* Two instrument outputs, `f158_result.json` and `f158_check.py`, contained raw Cyrillic because
  the **recorded object of measurement** contains it (the fragment quoted above is Russian in the
  Russian source, and the page-splitting regex was written with a literal Cyrillic range). Both
  are now ASCII: the regex uses an escape range with the same meaning, the recorded fragment is
  stored in escaped form, and the JSON is written with `ensure_ascii=True`. The **content is
  unchanged** — route A1 still finds the fragment in the Russian source (10/10 green).

## 6. Delivery, and how it was verified

* destination: `/work/transcend/SONY_A7SIII_ENGLISH_284` (the round-282 folder is left as the
  record of that round; it carries the three holes, and it is now superseded, like the round-281
  package before it);
* the delivery instrument is itself a check: it copies, then reads **every file back from the
  volume** and compares sha256 with the source, then writes `MANIFEST.sha256`, then runs
  `sha256sum -c MANIFEST.sha256` **on the volume**;
* the numbers are in `DELIVERY_RECEIPT.md`, written by the instrument, not typed by me;
* independently of the delivery instrument, the checks were run **from the delivered copy**:
  `string_check.py` from the volume (49/49, control green), and `pdftotext` on the delivered
  `paper/main.pdf`, where the three restored fragments are each present once.

## 7. Instrument errors of this round — F174–F177, not one deleted

Listed in `FAILURES_284.md`. Three of the four are mine rather than an instrument's, and all four
are the same class as F170–F173: **a result read off the wrong representation.**

## 8. What this does not mean

* It does not mean the paper changed in substance. Not one number, table row, conclusion or claim
  moved: three inline names were restored inside three sentences, and the number instrument
  (98 numbers, 12 artifacts) and the layout instrument were green before and after.
* It does not mean the three fragments are now provable *in every edition*: they are in the source
  and in the printed PDF of **this** edition, measured; the round-281 package still has them
  missing, and the round-282 package too — those are frozen records, not defects to repair.
* It does not mean the round-283 threshold (tokens of ≥ 49 characters dropped, ≤ 48 kept) is a law
  of translation; it is one measurement of one translation step, and it breaks on `\hx`/`\hl`.
* It does not mean the live half of the audit was re-measured: `round279_check.py` reports 28/29
  with **1 SKIP** because the camera does not answer from this container. The live measurements
  themselves are the round-279 witnesses, unchanged.
* It does not mean the package is byte-reproducible: the PDF's byte size varies between builds
  (§2) while its text does not.

## 9. The volume disappeared after the delivery (measured, and it is not the package)

The delivery completed and was verified against the volume: **110 files, 1 056 940 bytes, 0
mismatches after copying, 0 after reading every file back, `sha256sum -c MANIFEST.sha256` exit 0
with 110 OK lines** — re-run by hand and reproduced, and the receipt written on the volume by the
delivery instrument said the same. Then, minutes later, while the number instrument was being run
**from the delivered copy** as the last check, the volume stopped answering:

```
stat /work/transcend                    -> directory
ls /work/transcend                      -> cannot open directory: Not a directory
grep transcend /proc/mounts             -> /run/host_mark/Volumes /work/transcend fakeowner rw,...
ls /run/host_mark                       -> No such file or directory
df /work/transcend                      -> Not a directory
```

The mount source itself (`/run/host_mark/Volumes`, that is the host's view of the external disk)
no longer exists in this container: the drive was unmounted from the host side. That is an
external event, not a property of the package, and **nothing in the delivery wrote more than the
110 files above**. But it does bound my claim: the last check — `paper_check.py` run from the
delivered copy — printed two PASS lines (artifacts intact, numbers re-derived from the bytes) and
then died with `NotADirectoryError` because the volume vanished mid-run. A check that did not
finish is not a check that passed, so the delivered package's own number binding is asserted here
on the strength of the **project** copy (green in §2) plus the delivery's byte-for-byte
read-back, not on a completed run from the volume. Recorded as F178.

Consequence, stated plainly: the copy on the volume carries this report **without this section**,
and `FAILURES_284.md` there stops at F177 — both were written after the drive left. Everything
else on the drive is the package as measured. When
the drive is back, one command delivers the current state and verifies it:

```
cd /work/SONY_A7SIII_UPDATE && python3 audit/make_284_delivery.py   # copy + read-back + sha256sum -c, writes DELIVERY_RECEIPT.md
```

A frozen payload of the same file set, independent of that drive, is
`/work/SONY_A7SIII_ENGLISH_284_PAYLOAD.tar.gz` (the file list is produced by the delivery
instrument's own `walk()`, so the payload and the delivery cannot disagree about what ships). Its
sha256 and size are in `/work/SONY_A7SIII_ENGLISH_284_PAYLOAD.sha256` — outside the archive,
because an archive cannot contain its own hash. Unpacked into a fresh directory it gives 110
files; its inner `publication/MANIFEST.sha256` verifies 40/40; `string_check.py` and
`layout_check.py` run green from there; and the three restored names are each present once in the
payload's `paper/main.pdf`, whose sha256 equals the project's (`99ede4c3…`).

## 10. Reproduce in one command

```
cd /work/SONY_A7SIII_UPDATE/publication && sh run_all.sh          # the whole chain, ~14 min, ends RUN_ALL_PUBLICATION_OK
cd /work/SONY_A7SIII_UPDATE/publication && python3 f158_check.py  # F158: E1 on the frozen 282, E2 on this edition
cd /work/SONY_A7SIII_UPDATE/publication && python3 scan_cyrillic.py
cd /work/SONY_A7SIII_UPDATE && python3 audit/make_284_delivery.py # copy + read-back + sha256sum -c on the volume
```
