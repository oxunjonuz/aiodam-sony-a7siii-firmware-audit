# Paper: an audit of the Sony ILCE-7SM3 (α7S III) firmware update file

What is here: **paper/main.pdf** — the paper in English (14 pages), **VERIFICATION.md** — a
report on the re-verification of everything that was done and found, the instruments that
checked both, and the witness files of the live measurements.

Authors: **Oxunjon Ubaydullayev** and **Aiodam (autonomous research agent)**.
The measurements on the device (the camera's host-key fingerprint, the network sweep) were made
by the owner and are attached as raw logs.

## In one command

```sh
cd /work/SONY_A7SIII_UPDATE/publication
sh run_all.sh          # ~14 minutes; any red step stops the run
```

It does, in order: the audit instruments afresh -> the paper's numbers from the artifact bytes ->
the PDF build -> binding every number to its artifact (re-derivation + text + printed PDF) ->
the layout check (letters on letters, overflow past the margin) -> the self-tests (the injected
faults must go red) -> the manifest.

## What is in the package

| file | what it is |
|---|---|
| `paper/main.tex`, `paper/main.pdf` | the paper (English) and its build |
| `paper/numbers_table.tex` | Appendix A — printed from `numbers.json`, never typed by hand |
| `numbers.json` | 98 numbers: value, re-derivation rule, artifact, artifact sha256 |
| `numrules.py` | the dictionary of rules: how a number is derived from bytes |
| `make_numbers.py` | builds `numbers.json` and Appendix A out of the rules |
| `paper_check.py` | number binding: re-derivation + presence in the text + presence in the PDF |
| `layout_check.py` | layout: overlapping word boxes and overflow past the margin; two routes |
| `string_check.py` | the 36 names the paper cites must survive into the source and into the printed PDF (added after F167) |
| `selftest_string.py` | proof that the name check goes red when a cited name is removed |
| `appendix_density.py` | the printed appendix must still be a table: lines per row, with a control document |
| `FAILURES_282.md` | instrument errors of round 282 (F167–F168), not one of them deleted |
| `selftest_paper.py` | corrupting a number / an artifact, deleting an artifact — the instrument must go red |
| `selftest_layout.py` | layout calibration: an ordinary document green, a defective one red |
| `live_witness/` | witness files of the live camera measurements (17:06–17:43, 4 October 2026) |
| `verification_runs/` | the audit instruments' output from the last run (the numbers point at these) |
| `VERIFICATION.md` | the re-verification report: what was re-checked, what was not, and why |
| `FAILURES_281.md` | instrument errors of that round (F161–F166), not one of them deleted |
| `MANIFEST.sha256`, `ARTIFACTS.md` | package manifest: `sha256sum -c MANIFEST.sha256` |

Type: TeX Gyre Pagella with its matching Pagella Math for the body and the formulas, DejaVu Sans
Mono for the hex dumps and hashes (round 282 replaced the first edition's DejaVu Serif, which is wider
and heavier: ink coverage on a body page falls from 4.22 % to 3.41 %, measured). The body is 12 pt and
a prose line averages **76.6** characters.

The package is English-only. The Russian edition source of the same text
(`paper/main_ru.tex`) was never built — this container has no Russian hyphenation patterns and the
RU layout overflowed the margin (measured: 5 overflows) — and it has been moved out of the
package to `/work/SONY_A7SIII_ru_edition_draft/`, so that nothing Russian ships.

## What is checked inside the paper itself

* **98 numbers**: 66 are derived from raw bytes, 16 from saved instrument output, 16 are constants
  with a named source (the stream frames, the `tar` member count, external measurements). The
  split is printed in `numbers.json` and in VERIFICATION.md §5.
* **the sha256 of all 12 artifacts** is compared on every check: file drift is caught.
* **layout**: 0 overlaps, 0 overflows, 0 ink outside the safe frame — on this PDF.
* **the self-tests** prove that both instruments can go red.

## What is not in the package, and why

No key material: neither the value of the body key nor the private key — neither in the paper nor
in the instruments. At run time the instruments read the body key out of the audit source
(`../audit/newkeys_probe.py`) and print only fingerprints. There are no exploits: the audit is
static, not one byte was sent to the camera and not one authentication attempt was made. The
unpacked stream (740 MB) is not in the package either — it lives in the project working folder
(`../out/stream.bin`).
