# Instrument errors of this round — F167–F168 (not one of them deleted)

_Continuation of the F140–F166 list (rounds 276–281). Round 282 translated the whole package into
English, changed the paper's typeface, and revised the paper after the owner's review. Two errors are
recorded here, and neither of them was found by an instrument of mine._

## F167 — the paper had lost fifteen inline fragments, and no instrument could see it

**What happened.** The owner read the text extracted from the printed PDF and found holes in it: two
examples were a sentence about a single `HostKey` line and one about lines beginning with an armour
string. A systematic search then showed the loss was not local. **Fifteen inline fragments were missing
from the source of the paper**, in twelve sentences, and they had been missing since round 281 — the
delivered round-281 package (`/Volumes/Transcend234/SONY_A7SIII_PAPER_281/paper/main.tex`) carries the
same holes.

| # | the sentence that had a hole | what was missing | where the fact comes from |
|---|---|---|---|
| 1 | "there are 5 lines beginning  and the same number of `END` lines" | `BEGIN OPENSSH PRIVATE KEY` | ROUND_278.md §2 |
| 2 | "inside the member , in a block of 504 bytes" | `0700_part_image/dev/nflasha5` | ROUND_278.md §3 |
| 3 | "The `sshd_config` member (, 3094 bytes, at offset 740 733 952)" | `0800_appli/tmp/ssh/sshd_config` | ROUND_278.md §4a |
| 4 | "contains a single `HostKey` line, , and exactly four algorithm lines" | `HostKey /tmp_network/ssh/ssh_host_ecdsa_key` | ROUND_278.md §4a |
| 5 | "the script that creates such a key --- : ." | `/usr/bin/create_host_key.sh` and the command `ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key` | ROUND_278.md §4b |
| 6 | "(`PubkeyAuthentication no`, `PermitRootLogin no`, , `MaxSessions 0`)" | `PasswordAuthentication no` | ROUND_278.md §4d |
| 7 | "including `AES_encrypt`, `SM4_encrypt`, `Camellia_cbc_encrypt` and ;" | `CMS_EncryptedData_it` and the `[Encrypt] Error:` branch | ROUND_278.md §1 |
| 8 | "**(4) The numbers of this paper.**  re-derives every number" | `paper_check.py` | publication/paper_check.py |
| 9 | "printed PDF, and  proves the instrument can go red" | `selftest_paper.py` | publication/selftest_paper.py |
| 10 | "A separate layout instrument () checks the printed pages" | `layout_check.py` | publication/layout_check.py |
| 11 | "Audit instruments: ," | `audit/checks.py` | audit/checks.py |
| 12 | "`audit/round278_check.py`, ; the live ones are" | `audit/verify_findings.py` | audit/verify_findings.py |
| 13 | "the live ones are  (needs `paramiko`) and" | `audit/round279_check.py` | audit/round279_check.py |
| 14 | "and  on a Mac" | `MAC_FINGERPRINT.sh` | audit/make_279_delivery.py |
| 15 | "Paper:  --- it runs the instruments, rebuilds the numbers" | `publication/run_all.sh` | publication/run_all.sh |

**Why no instrument noticed.** `paper_check.py` tests numbers: all 98 of them were still there, so it
stayed green. `layout_check.py` measures the boxes that are present — text that is not there has no box,
no overlap and no overflow, so it too stayed green. `report_check.py` compares the report against the
instrument output, and the report was right; it was the paper that had lost the names. The gap is worth
stating plainly: **an instrument that checks what is there cannot notice what is gone.** Two of the
fifteen holes were found by a human reading the print; the other thirteen were found afterwards, by
searching the source for the artefacts a dropped token leaves behind (an empty `\code{}`, two spaces
where one was, a space before punctuation).

**What closes it.** `publication/string_check.py`, in three routes:
 A. **46 names** the paper's claims rest on — each with the artifact it comes from, written from the audit
    artifacts rather than from `main.tex` — must be present in the source;
 B. the same names must be present in the text extracted from the printed PDF (whitespace stripped, so a
    name broken across a line still counts);
 C. the source is searched for the artefacts of a dropped token, with its own control line.
`publication/selftest_string.py` proves routes A and B go red when a cited name is removed (source-only
removal: `source=False pdf=True`; removal that reaches the rebuilt PDF: `source=False pdf=False`). All
three routes run inside `run_all.sh`, and a red one now stops the run.

**Also closed by the same pass:** two names the paper had never carried at all — `key_cxd90057_k8` (the
key that opens the body) and `/dev/nflasha15` (the `/usr` image member). They are in the text now.

**What is not established.** *How* the fragments were lost. They were removed while the paper was
assembled in round 281 — not by any later edit, since the round-281 delivery proves they were already
gone — and I have not reproduced the mechanism; it belongs to the same open-question class as F158. What
can be said is what made the loss invisible: every missing piece was an inline code token inside an
otherwise complete sentence, so the prose still read as prose, and every instrument I had was looking at
numbers, boxes or the report — never at the paper's names.

**Consequence for the owner.** The handover PDF of round 281 has these holes in twelve sentences. The
round-282 package has all fifteen fragments restored, `string_check.py` green on the printed PDF (46/46,
route C clean, both controls firing), and the two names above added.

## F168 — a killed run left the recorded artifact hash stale, and the check caught it

`run_all.sh` was started, then stopped so that the paper could be revised before the final run. Stopping
it mid-flight (an orphaned `verify_findings.py` finishing into `verification_runs/`, then
`round279.txt` being rewritten by a second instrument pass) left `numbers.json` holding the sha256 of an
older copy of `publication/verification_runs/round279.txt`. The next `paper_check.py` reported exactly
that: `publication/verification_runs/round279.txt: 16845b9599906956 != b9fd136f95e54859`, 4/5 green,
`RESULT: NOT BOUND`. This is the artifact-drift leg of the number binding doing its job on my own
working state rather than on someone else's file — the same class as F164 read the other way round:
here the instrument was right and the state had moved. It was cleared by running the whole chain again
(`run_all.sh`), which re-derives the hashes after the instruments have written their output.

## F169 — Appendix A degenerated into a wall of digits, and the layout instrument was blind to it

**What the owner saw.** Reading the printed PDF, he described pages 14–15 as a table of "1 1 1 1 1 …"
and said the appendix had not rendered as a table at all.

**What was actually printed**, measured on that PDF with the same route `layout_check.py` uses
(`pdftotext -bbox-layout`): the appendix was a four-column table at `\scriptsize`. One DejaVu Sans Mono
character there is **5.038 pt** wide, so the number column (0.24`\textwidth` = 111 pt) held **22
characters per line**: a 64-hex sha256 needed three lines, and the 16-hex sha256 column printed its
digits in fragments that all started at the same x — a vertical strip of characters rather than a
column of values. The table took **294 text lines for 98 rows (2.88 lines per row)** across pages 13–15.
The header row wrapped so badly that "number" and "what it is" do not even share a baseline in the
printed round-281 PDF: a table whose header cannot be read in one glance.

**Why no instrument noticed.** `layout_check.py` measures two things: word boxes that overlap, and
text that leaves the type area. A table with columns too narrow for their content has neither — every
word sits neatly inside its own cell. This is the third blind spot of the round, and the same shape as
F167: an instrument that checks what is present and where it is, but never whether it can be *read*.

**Fixed how.** `make_numbers.py` now prints the numbers grouped by artifact: the artifact path and its
sha256 prefix appear **once per group** (12 groups instead of a sha256 column repeated 98 times), and
the table has two wide columns (0.46 and 0.50 of the text width), where a cell fits in at most two
lines. Measured on the rebuilt PDF: the appendix takes pages 13–14, **94 rows measured, tallest row 3
lines, mean 1.93 lines per row**, and the header is a single readable row again.

**Two checks now stand where none stood before.**
* Preventive, inside the generator: `make_numbers.py` estimates the lines each cell needs at the
  measured character width and **stops the build** if any cell needs more than two (`MAX_LINES`), with a
  control — a 400-character cell must be reported over the limit, or the estimate is declared blind.
* Post-build: `publication/appendix_density.py` measures the **printed** appendix — tallest row ≤ 3
  lines, mean ≤ 2.5 — and builds a synthetic document with one over-full row (sixty words in a
  0.50`\textwidth` cell) that the same code must report as over the limit. That control caught a defect
  in the instrument itself: its first version planted a single 200-character word, which does not wrap
  at all (it overflows the column instead, which is `layout_check.py`'s business), so the control was
  blind and said so.
