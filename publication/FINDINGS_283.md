# F158 — where and how 15 fragments were lost from the round-281 PDF

Round 283. Report against the commission "find the mechanism, do not repair". Subject: the
round-281 paper (`SONY_A7SIII_PAPER_281`). Nothing was modified: the round-281 package was only
read, `BODYDATA.DAT` and the audit artifacts were left untouched. The instrument of this round is
`f158_check.py` (in this same folder); its output is `f158_result.json`.

---

## 0. The answer

**This is not a loss out of the PDF and not a loss in the build. These fragments are absent from
the source of the English edition — they disappeared at the step that translated the Russian
source into English.**

That step was performed by the **author of the paper (a model), not by a program**: no script in
the tree does it, and the write itself is on record (`write_file` → `main_en.tex`, 34 708
characters). The established operation is therefore **translation**; "reproduce it with a
program" is impossible, and that is written up as a result, exactly as the commission requires.

The loss turned out to be **thresholded by length**, and the threshold is measured precisely:
exactly those `\lc{...}` tokens were lost whose **written form is longer than 48 characters**;
everything at 48 or below is not merely present but **byte-for-byte identical** to the Russian
file — `\allowbreak` placement and stray spaces inside the tokens included. That is the
signature not of a precis but of **line copying with a length limit**.

One correction to the wording of the commission: the fragments number not 15 but **17 distinct
(19 occurrences)** — `audit/verify_findings.py` went missing three times, and two names that
neither of us had searched for were added to the 15 you found.

---

## 1. Localisation (step 1 of the commission)

For every fragment, three questions: is it in the Russian source (`main_ru.tex`), is it in the
English source (`main.tex`), is it in the text layer of the printed PDF. The result is
**17 of 17**: `RU=Y  ENsource=N  PDF(English part)=N`.

| fragment | RU | EN source | PDF, English part | PDF, appendix |
|---|---|---|---|---|
| `BEGIN OPENSSH PRIVATE KEY` | Y | N | N | **Y** |
| `0700_part_image/dev/nflasha5` | Y | N | N | N |
| `0800_appli/tmp/ssh/sshd_config` | Y | N | N | N |
| `/tmp_network/ssh/ssh_host_ecdsa_key` | Y | N | N | N |
| `/usr/bin/create_host_key.sh` | Y | N | N | N |
| `ssh-keygen -q -b 256 -t ecdsa -N '' -f/tmp_network/ssh/ssh_host_ecdsa_key` | Y | N | N | N |
| `PasswordAuthentication no` | Y | N | N | N |
| `d2i_PKCS8_PRIV_KEY_INFO` | Y | N | N | N |
| `audit/verify_findings.py` (×3) | Y | N | N | N |
| `BEGIN ENCRYPTED PRIVATE KEY` | Y | N | N | N |
| `publication/paper_check.py` | Y | N | N | N |
| `publication/selftest_paper.py` | Y | N | N | N |
| `kex: host key algorithm: (no match)` | Y | N | N | N |
| `env/venv/bin/python3 audit/checks.py` | Y | N | N | N |
| `python3 audit/round279_check.py` | Y | N | N | N |
| `./MAC_FINGERPRINT.sh --ip <address of the camera>` | Y | N | N | N |
| `sh publication/run_all.sh` | Y | N | N | N |

Outcome: **the loss is in the source** (not in the build, not a reading artifact) — for all 17.

**The surviving fragments are found.** Control: six names from the same twelve sentences
(`sshd_config`, `HostKey`, `PubkeyAuthentication`, `MaxSessions 0`, `audit/round278_check.py`,
`RootLogin`) are found in both the source and the English part of the PDF. Second control: the
planted name `f158_no_such_fragment_anywhere.py` is found nowhere — so "not found" here means
"not found".

**A side finding produced by exactly this control (no instrument of round 281 saw it).**
`BEGIN OPENSSH PRIVATE KEY` *is* in the PDF — but not in the English text: it is in **Appendix A,
printed in Russian in the round-281 package**: pages 11–14 carry 2177 Cyrillic characters
("the numbers of the paper, their meaning and artifact…", "of which one is real", "corrections to
numbers recorded earlier"). That is, the English `main.tex` carries `\input{numbers_table.tex}`,
and `numbers_table.tex` itself is Russian. My first run of the instrument declared `PDF=Y` for
precisely this reason: it searched the whole PDF rather than the English part, and found the name
in the Russian appendix. After splitting the PDF into the English part and the appendix, the first
result became 17/17.

---

## 2. The build (step 2 of the commission)

The paper was rebuilt **twice from the same `main.tex`** (a copy of the folder in `/tmp`,
`xelatex` ×2):

* the two runs gave an **identical** text layer (31 032 characters each);
* **all 17 holes reproduce**, all 6 control names are present — the build neither creates nor
  removes them;
* a control proving that the route can see a presence at all: the fragment
  `d2i_PKCS8_PRIV_KEY_INFO`, typed back into the `.tex`, **appears** in the rebuilt PDF.

Outcome: **the build is excluded by measurement**, not by argument.

## 3. The LaTeX log (step 5 of the commission)

The round-281 `main.log` contains **not one** line matching `Runaway argument`, `Missing`,
`! LaTeX Error`, `! Undefined`, `! Extra`. The loss was **silent**. Control: a document with a
deliberately unclosed argument is built by the instrument on the spot and does produce
`Runaway argument` in the log — the search is sensitive.

## 4. The rule that separated what was lost from what stayed (step 3, "bisection")

The hypothesis to be broken was "something structural was lost" (`\code{}`, line breaks, the
build). It is broken — the rule turned out to be **numerical and exact**.

The Russian source contains **38** wrapped `\lc{}`/`\code{}` tokens of length ≥ 41 characters.
Of them **19 are present in the English edition and 19 were lost**. The lengths of the written
form:

* **the longest survivor is 48 characters** (`audit/round277_check.py`,
  `audit/round278_check.py`, `audit/round279_check.py` — all three);
* **the shortest casualty is 49 characters** (`audit/verify_findings.py`).

Between 48 and 49 there is not a single exception: the rule "≥ 49 → lost" holds for **all 19**,
and "≤ 48 → survived" for all 19. Two controls on that rule:

* **shifting the threshold breaks it**: at a threshold of 40 there are 19 contradictions — so
  48/49 is measured, not fitted;
* **the same rule applied to the hash macros `\hx`/`\hl` breaks too**: both long hash tokens
  (56 and 98 characters) survived. So the boundary is **not universal but macro-specific** — that
  is the honest limit of the rule, and I do not hide it.

And the main thing that separates copying from paraphrasing: **all 19 surviving tokens are
byte-for-byte identical** to the Russian ones — `\allowbreak` included, stray spaces included,
in the forms `Camellia\allowbreak \_cbc\_enc\allowbreak rypt` and `no match` →
`(no mat\allowbreak ch)`. A model retyping the text does not do that; copying a line does.
And where the fragments were cut, **debris was left behind**: a double space ("lines
beginning  and"), `, ,`, `: .`, `---\n,`.

## 5. The operation in the source (step 4 of the commission)

What is known for certain:

* the Russian edition is the **source** and the English one is derived: this is stated in the
  round-281 README ("`paper/main_ru.tex` — the Russian edition of the same text — is the
  **source**, it is not built") and is visible in the files themselves: both are 34 5xx
  characters with a 1:1 line correspondence, and the debris of the cutting stayed in the English
  file, not in the Russian one;
* the writing of the English edition is **on record** in my own work memory of that round:
  `write_file`, 34 708 characters, the file `publication/paper/main_en.tex`, then
  `cp main.tex main_ru.tex && mv main_en.tex main.tex`. So the English text is the result of an
  **authorial translation step**, not of a program;
* no program in the tree does this. Checked by search: `_brk()` in `make_numbers.py` is the only
  function that inserts `\allowbreak`, and it works only on the Appendix A table, deletes
  nothing, and never reads `main*.tex`; there is no `sed` or other text transformer over
  `main.tex` in the tree.

The established operation is therefore **translation** (a step performed by the author), and its
measurable signature is the **48/49-character threshold on a copied token**. The exact program
cannot be named: there is none. The commission allows for this: "'It does not reproduce' is a
valid result; write it up."

The 281 → 282 diff in those same twelve sentences shows exactly these holes — one per sentence,
on the plus side.

## 6. What the round-282 revision did — and what it left undone (step 6, a new result)

Across the 17 fragments: **8 came back verbatim**, **6 came back in a shortened form**
(`publication/paper_check.py` → `paper_check.py`, `env/venv/bin/python3 audit/checks.py` →
`audit/checks.py`, `python3 audit/round279_check.py` → `audit/round279_check.py`,
`sh publication/run_all.sh` → `publication/run_all.sh`, `./MAC_FINGERPRINT.sh --ip <address of
the camera>` → `MAC_FINGERPRINT.sh`, and `selftest_paper.py`), and **3 did not come back at
all**:

| still absent from edition 282 | where it stood in the Russian source |
|---|---|
| `d2i_PKCS8_PRIV_KEY_INFO` | the section on `pformat.elf` and its full OpenSSL (next to the restored `CMS_EncryptedData_it`) |
| `BEGIN ENCRYPTED PRIVATE KEY` | the section on the 8 armour-line blocks (line 535 of the Russian source) |
| `kex: host key algorithm: (no match)` | the section on the instrument that reddened twice (in edition 282 this place was rewritten in words: "negotiated no matching kex at all") |

These are not "fifteen more": the three omissions are technical strings rather than artifact
names, and that is exactly why they were caught neither by your list nor by the instrument
`string_check.py`'s list of 46 names.

**Closed in round 284.** All three were put back into `publication/paper/main.tex`, the chain
`publication/run_all.sh` was run again, and the three are now required names in
`string_check.py` (49 names, 49/49 present in the source and in the printed PDF) — so what
notices them next time is an instrument, not a reader's eye. The round-283 instrument
`f158_check.py` measures both editions: route E1 still records that the three are absent from the
**delivered and frozen** edition 282 (`/work/transcend/SONY_A7SIII_ENGLISH_282`), route E2 that
they are back in the live source of edition 284.

## 7. What this does not mean

* **It does not mean "the loss is unreproducible in general."** The **threshold** has been
  reproduced and measured; the **program** has not, because there is none. If someone (a person
  or a model) repeats the translation, the threshold may turn out to be different — I have no
  second run of the same translation.
* **It does not mean the instrument was "blind" by accident.** It was built to look at numbers
  (`paper_check`), at boxes (`layout_check`) and at the report (`report_check`) — and none of
  them looked at the **names** in the paper. That is exactly F167, and it is closed by
  `string_check.py`.
* **It does not mean the English edition of 281 was English.** Its Appendix A was Russian (§1).
  The round-282 revision cured that, but the defect is present in the published round-281
  package.
* The rule holds for **`\lc{}`**; for `\hx`/`\hl` it breaks (§4, second control). It must not be
  generalised to "all macros".

## 8. How this was checked

`f158_check.py` (in this folder): **9 non-control checks out of 9 green** and **5 controls out of
5 red** at the time of round 283 (threshold 40 must contradict; long `\hx`/`\hl` must break the
same rule; a fragment typed back must appear in the PDF; an unclosed argument must produce
`Runaway argument`; the restored form must be found in edition 282). The instrument is run **from
the delivered copy**, not from the working tree; the output is `f158_result.json`. After the
round-284 repair the same instrument reports **10 non-control checks out of 10 green and 5
controls out of 5 red**: route E1 measures the frozen edition 282, route E2 the live source of
284. The round-283 result is kept beside it as `f158_result_round283.json`.

The sources of round 281 were not modified: their `sha256sum` matches the manifest of the
round-281 package (`paper/main.tex` `2cd7a98c…`, `paper/main_ru.tex` `e2a1e7d2…`,
`paper/main.pdf` `68a5b426…`).

The instrument errors of that round are F170–F173 in `FAILURES_283.md`, not one of them deleted.
All four are of one class: the instrument measured a different object than the one it named (the
whole PDF instead of the English part; a substitution that never happened; an exact string where
the subject was an artifact name; whitespace removal that makes text "neighbouring" with
something standing between it).
