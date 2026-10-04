# The instrument errors of this round — F174–F178 (not one of them deleted)

_Continuation of the list F140–F173. Round 284 put three lost fragments back into the English
edition of the paper, rebuilt the chain and delivered the package. Five errors are recorded below.
Four of them are of the class **"the result was read off the wrong representation"** — the same
class as F170–F173 — and the fifth is an **environment failure read as a check result**. Three of
the five are mine rather than an instrument's. None of them changed a reported number, and the
ones that could have were caught before they did._

## F174 — a name searched for in its plain form inside LaTeX source

To put the fragments back, I first looked for them in the Russian source the obvious way:
`grep -n "d2i_PKCS8" main_ru.tex`. It printed **nothing**, which reads as "the Russian source does
not contain this fragment either" — and that would have turned the whole commission into an error
of mine. The fragment is there; it is written `\lc{d2i\_PKCS\allowbreak
8\_PRIV\_K\allowbreak EY\_INFO}`, so the name is **split by `\allowbreak` and its underscores are
escaped**. The plain form of a name is not the form a LaTeX source stores it in. I noticed only
because the same grep also failed on `ENCRYPTED`, which I knew to be present; the search was then
redone over the extracted `\lc{...}` tokens (34 of them), where all three appear. Class: the
instrument (here: a grep) measured a different representation than the one it named.

## F175 — a truncated print read as the complete list

`scan_cyrillic.py` prints the offending lines and then "… and 128 more"; it had been run in a
pipeline whose output I aggregated by hand, and the aggregation said **two** files carried
Cyrillic. The true number was **three** — the instrument's own printed excerpt stops before the
rest, and I read the excerpt as the list. The error was caught by writing the walk again
independently (same rule: U+0400–U+04FF, same skipped directories), which reported three files
with 58 Cyrillic characters in total, and named the third one (`f158_check.py`, whose
page-splitting regex used a literal Cyrillic range). Class: a printed sample taken for the
population.

## F176 — the status of a probe read from the wrong layer

While checking whether the rebuild route of `f158_check.py` really rebuilds (its `build()` ignores
`xelatex`'s exit code — see F177), I measured one build by hand: `time xelatex ...` returned
**rc=127**, which reads as "xelatex is not installed" and would have discredited four green checks
of the round-283 instrument. `time` is not a POSIX-shell keyword — this shell is `/bin/sh`, so the
command failed *before* reaching `xelatex`, and the exit code belonged to the shell, not to the
build. Re-measured without `time`: rc=0 in 1 s, and the rebuilt PDF differs from the copy it
replaced (sha256 `68a5b426…` → `78f14ddb…`), so the rebuild route of the instrument is live. No
reported number came from the bad probe. Class: an exit code read at the wrong layer.

## F177 — OPEN DEFECT, not fixed: a build whose failure would go unnoticed

`f158_check.py`'s `build()` runs `xelatex` twice with `capture_output=True` and **never looks at
the return code**. If a build failed, the route would not error out: it would measure the
`main.pdf` that was copied into the temporary directory together with the source — and routes C1
("two rebuilds give the same text") and C2 ("the holes reproduce in the rebuilt PDF") would then be
comparing the historical PDF with itself and reporting green. Today the only thing standing
between that and a false green is the C-red control (a fragment typed into the `.tex` must appear
in the rebuilt PDF), which would fail. That is one control, not a guard, and I am recording the
defect rather than repairing it: the commission for this round was to put three fragments back and
deliver, not to rework the round-283 instrument, and every extra line in it is a new chance to
change the round-283 record. The repair is two lines: assert the return code, and assert that the
rebuilt PDF's sha256 differs from the copied one.

## F178 — a check that did not finish, read as a check that failed

As the last verification of the delivery I ran the number instrument **from the delivered copy**
(`/work/transcend/SONY_A7SIII_ENGLISH_284/publication/paper_check.py`) — the strongest available
check, because it would bind the numbers of the package to the package's own artifacts. It printed
`PASS artifacts unchanged: 12 paths, sha256 match` and `PASS re-derivation of the numbers from the
bytes: 98 numbers`, then died with
`NotADirectoryError: [Errno 20] Not a directory: '.../publication/paper/main.tex'`.

The cause was not the package and not the instrument: the volume itself had gone away between the
two lines — `/run/host_mark/Volumes`, the mount source, no longer existed, and `ls` on the mount
root answered "Not a directory" while `stat` still called it a directory. The error is recorded,
not worked around: **a run that dies in the middle is neither a pass nor a fail**, and the two
PASS lines above it are evidence about two specific checks (the delivered artifacts are
byte-identical, and the numbers re-derive from the bytes), not about the third. What this round
can honestly claim about the delivered package is therefore the delivery instrument's own
verification (110 files, read back twice from the volume, sha256 equal in every case,
`sha256sum -c` exit 0 on the volume) plus the name and layout checks re-run from the delivered
copy — not a completed number binding inside the delivered tree.

A note for a later round, not a fix: the same volume already swallowed a working directory during
a run in round 279 (the open question in F158). Two such events do not establish one mechanism,
and I am not claiming a link — but a delivery that was verified on that volume should be
re-verified there when it returns, not assumed.
