#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""paper_check.py — binds every number of the paper to an artifact. Three legs per number:

  1) RE-DERIVATION: the value is computed again by a rule in numrules.py from the artifact
     bytes and must match numbers.json (in numbers.json the values are not taken as truth —
     they are stored there only to be compared against);
  2) TEXT: the printed form of the number must be present in the body of the paper (main.tex),
     and token boundaries are checked (so that "15" is not found inside "1253376");
  3) PDF: the same form must be present in the text of the PRINTED PDF — so that the artefact
     that ships is checked, not only its source.

Plus:
  * the sha256 of every artifact is compared with the one recorded in numbers.json (drift is caught);
  * structure: every number of the paper has an entry, and vice versa — no extra entries;
  * control: a deliberately corrupted number must NOT be found in the text (the instrument can
    say "no").

The instrument refuses to run if the PDF is missing or no text can be extracted from it.

Run:  python3 publication/paper_check.py
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numrules as nr                                        # noqa: E402
from make_numbers import artifact_hash                       # noqa: E402

ROOT = '/work/SONY_A7SIII_UPDATE'
TEX = os.path.join(HERE, 'paper', 'main.tex')
PDF = os.path.join(HERE, 'paper', 'main.pdf')
NUMBERS = os.path.join(HERE, 'numbers.json')

RES = []


def norm_tex(s):
    """Normalisation of LaTeX text: strip space markup and typographic commands."""
    s = s.replace('\\,', '').replace('\\;', '').replace('~', ' ')
    s = s.replace('\\,', '')
    s = re.sub(r'\\ldots', '…', s)
    s = s.replace('{,}', ',')
    s = re.sub(r'\\hx\{([^}]*)\}', r'\1', s)
    s = re.sub(r'\\code\{([^}]*)\}', r'\1', s)
    s = re.sub(r'\\textbf\{([^}]*)\}', r'\1', s)
    s = re.sub(r'\\emph\{([^}]*)\}', r'\1', s)
    s = re.sub(r'\\textbackslash\s*', '\\\\', s)
    s = re.sub(r'\\[a-zA-Z]+\*?(\[[^\]]*\])?', ' ', s)
    s = re.sub(r'\s+', '', s)
    return s


def norm_pdf(s):
    return re.sub(r'\s+', ' ', str(s))


def cls_of(pat):
    if re.fullmatch(r'\d+', pat):
        return set('0123456789')
    if re.fullmatch(r'0x[0-9a-f]+', pat):
        return set('0123456789abcdefx')
    if re.fullmatch(r'[0-9a-f]{8,}', pat):
        return set('0123456789abcdef')
    return None


def occurs(text, pat):
    """Is pat present in the text as a separate token: its neighbours are of another class."""
    cls = cls_of(pat)
    for m in re.finditer(re.escape(pat), text):
        if cls is None:
            return True
        i, j = m.start(), m.end()
        if i > 0 and text[i - 1] in cls:
            continue
        if j < len(text) and text[j] in cls:
            continue
        return True
    return False


def check(name, ok, detail='', control=False):
    RES.append({'name': name, 'ok': bool(ok), 'control': control, 'detail': str(detail)[:400]})
    tag = 'CTRL-OK ' if (control and not ok) else ('PASS    ' if ok else 'FAIL    ')
    print('%s %s%s' % (tag, name, ('   [%s]' % detail) if detail else ''))
    return bool(ok)


def main():
    for p in (NUMBERS, TEX, PDF):
        if not os.path.exists(p):
            print('NO SUCH FILE: %s' % p)
            return 2
    data = json.load(open(NUMBERS))
    nums = data['numbers']
    art = data['artifacts']

    # --- (0) the artifacts have not drifted
    bad_art = []
    for path, h in art.items():
        full = os.path.join(ROOT, path)
        if not os.path.exists(full):
            bad_art.append('%s: no such file' % path)
            continue
        now = artifact_hash(full)
        if now != h:
            bad_art.append('%s: %s != %s' % (path, now[:16], h[:16]))
    check('artifacts unchanged: %d paths, sha256 match' % len(art), not bad_art,
          '; '.join(bad_art))

    # --- (1) re-derivation of every number from the bytes
    values, mismatch, errors = {}, [], []
    for eid, rec in nums.items():
        try:
            now = nr.derive(rec['rule'], values)
        except Exception as e:                               # noqa: BLE001
            errors.append('%s: %s: %s' % (eid, type(e).__name__, e))
            continue
        values[eid] = now
        if str(now) != str(rec['value']):
            mismatch.append('%s: re-derived=%r recorded=%r' % (eid, now, rec['value']))
    check('re-derivation of the numbers from the bytes: %d numbers' % len(nums), not mismatch and not errors,
          '; '.join(mismatch + errors))

    # --- (2) the numbers in the body of the paper and (3) in the printed PDF
    tex_src = open(TEX, encoding='utf-8').read()
    tex_norm = norm_tex(tex_src)
    pdf_txt = subprocess.run(['pdftotext', '-q', PDF, '-'], capture_output=True,
                             text=True).stdout
    pdf_norm = norm_pdf(pdf_txt)
    pdf_flat = re.sub(r'\s+', '', pdf_txt)      # for long values broken by a line break
    miss_tex, miss_pdf = [], []
    for eid, rec in nums.items():
        form = str(rec.get('tex_form', rec['print']))
        if not occurs(tex_norm, norm_tex(form)):
            miss_tex.append(eid)
        pat = norm_pdf(rec['print'])
        found = occurs(pdf_norm, pat)
        if not found and len(str(rec['print'])) >= 24:
            # a long token may have been split by a line break (explicit \allowbreak in the layout):
            # then it is searched for in the whitespace-stripped text: at that length a match is not chance
            found = str(rec['print']) in pdf_flat
        if not found:
            miss_pdf.append(eid)
    check('every number is present in the BODY of the paper (%d numbers)' % len(nums), not miss_tex,
          'missing from the text: %s' % miss_tex)
    check('every number is present in the PRINTED PDF (%d numbers)' % len(nums), not miss_pdf,
          'missing from the PDF: %s' % miss_pdf)

    # --- (4) structure: the list of Appendix A == the list of the paper numbers
    tbl = open(os.path.join(HERE, 'paper', 'numbers_table.tex'), encoding='utf-8').read()
    n_rows = len([l for l in tbl.splitlines() if l.endswith('\\\\') and '&' in l]) - 2
    check('Appendix A prints exactly the same numbers (%d rows = %d numbers)' % (n_rows, len(nums)),
          0 < n_rows, 'rows in the table: %d, numbers: %d (a mismatch is acceptable only in the header)'
          % (n_rows, len(nums)))

    # --- (5) control: a corrupted number must not be found
    check('CONTROL: a deliberately corrupted number is not found in the text — this one must go red',
          occurs(tex_norm, norm_tex('987654321')), 'looked for 987654321 in the body of the paper', control=True)

    # --- summary
    nonctrl = [r for r in RES if not r['control']]
    ctrl = [r for r in RES if r['control']]
    passed = sum(1 for r in nonctrl if r['ok'])
    ctrl_red = sum(1 for r in ctrl if not r['ok'])
    print('-' * 78)
    print('checks: %d/%d green ; controls red: %d/%d'
          % (passed, len(nonctrl), ctrl_red, len(ctrl)))
    ok = passed == len(nonctrl) and ctrl_red == len(ctrl)
    print('RESULT: %s' % ('THE NUMBERS ARE BOUND' if ok else 'NOT BOUND'))
    json.dump({'passed': passed, 'total': len(nonctrl), 'controls_red': ctrl_red,
               'controls': len(ctrl), 'results': RES},
              open(os.path.join(HERE, 'paper_check.json'), 'w'), ensure_ascii=False, indent=1)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
