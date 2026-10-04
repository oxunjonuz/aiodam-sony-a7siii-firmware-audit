#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_layout.py — calibration of the instrument layout_check.py: it must be able to go red.

Three documents, built right here:
  GOOD     — ordinary text and a table: the instrument must come out clean;
  OVERLAP  — two cells placed at the same point: the letters of one lie on the other,
             and the instrument must see it (TeX will say almost nothing about it);
  WIDEWORD — a 250-character word with no hyphenation: overflow past the margin, which the
             instrument must see.

Without this file "layout is clean" means nothing: an instrument that never goes red
cannot tell a clean layout from a broken check.

Run: python3 publication/selftest_layout.py
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, 'layout_check.py')

PREAMBLE = (r'\documentclass[11pt]{article}' '\n'
            r'\usepackage[a4paper,margin=0.92in]{geometry}' '\n'
            r'\usepackage{fontspec}' '\n'
            r'\setmainfont{DejaVu Serif}' '\n'
            r'\setmonofont{DejaVu Sans Mono}' '\n'
            r'\begin{document}' '\n')
END = '\n\\end{document}\n'

GOOD = PREAMBLE + (
    'A normal paragraph of text that fits the type area without any trick. '
    'It has several lines and nothing overlaps.\n\n'
    '\\begin{tabular}{ll}\\hline left & right \\\\ \\hline a & b \\\\ \\hline\\end{tabular}\n'
) + END

OVERLAP = PREAMBLE + (
    '\\noindent'
    '\\makebox[0pt][l]{OVERLAPONE}'
    '\\makebox[0pt][l]{OVERLAPTWO}\n'
) + END

WIDEWORD = PREAMBLE + (
    '\\noindent\\texttt{' + 'A' * 250 + '}\n'
) + END


def build(name, src, tmp):
    tex = os.path.join(tmp, name + '.tex')
    open(tex, 'w').write(src)
    r = subprocess.run(['xelatex', '-interaction=nonstopmode', name + '.tex'],
                       cwd=tmp, capture_output=True, text=True, timeout=300)
    pdf = os.path.join(tmp, name + '.pdf')
    return pdf if os.path.exists(pdf) else None, (r.stdout or '')[-300:]


def run_check(pdf):
    r = subprocess.run([sys.executable, CHECK, pdf], capture_output=True, text=True, timeout=600)
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def main():
    tmp = tempfile.mkdtemp(prefix='seltest_layout_')
    fails = []
    for name, src, want_red, expect_word in (('GOOD', GOOD, False, None),
                                             ('OVERLAP', OVERLAP, True, 'OVERLAP'),
                                             ('WIDEWORD', WIDEWORD, True, 'OVERFLOW')):
        pdf, log = build(name, src, tmp)
        if not pdf:
            print('FAIL  %s: the build produced no PDF (%s)' % (name, log[-120:]))
            fails.append(name)
            continue
        rc, out = run_check(pdf)
        red = rc != 0
        ok = (red == want_red) and (expect_word is None or (expect_word in out) if want_red else True)
        seen = [l.strip() for l in out.splitlines()
                if l.strip().startswith(('OVERLAP', 'OVERFLOW', 'INK'))][:2]
        print('%s  %-9s rc=%d expected %s %s' % ('PASS ' if ok else 'FAIL ', name, rc,
                                                  'red' if want_red else 'green',
                                                  ('| ' + ' ; '.join(seen)) if seen else ''))
        if not ok:
            fails.append(name)
    print('-' * 78)
    print('calibration: %s' % ('OK — the instrument goes red on real defects and stays clean'
                               ' on a good document' if not fails else 'NOT OK: %s' % fails))
    return 0 if not fails else 1


if __name__ == '__main__':
    sys.exit(main())
