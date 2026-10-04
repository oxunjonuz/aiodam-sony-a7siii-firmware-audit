#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""selftest_string.py — proof that the name check (string_check.py) can go red.

F167 in publication/FAILURES_282.md is the reason this file exists: five inline names had been lost
from the paper and paper_check.py, which guards the numbers, could not see it. A check whose whole job
is to notice something that is NOT there has to demonstrate that it fails when something really is not
there.

  M0  nothing changed                          -> the instrument must be green;
  M1  a cited name deleted from the SOURCE     -> the "source" route must go red;
  M2  the same name deleted and the PDF rebuilt -> both routes must go red;
  M3  the original restored and the PDF rebuilt -> green again.

The paper's source and its PDF are restored in a finally block; the PDF is then rebuilt from the
restored source, so the package is left exactly as it was found (the rebuild is also checked: M3 is not
declared passed unless the instrument is green against the rebuilt PDF).

Run: python3 publication/selftest_string.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TEX = os.path.join(HERE, 'paper', 'main.tex')
CHECK = os.path.join(HERE, 'string_check.py')
FAILS = []

# a name the paper cites, and a mangled form of it that must be reported as missing
NAME = 'MaxSessions 0'
BROKEN = 'MaxSessions 1'          # the cited directive is no longer there


def run_check():
    r = subprocess.run([sys.executable, CHECK], capture_output=True, text=True, timeout=900)
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def rebuild_pdf():
    r = subprocess.run(['xelatex', '-interaction=nonstopmode', '-halt-on-error', 'main.tex'],
                       cwd=os.path.dirname(TEX), capture_output=True, text=True, timeout=600)
    return r.returncode == 0


def report(name, ok, detail=''):
    print('%s %s%s' % ('PASS ' if ok else 'FAIL ', name, ('   [%s]' % detail) if detail else ''))
    if not ok:
        FAILS.append(name)


def main():
    rc, out = run_check()
    report('M0 no change: the name check is green', rc == 0 and 'EVERY CITED NAME' in out,
           'rc=%d %s' % (rc, out.strip().splitlines()[-1] if out.strip() else ''))

    tmp = tempfile.mkdtemp(prefix='seltest_string_')
    tex_copy = os.path.join(tmp, 'main.tex')
    pdf_copy = os.path.join(tmp, 'main.pdf')
    shutil.copy2(TEX, tex_copy)
    pdf = os.path.join(HERE, 'paper', 'main.pdf')
    shutil.copy2(pdf, pdf_copy)
    try:
        t = open(TEX, encoding='utf-8').read()
        assert t.count(NAME) >= 1, 'the name %r is not in the source to begin with' % NAME
        # M1: source only
        open(TEX, 'w', encoding='utf-8').write(t.replace(NAME, BROKEN))
        rc, out = run_check()
        report('M1 a cited name deleted from the source: the source route goes red',
               rc != 0 and 'MISSING' in out,
               'rc=%d; %s' % (rc, [l.strip() for l in out.splitlines() if 'MISSING' in l][:1]))
        # M2: source and the printed PDF
        ok_build = rebuild_pdf()
        rc, out = run_check()
        report('M2 the same name deleted and the PDF rebuilt: both routes go red',
               ok_build and rc != 0 and 'source=False pdf=False' in out,
               'build=%s rc=%d' % (ok_build, rc))
    finally:
        shutil.copy2(tex_copy, TEX)
        rebuild_pdf()

    rc, out = run_check()
    report('M3 restored and rebuilt: green again', rc == 0 and 'EVERY CITED NAME' in out,
           'rc=%d %s' % (rc, out.strip().splitlines()[-1] if out.strip() else ''))
    print('-' * 78)
    print('name-check self-test: %s' % ('OK' if not FAILS else 'NOT OK: %s' % FAILS))
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
