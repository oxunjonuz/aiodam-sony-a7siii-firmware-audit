#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""selftest_paper.py — proof that the instrument paper_check.py can go red.

Three corruptions, each on its own route, plus one "no corruption — green" check:

  M0  change nothing                        -> the instrument must be green;
  M1  corrupt a NUMBER in the body of the paper -> the "text/PDF" route must go red;
  M2  corrupt an ARTIFACT (one byte in a witness) -> the "artifact/re-derivation" route must go red;
  M3  DELETE an artifact                    -> the instrument must refuse to run.

The originals are restored in finally: this file leaves nothing corrupted behind.

Run: python3 publication/selftest_paper.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, 'paper_check.py')
TEX = os.path.join(HERE, 'paper', 'main.tex')
WITNESS = os.path.join(HERE, 'live_witness', 'live_probe_log.txt')
PY = '/work/SONY_A7SIII_UPDATE/env/venv/bin/python3' if os.path.exists(
    '/work/SONY_A7SIII_UPDATE/env/venv/bin/python3') else sys.executable
FAILS = []


def run_check():
    r = subprocess.run([PY, CHECK], capture_output=True, text=True, timeout=1800)
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def report(name, ok, detail=''):
    print('%s %s%s' % ('PASS ' if ok else 'FAIL ', name, ('   [%s]' % detail) if detail else ''))
    if not ok:
        FAILS.append(name)


def main():
    # M0: no corruption — green
    rc, out = run_check()
    report('M0 no corruption: the instrument is green', rc == 0 and 'THE NUMBERS ARE BOUND' in out,
           'rc=%d %s' % (rc, out.strip().splitlines()[-1] if out.strip() else ''))

    tmp = tempfile.mkdtemp(prefix='seltest_paper_')
    tex_copy = os.path.join(tmp, 'main.tex')
    wit_copy = os.path.join(tmp, 'live_probe_log.txt')
    shutil.copy2(TEX, tex_copy)
    shutil.copy2(WITNESS, wit_copy)
    try:
        # M1: corrupt a number in the body of the paper
        t = open(TEX, encoding='utf-8').read()
        assert '726\\,385' in t, 'the expected number 726\\,385 is not in the text'
        open(TEX, 'w', encoding='utf-8').write(t.replace('726\\,385', '726\\,386', 1))
        rc, out = run_check()
        report('M1 number corrupted in the text: the instrument goes red', rc != 0,
               'rc=%d; said: %s' % (rc, 'missing from PDF/text' if 'missing from' in out else out[-160:]))
        shutil.copy2(tex_copy, TEX)

        # M2: corrupt an artifact (one witness loses one probe)
        w = open(WITNESS, encoding='utf-8', errors='replace').read().splitlines(True)
        kept = [l for l in w if 'port22=OPEN' in l]
        open(WITNESS, 'w', encoding='utf-8').write(
            ''.join(l for i, l in enumerate(w) if not ('port22=OPEN' in l and i == w.index(kept[0]))))
        rc, out = run_check()
        report('M2 artifact corrupted (22 -> 21 probes): the instrument goes red',
               rc != 0 and ('live.probes_open' in out or 're-derivation' in out),
               'rc=%d; %s' % (rc, [l for l in out.splitlines() if 're-derivation' in l or 'artifact' in l][:1]))
        shutil.copy2(wit_copy, WITNESS)

        # M3: delete an artifact
        os.unlink(WITNESS)
        rc, out = run_check()
        report('M3 artifact deleted: the instrument refuses to run',
               rc != 0 and ('NO SUCH FILE' in out or 'artifact' in out.lower()),
               'rc=%d; %s' % (rc, out.strip().splitlines()[0] if out.strip() else ''))
    finally:
        shutil.copy2(tex_copy, TEX)
        shutil.copy2(wit_copy, WITNESS)

    # after restoring — green again (a control that the corruptions were undone)
    rc, out = run_check()
    report('M4 restored: the instrument is green again', rc == 0,
           'rc=%d %s' % (rc, out.strip().splitlines()[-1] if out.strip() else ''))
    print('-' * 78)
    print('number self-test: %s' % ('OK' if not FAILS else 'NOT OK: %s' % FAILS))
    json.dump({'fails': FAILS}, open(os.path.join(HERE, 'selftest_paper.json'), 'w'), indent=1)
    return 0 if not FAILS else 1


if __name__ == '__main__':
    sys.exit(main())
