#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Delivery of round 282 onto the volume + sha256 comparison on both sides.

A delivery is an instrument too: after copying, every file is read back FROM THE VOLUME and
its sha256 is compared with the source sha256. Any discrepancy is a FAIL.
Round 282 is the English-only delivery: every document, instrument and generated artifact of
the package is in English.
"""
import hashlib
import os
import shutil
import subprocess
import sys

ROOT = '/work/SONY_A7SIII_UPDATE'
DEST = '/work/transcend/SONY_A7SIII_ENGLISH_282'

# what ships: the documents, the audit instruments and their output, the paper package
INCLUDE_DIRS = ['audit', 'publication']
INCLUDE_FILES = ['README.md', 'AUDIT_REPORT.md', 'TZ_SONY_ADUDIT.md',
                 'ROUND_277.md', 'ROUND_278.md', 'ROUND_279.md', 'ROUND_282.md',
                 'MAC_FINGERPRINT.sh']
# never shipped: the subject, the unpacked stream, the isolated environment, the frozen snapshots
SKIP_DIRS = {'env', 'out', 'downloads', 'out_fwtool', 'tools', 'tmpwork', '__pycache__'}
SKIP_FILES = {'BODYDATA.DAT'}


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def walk():
    for name in INCLUDE_FILES:
        p = os.path.join(ROOT, name)
        if os.path.isfile(p):
            yield os.path.relpath(p, ROOT)
    for d in INCLUDE_DIRS:
        base = os.path.join(ROOT, d)
        for dp, dn, fn in os.walk(base):
            dn[:] = [x for x in dn if x not in SKIP_DIRS]
            for f in sorted(fn):
                if f in SKIP_FILES or f.endswith(('.aux', '.log', '.out', '.toc')):
                    continue
                p = os.path.join(dp, f)
                if os.path.getsize(p) > 40 * 1024 * 1024:
                    continue
                yield os.path.relpath(p, ROOT)


def main():
    files = sorted(set(walk()))
    copied, bad = [], []
    for rel in files:
        src = os.path.join(ROOT, rel)
        dst = os.path.join(DEST, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        hs, hd = sha256(src), sha256(dst)
        if hs != hd:
            bad.append('%s: %s != %s' % (rel, hs[:16], hd[:16]))
        copied.append((rel, os.path.getsize(src), hs))

    # read everything back from the volume once more (a second, independent pass)
    reread_bad = []
    for rel, size, hs in copied:
        dst = os.path.join(DEST, rel)
        if not os.path.exists(dst) or os.path.getsize(dst) != size or sha256(dst) != hs:
            reread_bad.append(rel)

    with open(os.path.join(DEST, 'MANIFEST.sha256'), 'w') as fh:
        for rel, size, hs in copied:
            fh.write('%s  %s\n' % (hs, rel))

    r = subprocess.run(['sha256sum', '-c', 'MANIFEST.sha256'], cwd=DEST,
                       capture_output=True, text=True)
    tail = (r.stdout or r.stderr).strip().splitlines()[-1] if (r.stdout or r.stderr) else ''

    print('files copied        :', len(copied))
    print('bytes               :', sum(s for _, s, _ in copied))
    print('sha256 mismatches   :', len(bad), bad[:5])
    print('read-back mismatches:', len(reread_bad), reread_bad[:5])
    print('sha256sum -c on the volume: exit=%d  %s' % (r.returncode, tail))
    print('destination         :', DEST)
    return 0 if not bad and not reread_bad and r.returncode == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
