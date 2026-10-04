#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Delivery of round 284 onto the volume + sha256 comparison on both sides.

A delivery is an instrument too: after copying, every file is read back FROM THE VOLUME and its
sha256 is compared with the source sha256. Any discrepancy is a FAIL. Then MANIFEST.sha256 is
written inside the destination and `sha256sum -c` is run ON THE VOLUME, so that the check the
owner asked for is the one the delivery reports — not a claim of mine. The last step writes
DELIVERY_RECEIPT.md from these measurements, so the numbers in the receipt are produced by the
delivery, not typed by hand.

Round 284 is the English-only delivery with the three F158 fragments restored in the paper.
"""
import hashlib
import os
import shutil
import subprocess
import sys
import time

ROOT = '/work/SONY_A7SIII_UPDATE'
DEST = '/work/transcend/SONY_A7SIII_ENGLISH_284'

# what ships: the documents, the audit instruments and their output, the paper package
INCLUDE_DIRS = ['audit', 'publication']
INCLUDE_FILES = ['README.md', 'AUDIT_REPORT.md', 'TZ_SONY_ADUDIT.md',
                 'ROUND_277.md', 'ROUND_278.md', 'ROUND_279.md', 'ROUND_282.md', 'ROUND_284.md',
                 'MAC_FINGERPRINT.sh']
# never shipped: the subject, the unpacked stream, the isolated environment, the frozen snapshots
SKIP_DIRS = {'env', 'out', 'downloads', 'out_fwtool', 'tools', 'tmpwork', '__pycache__'}
SKIP_FILES = {'BODYDATA.DAT'}
RECEIPT = 'DELIVERY_RECEIPT.md'


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
    out = (r.stdout or '') + (r.stderr or '')
    ok_lines = sum(1 for l in out.splitlines() if l.endswith(': OK'))
    tail = out.strip().splitlines()[-1] if out.strip() else ''

    # the count of files carrying Cyrillic, measured on the DELIVERED bytes (not on the source)
    import re
    cyr_re = re.compile(r'[\u0400-\u04FF]')
    cyr_ext = {'.md', '.py', '.sh', '.tex', '.json', '.txt', '.cff', '.yml', '.yaml', '.xml',
               '.conf', '.cfg', '.csv', '.log'}
    cyr_files, cyr_chars = {}, 0
    for dp, dn, fn in os.walk(DEST):
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.splitext(f)[1] not in cyr_ext:
                continue
            try:
                t = open(p, encoding='utf-8', errors='ignore').read()
            except OSError:
                continue
            n = len(cyr_re.findall(t))
            if n:
                cyr_files[os.path.relpath(p, DEST)] = n
                cyr_chars += n

    stamp = time.strftime('%Y-%m-%d %H:%M:%S %z')
    with open(os.path.join(DEST, RECEIPT), 'w') as fh:
        fh.write('# Delivery receipt — round 284, written by audit/make_284_delivery.py\n\n')
        fh.write('* produced: %s\n' % stamp)
        fh.write('* source: `%s`\n' % ROOT)
        fh.write('* destination: `%s`\n' % DEST)
        fh.write('* delivery instrument: `audit/make_284_delivery.py`, sha256 `%s`\n'
                 % sha256(os.path.abspath(__file__)))
        fh.write('* files copied: **%d**, bytes: **%d**\n'
                 % (len(copied), sum(s for _, s, _ in copied)))
        fh.write('* sha256 mismatches after copying: **%d**\n' % len(bad))
        fh.write('* sha256 mismatches after reading every file back from the volume: **%d**\n'
                 % len(reread_bad))
        fh.write('* `sha256sum -c MANIFEST.sha256` on the volume: exit **%d**, **%d** lines OK,'
                 ' last line `%s`\n' % (r.returncode, ok_lines, tail))
        fh.write('* Cyrillic in the DELIVERED bytes: **%d** text files, **%d** characters%s\n'
                 % (len(cyr_files), cyr_chars,
                    ''.join('\n  * `%s` (%d)' % (k, v) for k, v in sorted(cyr_files.items()))))
        fh.write('\nThe manifest covers every file above except this receipt (it is written after'
                 ' the manifest; hashing itself would be circular).\n')

    print('files copied        :', len(copied))
    print('bytes               :', sum(s for _, s, _ in copied))
    print('sha256 mismatches   :', len(bad), bad[:5])
    print('read-back mismatches:', len(reread_bad), reread_bad[:5])
    print('sha256sum -c on the volume: exit=%d  %d OK  %s' % (r.returncode, ok_lines, tail))
    print('destination         :', DEST)
    return 0 if not bad and not reread_bad and r.returncode == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
