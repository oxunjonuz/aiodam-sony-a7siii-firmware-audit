#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Delivery of round 279 onto the volume + sha256 comparison on both sides.

A delivery is an instrument too: after copying, every file is read back FROM THE VOLUME and
its sha256 is compared with the source sha256. Any discrepancy is a FAIL.
"""
import hashlib
import os
import shutil

SRC = '/work/SONY_A7SIII_UPDATE'
DST = '/work/transcend/SONY_A7SIII_AUDIT_279'

FILES = [
    'MAC_FINGERPRINT.sh',
    'ROUND_279.md',
    'ROUND_278.md',
    'AUDIT_REPORT.md',
    'TZ_SONY_ADUDIT.md',
    'README.md',
    'audit/round279_check.py',
    'audit/round279_checks.json',
    'out/live_probe_log.txt',
    'out/live_camera_ssh_keyscan.txt',
    'out/live_camera_key.pub',
    'out/round279_live_camera_report.txt',
    'out/round279_match_report.txt',
    'out/create_host_key.sh',
    'out/get_finger_print.sh',
]


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def main():
    os.makedirs(DST, exist_ok=True)
    copied = []
    for rel in FILES:
        s = os.path.join(SRC, rel)
        if not os.path.exists(s):
            print('MISSING', rel)
            return 2
        d = os.path.join(DST, rel)
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copy2(s, d)
        copied.append(rel)
    bad = []
    lines = []
    for rel in copied:
        hs, hd = sha(os.path.join(SRC, rel)), sha(os.path.join(DST, rel))
        lines.append(f'{hd}  {rel}')
        if hs != hd:
            bad.append((rel, hs, hd))
    with open(os.path.join(DST, 'MANIFEST.sha256'), 'w') as f:
        f.write('\n'.join(sorted(lines)) + '\n')
    print(f'files copied: {len(copied)} (+1 manifest)')
    print(f'discrepancies when reading back from the volume: {len(bad)}')
    for b in bad:
        print('  MISMATCH', b)
    for rel in copied:
        print(f'  {sha(os.path.join(DST, rel))[:16]}  {rel}')
    return 0 if not bad else 1


if __name__ == '__main__':
    raise SystemExit(main())
