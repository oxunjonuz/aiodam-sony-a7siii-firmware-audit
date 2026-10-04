#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Delivery of round 278 onto the volume + sha256 comparison on both sides.

A delivery is an instrument too: after copying, every file is read back FROM THE VOLUME and
its sha256 is compared with the source sha256. Any discrepancy is a FAIL.
"""
import hashlib
import os
import shutil
import sys

SRC = '/work/SONY_A7SIII_UPDATE'
DST = '/work/transcend/SONY_A7SIII_AUDIT_278'

FILES = [
    'ROUND_278.md', 'ROUND_277.md', 'AUDIT_REPORT.md', 'TZ_SONY_ADUDIT.md', 'README.md',
    'audit/round278_check.py', 'audit/round278_checks.json',
    'audit/round277_check.py', 'audit/round277_checks.json',
    'audit/fs_inventory.py',
    'out/fs_inventory.json', 'out/fs_filelist.txt', 'out/tar_members2.txt',
    'out/key_wbi_nflasha5.pem', 'out/key_pub.pub', 'out/key_pub_pem.pem',
    'out/fs_user.sqsh',
]
DIRS = [('out/fs_root', 'squashfs_root'), ('out/members', 'appli_members')]


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
    for srcdir, dstdir in DIRS:
        for dirpath, _dd, files in os.walk(os.path.join(SRC, srcdir)):
            for fn in files:
                s = os.path.join(dirpath, fn)
                rel = os.path.relpath(s, SRC)
                rel_dst = os.path.join(dstdir, os.path.relpath(s, os.path.join(SRC, srcdir)))
                d = os.path.join(DST, rel_dst)
                os.makedirs(os.path.dirname(d), exist_ok=True)
                shutil.copy2(s, d)
                copied.append(rel_dst)
    bad = []
    lines = []
    for rel_dst in copied:
        d = os.path.join(DST, rel_dst)
        rel_src = rel_dst
        if rel_dst.startswith('squashfs_root/'):
            rel_src = 'out/fs_root/' + rel_dst[len('squashfs_root/'):]
        elif rel_dst.startswith('appli_members/'):
            rel_src = 'out/members/' + rel_dst[len('appli_members/'):]
        s = os.path.join(SRC, rel_src)
        hs, hd = sha(s), sha(d)
        lines.append(f'{hd}  {rel_dst}')
        if hs != hd:
            bad.append((rel_dst, hs, hd))
    man = os.path.join(DST, 'MANIFEST.sha256')
    open(man, 'w').write('\n'.join(sorted(lines)) + '\n')
    print(f'files copied: {len(copied)} (+1 manifest)')
    print(f'discrepancies when reading back from the volume: {len(bad)}')
    for b in bad:
        print('  MISMATCH', b)
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main())
