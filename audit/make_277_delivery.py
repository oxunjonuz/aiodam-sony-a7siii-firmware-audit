#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build of the round-277 delivery onto the volume + sha256 comparison on both sides.

A delivery is an instrument too: after copying, every file is read back FROM THE VOLUME
and its sha256 is compared with the source sha256. Any discrepancy is a FAIL.
"""
import hashlib, json, os, shutil, subprocess, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
DST = '/work/transcend/SONY_A7SIII_AUDIT_277'
FILES = [
    'ROUND_277.md', 'AUDIT_REPORT.md', 'TZ_SONY_ADUDIT.md', 'README.md',
    'audit/round277_check.py', 'audit/round277_checks.json',
    'audit/f07.py', 'audit/f07.json', 'audit/f07_out.txt',
    'audit/frame_probe.py', 'audit/frame_probe.json',
    'audit/newkeys_probe.py', 'audit/newkeys_probe.json',
    'audit/unpack_full.py', 'audit/unpack_full.json',
    'audit/stream_analysis.py', 'audit/stream_analysis.json',
    'audit/keys_and_sig.py', 'audit/keys_and_sig.json',
    'audit/allkeys_sig.py', 'audit/allkeys_sig.json',
    'audit/verify_stream.py', 'audit/verify_stream.json',
    'audit/tail_rsa.py', 'audit/tail_rsa.json',
    'audit/checks.py', 'audit/evidence.json',
    'out/tar_members.txt', 'out/fs_filelist.txt', 'out/fs_config.xml', 'out/fs_chassis',
    'out/fs_body_version', 'out/fs_chkfirm.sh', 'out/fs_startupdate.sh',
    'out/public_key.pem', 'out/verify_key.pem', 'out/mount.conf', 'out/partinf.conf',
    'out/config.sum',
]


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


# extracted artifacts (for a reader on the Mac; these are data FROM the file)
os.makedirs(ROOT + '/out', exist_ok=True)
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
st = open(ROOT + '/out/stream.bin', 'rb')
FW_OFF, FW_SIZE = 1253888, 739658240


def members(buf, base, size):
    off, out = 0, []
    while off + 512 <= size:
        hd = buf[off:off + 512]
        if hd[:100].rstrip(b'\x00') == b'':
            off += 512
            continue
        if hd[257:262] != b'ustar':
            break
        nm = hd[0:100].rstrip(b'\x00').decode('latin1')
        sz = int(hd[124:136].rstrip(b'\x00 ').decode() or '0', 8)
        out.append((nm, base + off + 512, sz))
        off += 512 + ((sz + 511) // 512) * 512
    return out


f = open(ROOT + '/out/stream.bin', 'rb')
f.seek(FW_OFF)
head = f.read(4096)
# build the tar table of contents, reading as needed
f.seek(0)
pos = FW_OFF
ms = []
while pos + 512 <= FW_OFF + FW_SIZE:
    f.seek(pos)
    hd = f.read(512)
    if len(hd) < 512 or hd[257:262] != b'ustar':
        break
    nm = hd[0:100].rstrip(b'\x00').decode('latin1')
    sz = int(hd[124:136].rstrip(b'\x00 ').decode() or '0', 8)
    ms.append((nm, pos + 512, sz))
    pos += 512 + ((sz + 511) // 512) * 512
with open(ROOT + '/out/tar_members.txt', 'w') as fo:
    fo.write('no.\tsize\tname\n')
    for i, (nm, o, s) in enumerate(ms, 1):
        fo.write('%d\t%d\t%s\n' % (i, s, nm))
# two keys and two configs — as they are, for reading on the Mac
for nm, o, s in ms:
    if nm in ('0800_appli/setting/public_key.pem', '0800_appli/setting/verify_key.pem',
              '0100_config/mount.conf', '0300_partconf/partinf.conf',
              '0101_config_sum/config.sum'):
        f.seek(o)
        with open(ROOT + '/out/' + os.path.basename(nm), 'wb') as fo:
            fo.write(f.read(s))
        FILES.append('out/' + os.path.basename(nm))
f.close()

os.makedirs(DST, exist_ok=True)
manifest = {'source_root': ROOT, 'destination': DST, 'files': []}
for rel in FILES:
    src = os.path.join(ROOT, rel)
    if not os.path.exists(src):
        manifest['files'].append({'file': rel, 'status': 'MISSING-AT-SOURCE'})
        continue
    dst = os.path.join(DST, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copyfile(src, dst)
    a, b = sha(src), sha(dst)
    manifest['files'].append({'file': rel, 'bytes': os.path.getsize(src),
                              'sha256': a, 'match_after_copy': a == b})
bad = [m for m in manifest['files'] if not m.get('match_after_copy')]
manifest['all_match'] = not bad
manifest['n_files'] = len([m for m in manifest['files'] if m.get('match_after_copy')])
with open(DST + '/MANIFEST_277.json', 'w') as fo:
    json.dump(manifest, fo, indent=1, ensure_ascii=False)
print('files delivered:', manifest['n_files'])
print('everything matched byte for byte:', manifest['all_match'])
if bad:
    print('DISCREPANCIES:', bad)
# an independent check: sha256sum -c on the volume
lines = ['%s  %s' % (m['sha256'], m['file']) for m in manifest['files'] if m.get('sha256')]
with open('/tmp/sums277.txt', 'w') as fo:
    fo.write('\n'.join(lines) + '\n')
r = subprocess.run(['sha256sum', '-c', '/tmp/sums277.txt'], cwd=DST, capture_output=True, text=True)
print('sha256sum -c on the volume:', r.returncode, r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr[:200])
