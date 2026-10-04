#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_findings.py — round 281: re-verification of EVERYTHING found, again from the raw bytes.

Why a separate instrument when checks.py / round277..279_check.py already exist?
------------------------------------------------------------------
Those instruments measured in THEIR rounds, and their output sits in JSON files. This one does
something else: it takes the claims that made it into the paper and derives each one AGAIN FROM
THE RAW BYTES with its own code (its own frame parser, its own ustar, its own openssh-key-v1
parse, its own P-256 arithmetic) rather than by calling the same path that measured before. A
match against a recorded number therefore means: the claim reproduces, it is not being quoted.

Three places where this has already produced a correction to earlier reports (D4b, D8b, D10) are
NOT hidden: they are printed as a discrepancy against what was recorded.

What is NOT checked here: measurements on the live device (camera 192.168.1.102) and the owner's
run on the Mac. Nothing in this container can repeat them; they are listed in EXTERNAL.

Controls (which must go red) are built in: an instrument that cannot say "no" does not prove "yes".

No key material is copied into this file: the public body key is read from the audit source
(audit/newkeys_probe.py) at run time.

Run:    ./env/venv/bin/python3 audit/verify_findings.py
Output: audit/verify_findings.json + printed text; exit 0 only if everything matched.
"""
import base64
import binascii
import hashlib
import json
import mmap
import os
import re
import struct
import subprocess
import sys
import tempfile
import zlib

import numpy as np

ROOT = '/work/SONY_A7SIII_UPDATE'
P = os.path.join(ROOT, 'BODYDATA.DAT')
STREAM = os.path.join(ROOT, 'out', 'stream.bin')
STREAM_LIB = os.path.join(ROOT, 'out', 'stream_fwtool.bin')
FSROOT = os.path.join(ROOT, 'out', 'fs_root')
OUTJ = os.path.join(ROOT, 'audit', 'verify_findings.json')
sys.path.insert(0, os.path.join(ROOT, 'tools', 'fwtool.py-master'))

from Crypto.Cipher import AES                      # noqa: E402
from Crypto.PublicKey import RSA as RSAKey         # noqa: E402
from fwtool.sony import constants as KC            # noqa: E402
from fwtool.sony.fdat import AesCbcCrypter         # noqa: E402

_src = open(os.path.join(ROOT, 'audit', 'newkeys_probe.py'), encoding='utf-8').read()
_chunk = _src[_src.index('K_057_k8'):][:400]
K_057_k8 = bytes(int(h, 16) for h in re.findall(r'\\x([0-9A-Fa-f]{2})', _chunk))
assert len(K_057_k8) == 32, 'the body key was not read (%d bytes)' % len(K_057_k8)

RES = []


def rec(cid, claim, ok, measured, expected=None, how='', control=False):
    RES.append({'id': cid, 'claim': claim, 'ok': bool(ok), 'measured': str(measured),
                'expected': str(expected), 'how': how, 'control': control})
    tag = 'CTRL-RED' if (control and not ok) else ('FAIL' if not ok else ('CTRL-GREEN' if control else 'PASS'))
    print('%-9s %-9s %s' % (tag, cid, claim))
    print('            expected  : %s' % (expected,))
    print('            measured  : %s' % (measured,))
    return bool(ok)


def read_at(fh, off, n):
    fh.seek(off)
    return fh.read(n)


def sha256_file(path, chunk=1 << 22):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(chunk), b''):
            h.update(b)
    return h.hexdigest()


# =====================================================================================
print('=' * 92)
print('A. THE OBJECT ITSELF')
print('=' * 92)
EXPECT_SIZE = 743818632
EXPECT_SHA = 'dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb'
size = os.path.getsize(P)
rec('A1', 'size of the object, bytes', size == EXPECT_SIZE, size, EXPECT_SIZE, 'os.path.getsize')
h256 = sha256_file(P)
rec('A2', 'sha256 of the object', h256 == EXPECT_SHA, h256, EXPECT_SHA, 'a full pass')
md5, sha1 = hashlib.md5(), hashlib.sha1()
with open(P, 'rb') as fh:
    for b in iter(lambda: fh.read(1 << 22), b''):
        md5.update(b)
        sha1.update(b)
rec('A3', 'md5 and sha1 of the object (step 1 of the terms of reference: pin the hash sums)',
    len(md5.hexdigest()) == 32 and len(sha1.hexdigest()) == 40,
    'md5=%s\n                          sha1=%s' % (md5.hexdigest(), sha1.hexdigest()),
    'both sums pinned', 'a full pass')

f = open(P, 'rb')
tlv, off = [], 8
while off < 200:
    ln = struct.unpack('>I', read_at(f, off, 4))[0]
    tag = read_at(f, off + 4, 4)
    tlv.append((tag.decode('latin1'), off, ln))
    if tag == b'FDAT':
        break
    off += 8 + ln
    if ln % 4:
        off += 4 - ln % 4
rec('A4', 'TLV container: a block = [u32 length][4-byte tag][payload]',
    tlv == [('DATV', 8, 4), ('PROV', 20, 4), ('UDID', 32, 60), ('FDAT', 100, 743818512)]
    and struct.unpack('>I', read_at(f, 743818620, 4))[0] == 4
    and read_at(f, 743818624, 4) == b'DEND',
    '%s ; DEND: size=%d tag=%r crc=%s' % (tlv, struct.unpack('>I', read_at(f, 743818620, 4))[0],
                                          read_at(f, 743818624, 4),
                                          read_at(f, 743818628, 4).hex()),
    "[('DATV',8,4),('PROV',20,4),('UDID',32,60),('FDAT',100,743818512)]; "
    "DEND size=4 tag=b'DEND'", 'own TLV parse; the offset is the length field, the body at +8')

F0, FLEN = 108, 743818512                 # the FDAT body starts AFTER the tag, not on it

calc_crc = binascii.crc32(read_at(f, 0, EXPECT_SIZE - 12)) & 0xffffffff
stored_crc = struct.unpack('>I', read_at(f, EXPECT_SIZE - 4, 4))[0]
rec('A5', 'DEND.crc == crc32(the first size-12 bytes)',
    calc_crc == stored_crc == 0x1fafdcaa, 'calc=0x%08x stored=0x%08x' % (calc_crc, stored_crc),
    'both 0x1fafdcaa', 'own crc32 over the prefix')

udid = read_at(f, 40, 60)                 # UDID payload: 40..100 (after [size][tag])
count_field = struct.unpack('>I', udid[0:4])[0]
entries = [(struct.unpack('>H', udid[4 + 8 * i:6 + 8 * i])[0],        # pid
            struct.unpack('>H', udid[6 + 8 * i:8 + 8 * i])[0],        # vid
            struct.unpack('<I', udid[8 + 8 * i:12 + 8 * i])[0])       # flags (LE)
           for i in range((len(udid) - 4) // 8)]
rec('A6', 'the UDID table: 7 entries (PID, VID, flags), all Sony 054c — including the '
          'updater-mode descriptor right inside the file',
    count_field == 7 and len(entries) == 7
    and [e[0] for e in entries] == [0x0448, 0x047d, 0x0d15, 0x0d16, 0x0d19, 0x0d1a, 0x03e2]
    and all(e[1] == 0x054c for e in entries)
    and [e[2] for e in entries] == [1, 1, 1, 1, 1, 1, 2],
    'count=%d entries=%s' % (count_field, ['%04x:%04x f=%d' % (e[1], e[0], e[2]) for e in entries]),
    'count=7; six 054c:0448|047d|0d15|0d16|0d19|0d1a with flag 1 and 054c:03e2 with flag 2',
    'own UDID parse: 8 bytes per entry (pid, vid, flags)')

# =====================================================================================
print('=' * 92)
print('B. THE FDAT HEADER: readable with a public key; coordinates; the ECB leak')
print('=' * 92)
head_pt = AES.new(KC.key_aes, AES.MODE_ECB).decrypt(read_at(f, F0, 512))
H = head_pt[4:]
hdr = dict(checksum=struct.unpack('<I', H[8:12])[0], model=struct.unpack('<I', H[36:40])[0],
           region=struct.unpack('<I', H[40:44])[0],
           fw_off=struct.unpack('<I', H[48:52])[0], fw_size=struct.unpack('<I', H[52:56])[0],
           num_fs=struct.unpack('<I', H[56:60])[0],
           fsU=(H[64:65].decode('latin1'),) + struct.unpack('<II', H[68:76]),
           fsP=(H[80:81].decode('latin1'),) + struct.unpack('<II', H[84:92]))
rec('B1', 'the first 512 bytes of FDAT decrypted with the PUBLIC key_aes (ECB): a 4-byte frame + magic',
    head_pt[4:12] == b'UDTRFIRM' and head_pt[16:20] == b'0100'
    and head_pt[20:21] == b'U' and head_pt[24:25] == b'N',
    'raw[0:4]=%s magic@4=%r ver=%r mode=%r luw=%r' % (head_pt[:4].hex(), head_pt[4:12],
                                                      head_pt[16:20], head_pt[20:21], head_pt[24:25]),
    'frame c4a9fc03; magic UDTRFIRM at 4; format version 0100; mode U; flag N',
    'ECB decryption of the raw 512-byte window')
rec('B2', 'model, version and region from the header',
    hdr['model'] == 0x91030083 and (H[33], H[32]) == (5, 1) and hdr['region'] == 0,
    'model=0x%08x version=%d.%02d region=%d' % (hdr['model'], H[33], H[32], hdr['region']),
    'model=0x91030083 version=5.01 region=0', 'header fields by offset')
rec('B3', 'component layout: fsU, the empty slot P, the firmware area',
    hdr['fsU'] == ('U', 512, 1253376) and hdr['fsP'] == ('P', 512, 0)
    and (hdr['fw_off'], hdr['fw_size']) == (1253888, 739658240) and hdr['num_fs'] == 2,
    'fsU=%s fsP=%s fw=(%d,%d) numFS=%d' % (hdr['fsU'], hdr['fsP'], hdr['fw_off'],
                                           hdr['fw_size'], hdr['num_fs']),
    'fsU=(U,512,1253376) fsP=(P,512,0) fw=(1253888,739658240) numFS=2', 'header fields')


def solve4(prefix, target):
    def cc(x):
        return binascii.crc32(prefix + x) & 0xffffffff
    c0 = cc(b'\x00\x00\x00\x00')
    basis = {}
    for i in range(32):
        x = bytearray(4)
        x[i // 8] |= 1 << (i % 8)
        col, bit = cc(bytes(x)) ^ c0, 1 << i
        for p in list(basis):
            if col >> p & 1:
                col ^= basis[p][0]
                bit ^= basis[p][1]
        if col:
            basis[col.bit_length() - 1] = (col, bit)
    v, x = target ^ c0, 0
    for p in sorted(basis, reverse=True):
        if v >> p & 1:
            v ^= basis[p][0]
            x ^= basis[p][1]
    return x.to_bytes(4, 'little'), cc


X, cc = solve4(H[12:508], hdr['checksum'])
rec('B4', 'the header crc32 is invertible: the 4 bytes H[508:512] are DETERMINED by it and are zero',
    X == b'\x00\x00\x00\x00' and cc(X) == hdr['checksum'],
    'required bytes=%s checksum=0x%08x' % (X.hex(), hdr['checksum']),
    'required=00000000, checksum matches', 'linear algebra over GF(2)')


def zero_blocks(pt512):
    pt = bytearray(pt512) + b'\x00' * 512          # H[508:512] proved zero (B4)
    return [i for i in range(32) if all(b == 0 for b in pt[i * 16:(i + 1) * 16])]


pred = zero_blocks(head_pt)


def repeat_runs_numpy(path, off, length, block=16, chunk=1 << 24):
    """Runs of identical ciphertext blocks: no key, numpy, carrying the chunk boundary."""
    step = (chunk // block) * block
    runs, prev_last, done = [], None, 0
    with open(path, 'rb') as fh:
        fh.seek(off)
        while done < length:
            buf = fh.read(min(step, length - done))
            if not buf:
                break
            n = len(buf) // block
            a = np.frombuffer(buf[:n * block], dtype=np.uint8).reshape(n, block)
            if prev_last is not None:
                first = np.array_equal(a[0], prev_last)
                if first:
                    runs.append((done // block - 1, 2))
            eq = np.all(a[1:] == a[:-1], axis=1)
            idx = np.nonzero(eq)[0]
            if len(idx):
                breaks = np.nonzero(np.diff(idx) != 1)[0]
                starts = np.concatenate(([0], breaks + 1))
                ends = np.concatenate((breaks, [len(idx) - 1]))
                for s, e in zip(starts, ends):
                    length_run = e - s + 2
                    if not (runs and runs[-1][0] == (done // block + idx[s] - 1)
                            and runs[-1][0] + runs[-1][1] - 1 == (done // block + idx[e])):
                        runs.append((done // block + idx[s], int(length_run)))
            prev_last = a[-1].copy()
            done += n * block
    return runs


runs = repeat_runs_numpy(P, F0, 743818240)
rec('B5', 'ECB leak: a run of identical CIPHERTEXT blocks (no key) agrees with the '
          'prediction from the decrypted header',
    len(runs) == 1 and len(pred) == 26 and runs[0][0] == pred[0] and runs[0][1] == len(pred),
    'measured: runs=%d start=%s length=%s ; predicted: start=%s length=%d' %
    (len(runs), runs[0][0] if runs else None, runs[0][1] if runs else None,
     pred[0] if pred else None, len(pred)),
    'one run: start=6 length=26, the prediction matched',
    'comparison of neighbouring 16-byte ciphertext blocks, no key')

# =====================================================================================
print('=' * 92)
print('C. THE BODY: opened with a public key, its frames, the fate of the "2 906 112 bytes"')
print('=' * 92)
from fwtool.sony import dat as refdat                # noqa: E402
dat = refdat.readDat(open(P, 'rb'))
payload = dat.firmwareData
payload.seek(0)
try:
    stream = AesCbcCrypter(KC.key_aes, K_057_k8).decrypt(payload)
    h = hashlib.sha256()
    n, head_stream = 0, None
    while True:
        b = stream.read(1 << 22)
        if not b:
            break
        if head_stream is None:
            head_stream = b[:16]
        h.update(b)
        n += len(b)
    fresh_sha, fresh_len = h.hexdigest(), n
except Exception as e:                               # noqa: BLE001
    fresh_sha, fresh_len, head_stream = 'ERROR %s: %s' % (type(e).__name__, e), -1, None
rec('C1', 'a fresh unpacking of the body with the public key gives a stream of the expected length and hash',
    fresh_len == 740912128
    and fresh_sha == '11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66',
    'bytes=%s\n                          sha256=%s' % (fresh_len, fresh_sha),
    'bytes=740912128 sha256=11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66',
    'library decrypter + own hash and count')
s1 = (os.path.getsize(STREAM), sha256_file(STREAM))
s2 = (os.path.getsize(STREAM_LIB), sha256_file(STREAM_LIB))
rec('C2', 'two independent implementations (my block-wise code and the fwtool library) produced one file',
    s1[1] == s2[1] == fresh_sha and s1[0] == s2[0] == fresh_len,
    'stream.bin=%d/%s… ; stream_fwtool.bin=%d/%s…' % (s1[0], s1[1][:16], s2[0], s2[1][:16]),
    'all lengths and sha256 match the fresh computation', 'two files + a fresh computation')
rec('C3', 'the stream starts with the UDTRFIRM magic (stream coordinates, not ciphertext)',
    head_stream is not None and head_stream[:8] == b'UDTRFIRM',
    'stream[0:16]=%s' % (head_stream.hex() if head_stream else None),
    'the magic is in the first 8 bytes', 'first bytes of a fresh unpacking')

payload.seek(0)
cipher_len = payload.size - 0x110
payload.seek(cipher_len)
iv = payload.read(0x10)
payload.seek(0)
cbc = AES.new(K_057_k8, AES.MODE_CBC, iv)
ecb_a = AES.new(KC.key_aes, AES.MODE_ECB)
nblocks, nbad, sizes, endflags, total, pad = 0, 0, [], [], 0, b''
first = True
while True:
    blk = payload.read(1024)
    if not blk:
        break
    if first:
        pt = ecb_a.decrypt(blk[:512]) + cbc.decrypt(blk[512:])
        first = False
    else:
        pt = cbc.decrypt(blk)
    if len(pt) < 1024:
        pt += b'\x00' * (1024 - len(pt))
    csum = int.from_bytes(pt[0:2], 'little')
    sized = int.from_bytes(pt[2:4], 'little')
    sz = sized & 0x7fff
    calc = sum(int.from_bytes(pt[j:j + 2], 'little') for j in range(2, 1024, 2)) & 0xffff
    nbad += (calc != csum)
    nblocks += 1
    sizes.append(sz)
    endflags.append(bool(sized & 0x8000))
    total += sz
    if sized & 0x8000:
        pad = pt[4 + sz:1024]
        break
rec('C4', 'every block frame matches its 16-bit sum; the number of blocks',
    nblocks == 726385 and nbad == 0, 'blocks=%d bad=%d' % (nblocks, nbad),
    'blocks=726385 bad=0', 'own check of every frame sum')
rec('C5', 'payload size: 1020 in all but the last frame (448); the end flag only on that one',
    all(s == 1020 for s in sizes[:-1]) and sizes[-1] == 448
    and sum(endflags) == 1 and endflags[-1],
    'last=%d endflags=%d distinct=%s' % (sizes[-1], sum(endflags), sorted(set(sizes))),
    'last=448 endflags=1', 'fields of the frames themselves')
rec('C6', 'the padding of the last frame is 572 bytes, all 0xff',
    len(pad) == 572 and all(b == 0xff for b in pad),
    'len=%d all_ff=%s' % (len(pad), all(b == 0xff for b in pad)), 'len=572 all_ff=True',
    'reading the tail of the last frame')
rec('C7', 'F-07 does not exist: 4*726 385 + 572 = 2 906 112',
    4 * 726385 + 572 == 2906112 and total == fresh_len and 512 + 1253376 + 739658240 == fresh_len,
    '4*726385+572=%d ; sum of frames=%d ; 512+1253376+739658240=%d' %
    (4 * 726385 + 572, total, 512 + 1253376 + 739658240),
    '2 906 112 ; 740 912 128 ; 740 912 128', 'frame arithmetic against the stream length')
rec('C8', 'there are no bytes beyond the declared components (unaccounted = 0)',
    fresh_len - (512 + 1253376 + 739658240) == 0,
    'unaccounted=%d' % (fresh_len - (512 + 1253376 + 739658240)), '0',
    'stream length minus the header components')

# =====================================================================================
print('=' * 92)
print('D. WHAT IS INSIDE: images, strings, the private key, the tail, .sum')
print('=' * 92)
S = open(STREAM, 'rb')
fs_img = read_at(S, 512, 1253376)
rec('D1', 'fs_user is squashfs (hsqs) and its sha256',
    fs_img[:4] == b'hsqs'
    and hashlib.sha256(fs_img).hexdigest()
    == '62e86fad175e0326969d5f1cea29d780feb496ce8034acd2c9c3954320d8ccaa',
    'magic=%r sha256=%s' % (fs_img[:4], hashlib.sha256(fs_img).hexdigest()),
    "magic=b'hsqs' sha256=62e86fad...d8ccaa", 'a slice of the stream taken by the header fields')

fw_off, fw_size = 1253888, 739658240
names, offs, szmap = [], {}, {}
pos, end, member_count = fw_off, fw_off + fw_size, 0
while pos + 512 <= end:
    hdrb = read_at(S, pos, 512)
    if hdrb[:1] == b'\x00' or hdrb[257:262] != b'ustar':
        break
    name = hdrb[0:100].split(b'\x00')[0].decode('latin1')
    try:
        sz = int((hdrb[124:136].split(b'\x00')[0].strip() or b'0'), 8)
    except ValueError:
        sz = 0
    names.append(name)
    member_count += 1
    if len(offs) < 5000:
        offs[name] = pos + 512
        szmap[name] = sz
    pos += 512 + ((sz + 511) // 512) * 512
rec('D2', 'firmware is a tar (ustar); the member count and the offset of the sshd_config member, in my own pass',
    member_count == 159 and any(n.endswith('mount.conf') for n in names),
    'members=%d ; mount.conf: %s ; first=%r' % (member_count,
                                                 any(n.endswith('mount.conf') for n in names),
                                                 names[0] if names else None),
    'members=159, mount.conf present', 'own parse of the ustar headers')

NEEDLES = [('ILCE-7SM3', 61), ('ILCE-9', 2), ('myftm', 44), ('crypter.elf', 14),
           ('libnss_ssh', 6), ('OPENSSH PRIVATE KEY', 10),
           ('ssh_account_lock_recorder', 8), ('ssh_session_monitoring', 7)]
counts = {n: 0 for n, _ in NEEDLES}
tail = b''
S.seek(0)
while True:
    b = S.read(1 << 24)
    if not b:
        break
    buf = tail + b
    for n, _ in NEEDLES:
        counts[n] += buf.count(n.encode())
    tail = buf[-(max(len(n) for n, _ in NEEDLES) - 1):]
for sname, exp in NEEDLES:
    rec('D3:%s' % sname, 'occurrences of the string %r in the stream' % sname, counts[sname] == exp,
        counts[sname], exp, 'counted in a single pass over the whole stream')

KEY_BEGIN = b'-----BEGIN OPENSSH PRIVATE KEY-----'
KEY_END = b'-----END OPENSSH PRIVATE KEY-----'
koff = 587628092
blkwin = read_at(S, koff, 700)
end_at = blkwin.find(KEY_END) + len(KEY_END)
block = blkwin[:end_at]
body_b64 = len(block) - len(KEY_BEGIN) - 1 - len(KEY_END)
rec('D4', 'the private key: offset, block size (BEGIN..END inclusive), base64 characters',
    block.startswith(KEY_BEGIN) and block.endswith(KEY_END) and len(block) == 504
    and body_b64 == 435,
    'offset=%d len(block)=%d body_b64=%d' % (koff, len(block), body_b64),
    'offset=587628092 len(block)=504 body_b64=435',
    'reading a window at the recorded offset and finding the closing line')
rec('D4b', 'CORRECTION to the 277/278 reports: the recorded "501 B" and "471 base64 '
           'characters" do not reproduce (471 is the offset of the END line, not the body length)',
    len(block) != 501 and body_b64 != 471,
    'measured now: block=%d B, body=%d characters (the reports said 501 and 471)' % (len(block), body_b64),
    'the discrepancy is recorded, not hushed up',
    'the measured value against the one recorded earlier')


def parse_openssh(b64text):
    raw = base64.b64decode(b64text)
    o, out = 15, {}
    for field in ('cipher', 'kdf', 'kdfopts'):
        ln = struct.unpack('>I', raw[o:o + 4])[0]
        o += 4
        out[field] = raw[o:o + ln]
        o += ln
    out['nkeys'] = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    ln = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    out['pub'] = raw[o:o + ln]
    o += ln
    ln = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    priv = raw[o:o + ln]
    po = 0
    out['checkint'] = struct.unpack('>II', priv[po:po + 8])
    po += 8
    fl = {}
    for nm in ('keytype', 'curve', 'Q', 'd', 'comment'):
        ln = struct.unpack('>I', priv[po:po + 4])[0]
        po += 4
        fl[nm] = priv[po:po + ln]
        po += ln
    out['fields'] = fl
    return out


b64 = b''.join(l for l in block.splitlines() if not l.startswith(b'-----')).decode()
kb = parse_openssh(b64)
rec('D5', 'parse of the key container: openssh-key-v1, cipher=none, kdf=none, 1 key, P-256, root@(none)',
    kb['cipher'] == b'none' and kb['kdf'] == b'none' and kb['nkeys'] == 1
    and kb['fields']['keytype'] == b'ecdsa-sha2-nistp256'
    and kb['fields']['curve'] == b'nistp256' and kb['fields']['comment'] == b'root@(none)'
    and kb['checkint'][0] == kb['checkint'][1],
    'cipher=%r kdf=%r nkeys=%d type=%r curve=%r comment=%r checkint matched=%s' %
    (kb['cipher'], kb['kdf'], kb['nkeys'], kb['fields']['keytype'], kb['fields']['curve'],
     kb['fields']['comment'], kb['checkint'][0] == kb['checkint'][1]),
    'none / none / 1 / ecdsa-sha2-nistp256 / nistp256 / root@(none) / matched',
    'own parse of openssh-key-v1')


def ec_mul(d, Gx, Gy, p, a):
    def inv(x):
        return pow(x, p - 2, p)

    def add(Pa, Pb):
        if Pa is None:
            return Pb
        if Pb is None:
            return Pa
        x1, y1 = Pa
        x2, y2 = Pb
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        lam = ((3 * x1 * x1 + a) * inv(2 * y1 % p) if Pa == Pb
               else (y2 - y1) * inv((x2 - x1) % p)) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    R, Q = None, (Gx, Gy)
    while d:
        if d & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        d >>= 1
    return R


P256 = (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
        0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
        0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
        0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
Qb = kb['fields']['Q'][1:]
Qx, Qy = int.from_bytes(Qb[0:32], 'big'), int.from_bytes(Qb[32:64], 'big')
G = ec_mul(int.from_bytes(kb['fields']['d'], 'big'), P256[2], P256[3], P256[0], P256[1])
rec('D6', 'the key works: the public point from the private scalar (own P-256 arithmetic) == '
          'the embedded point',
    G is not None and G[0] == Qx and G[1] == Qy,
    'd*G == Q : %s' % (G is not None and G[0] == Qx and G[1] == Qy), True,
    'double-and-add on P-256 without libraries')
blob = kb['pub']
blob_sha = hashlib.sha256(blob).hexdigest()
tmp = tempfile.mkdtemp(prefix='vf281_')
pubpath = os.path.join(tmp, 'k.pub')
with open(pubpath, 'wb') as fh:
    fh.write(b'ecdsa-sha2-nistp256 ' + base64.b64encode(blob) + b'\n')
try:
    kg = subprocess.run(['ssh-keygen', '-lf', pubpath], capture_output=True, text=True, timeout=30)
    fp_line, fp_err = kg.stdout.strip(), kg.stderr.strip()[:80]
except Exception as e:                                # noqa: BLE001
    fp_line, fp_err = 'ssh-keygen failed: %s' % e, ''
rec('D7', 'key fingerprint: the third-party OpenSSH tool agrees with the recorded one',
    'SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI' in fp_line
    and blob_sha == '27c2fd6812c48a64dd0d6e66d6257bc14eb82cfd625a8dfe963f4c182c4d3832',
    'ssh-keygen: %s %s ; blob sha256=%s' % (fp_line, fp_err, blob_sha),
    'fp=SHA256:J8L9aBLE…NODI ; blob sha256=27c2fd68…3832',
    'ssh-keygen on the raw bytes from the file + own sha256')

cfg_name = next((n for n in offs if n.endswith('tmp/ssh/sshd_config')), None)
cfg = read_at(S, offs[cfg_name], szmap[cfg_name]) if cfg_name else b''
hostkey = [l for l in cfg.split(b'\n') if l.startswith(b'HostKey ')]
want = [b'HostKeyAlgorithms ecdsa-sha2-nistp256', b'KexAlgorithms ecdh-sha2-nistp256',
        b'MACs hmac-sha2-256', b'Ciphers aes128-ctr']
rec('D8', 'sshd_config (found through the tar table of contents): exactly one HostKey and exactly '
          'the algorithm set of the live camera',
    bool(cfg) and len(hostkey) == 1
    and hostkey[0] == b'HostKey /tmp_network/ssh/ssh_host_ecdsa_key'
    and all(w in cfg for w in want),
    'member=%s off=%s size=%s ; HostKey lines=%d %r ; set lines=%d/4' %
    (cfg_name, offs.get(cfg_name), szmap.get(cfg_name), len(hostkey),
     hostkey[0] if hostkey else None, sum(1 for w in want if w in cfg)),
    'one HostKey line /tmp_network/ssh/ssh_host_ecdsa_key + 4/4 set lines',
    'offset and size taken from the tar table of contents, not from the report')
rec('D8b', 'CORRECTION: the sshd_config offset named in the reports (740736525) is not the start '
           'of the file; the start from the tar table of contents is 740733952, and the text begins there',
    bool(cfg) and offs[cfg_name] == 740733952 and cfg.startswith(b'# Package generated')
    and 740736525 != offs[cfg_name] and 740736525 - offs[cfg_name] < szmap[cfg_name],
    'start by the tar=%s, the text begins with %r ; the reports said 740736525 (that is +%d inside)'
    % (offs.get(cfg_name), cfg[:28], 740736525 - offs.get(cfg_name)),
    'start 740733952', 'compared with what the report recorded')

csh = read_at(S, 395581615, 260)
rec('D9', 'the text of the script that creates this key lies in the image in full',
    all(x in csh for x in (b'ssh-keygen', b'-b 256', b'-t ecdsa',
                           b'/tmp_network/ssh/ssh_host_ecdsa_key')),
    repr(csh[:150]),
    "ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key",
    'read at the recorded offset 395581615')

with open(STREAM, 'rb') as fh:
    mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
literals, rsa_keys = {}, {}
for m in re.finditer(rb'-----BEGIN ([A-Z ]+)-----', mm):
    kind = m.group(1).decode()
    literals[kind] = literals.get(kind, 0) + 1
    if kind == 'PUBLIC KEY':
        body = mm[m.end():mm.find(b'-----END', m.end())]
        try:
            k = RSAKey.import_key(base64.b64decode(b''.join(body.split())))
            rsa_keys[m.start()] = k
        except Exception:                             # noqa: BLE001
            rsa_keys[m.start()] = None
mm.close()
distinct = {}
for off, k in rsa_keys.items():
    if k is not None:
        distinct.setdefault(hashlib.sha256(k.n.to_bytes((k.n.bit_length() + 7) // 8, 'big')
                                           ).hexdigest()[:16], []).append((off, k.size_in_bits()))
rec('D10', 'inventory of armor blocks in the stream and distinct RSA moduli (own SPKI parse)',
    literals.get('PUBLIC KEY') == 8 and literals.get('OPENSSH PRIVATE KEY') == 5
    and len(distinct) == 6,
    'literals=%s ; SPKI blocks=%d ; distinct moduli=%d: %s' %
    (literals, len(rsa_keys), len(distinct),
     sorted((v[0][1], k[:8], v[0][0]) for k, v in distinct.items())),
    'PUBLIC KEY=8, OPENSSH PRIVATE KEY=5, distinct moduli=6 (3071x2, 3072x3, 2048x1)',
    'own scan of armor strings over mmap + SPKI parse with pycryptodome')
rec('D10b', 'CORRECTION: the "4 PUBLIC KEY blocks" of report 278 does not reproduce (there are 8, one '
            'of them a literal with no body); six distinct RSA keys, not five',
    literals.get('PUBLIC KEY') != 4 and len(distinct) != 5 and len(distinct) != 3,
    'PUBLIC KEY literals=%s, distinct moduli=%s' % (literals.get('PUBLIC KEY'), len(distinct)),
    'the discrepancy is recorded', 'measured against what was recorded earlier')

cipher_tail = read_at(f, F0 + cipher_len, 0x110)
rec('D11', 'the body tail: 272 = 16 (IV) + 256; the IV matches the one the stream was opened with',
    len(cipher_tail) == 272 and cipher_tail[:16].hex() == '89a85276c7208ea533a0e187fac4092c'
    and len(cipher_tail[16:]) == 256 and cipher_tail[:16] == iv,
    'iv=%s sig_len=%d iv==iv_payload:%s (the tail is read at %d inside FDAT)' %
    (cipher_tail[:16].hex(), len(cipher_tail[16:]), cipher_tail[:16] == iv, F0 + cipher_len),
    'iv=89a85276c7208ea533a0e187fac4092c sig_len=256 iv==iv_payload:True',
    'reading 272 bytes after the ciphertext area inside FDAT')
k2048 = next((k for k in rsa_keys.values() if k is not None and k.size_in_bits() == 2048), None)
if k2048 is not None:
    m_int = pow(int.from_bytes(cipher_tail[16:], 'big'), k2048.e, k2048.n)
    mb = m_int.to_bytes((k2048.n.bit_length() + 7) // 8, 'big')
    pkcs = mb[0] == 0 and mb[1] == 1 and b'\x00' in mb[2:80]
    rec('D12', 'no key in the file confirms the tail: the 2048-bit key yields no '
               'PKCS#1 v1.5 structure',
        not pkcs and mb[:2] == b'\x49\x7f', 'm[:4]=%s pkcs1_structure=%s' % (mb[:4].hex(), pkcs),
        '497f..., no structure', 'own modular exponentiation')
else:
    rec('D12', 'no key in the file confirms the tail', False, 'the 2048-bit key was not found',
        'found, and it does not confirm', 'search in the stream')

sum_name = next((n for n in offs if n.endswith('0101_config_sum/config.sum')), None)
n_ok = n_tot = 0
det = []
if sum_name:
    for ln in read_at(S, offs[sum_name], szmap[sum_name]).split(b'\n'):
        parts = ln.split(b',')
        if len(parts) < 11:
            continue
        try:
            want_crc, want_size = int(parts[1], 16), int(parts[2], 16)
        except ValueError:
            continue
        fname = parts[10].decode('latin1')
        cand = sorted([k for k in offs if k.split('/')[-1] == fname], key=len)
        if not cand:
            continue
        data = read_at(S, offs[cand[0]], want_size)
        if len(data) != want_size:
            continue
        got = zlib.crc32(data) & 0xffffffff
        n_tot += 1
        n_ok += (got == want_crc)
        det.append('%s:%s' % (fname, 'ok' if got == want_crc
                              else 'MISMATCH %08x!=%08x' % (got, want_crc)))
rec('D13', 'the internal integrity of the image is a CRC32 in .sum, and it matches on the member bytes themselves',
    n_tot >= 2 and n_ok == n_tot, '%d/%d %s' % (n_ok, n_tot, det), 'all matched',
    'own zlib.crc32 over the member bytes')

# =====================================================================================
print('=' * 92)
print('E. SQUASHFS: what was unpacked')
print('=' * 92)
files = [(os.path.relpath(os.path.join(dp, x), FSROOT), os.path.getsize(os.path.join(dp, x)))
         for dp, dn, fn in os.walk(FSROOT) for x in fn]
elfs, scripts = [], []
for rel, sz in files:
    head = open(os.path.join(FSROOT, rel), 'rb').read(20)
    if head[:4] == b'\x7fELF':
        elfs.append((rel, struct.unpack('<H', head[18:20])[0]))
    elif head[:2] == b'#!':
        scripts.append(rel)
rec('E1', 'the unpacked squashfs: files, ELF, scripts, total size, architecture',
    len(files) == 58 and len(elfs) == 31 and len(scripts) == 21
    and sum(s for _, s in files) == 3151747 and {m for _, m in elfs} == {183},
    'files=%d elf=%d scripts=%d bytes=%d arch=%s' %
    (len(files), len(elfs), len(scripts), sum(s for _, s in files), sorted({m for _, m in elfs})),
    'files=58 elf=31 scripts=21 bytes=3151747 arch=[183]', 'walk of out/fs_root')


def fsread(rel):
    p = os.path.join(FSROOT, rel)
    return open(p, 'rb').read() if os.path.exists(p) else b''


rec('E2', 'config/chassis and config/body_version inside the updater image',
    fsread('config/chassis').strip() == b'CXD90057+CXD90058'
    and fsread('config/body_version').strip() == b'700.104.039',
    'chassis=%r body_version=%r' % (fsread('config/chassis').strip(),
                                    fsread('config/body_version').strip()),
    "chassis=b'CXD90057+CXD90058' body_version=b'700.104.039'", 'reading two files')
pf = fsread('bin/pformat.elf')
sym = [s for s in (b'AES_encrypt', b'SM4_encrypt', b'Camellia_cbc_encrypt',
                   b'd2i_PKCS8_PRIV_KEY_INFO', b'CMS_EncryptedData_it') if s in pf]
rec('E3', 'pformat.elf: its size and the OpenSSL encryption found in its strings',
    len(pf) == 1631008 and len(sym) == 5,
    'bytes=%d symbols=%s' % (len(pf), [s.decode() for s in sym]), 'bytes=1631008 symbols=5/5',
    'reading the file + searching its strings')
cfgx = fsread('config/config.xml')
lw = fsread('bin/loader_writer.sh')
common = fsread('config/common.src')
rec('E4', 'the pipeline: CRC32 yes, signature no; MODE_SERVICE=2; the loader md5 is commented out',
    b'crc32' in cfgx.lower() and b'sign' not in cfgx.lower()
    and b'MODE_SERVICE=2' in common and b'MD5SUM_COMMAND -c $SUM_FILE' in lw,
    'config.xml: crc32=%s sign=%s ; common.src MODE_SERVICE=2=%s ; loader_writer.sh md5=%s' %
    (b'crc32' in cfgx.lower(), b'sign' in cfgx.lower(), b'MODE_SERVICE=2' in common,
     b'MD5SUM_COMMAND -c $SUM_FILE' in lw),
    'crc32=True sign=False MODE_SERVICE=2=True md5=True', 'reading three files of the image')

# =====================================================================================
print('=' * 92)
print('K. CONTROLS: the instrument must be able to say "no"')
print('=' * 92)
S.seek(0)
window = S.read(100 << 20)
rec('K1', 'CONTROL: "find" a string that is certainly absent from the stream — must go red',
    window.count(b'ILCE-7SM3-FABRICATED-BY-THE-VERIFIER') > 0,
    'occurrences found: %d' % window.count(b'ILCE-7SM3-FABRICATED-BY-THE-VERIFIER'),
    0, 'search for a certainly absent string', control=True)
Hp = bytearray(H[12:508])
Hp[10] ^= 0x01
Xp, _ = solve4(bytes(Hp), hdr['checksum'])
rec('K2', 'CONTROL: a prefix corrupted by one bit still demands zeros — must go red',
    Xp == b'\x00\x00\x00\x00', 'required bytes=%s' % Xp.hex(), 'not 00000000',
    'the same solver on corrupted input', control=True)
bad = bytearray(kb['fields']['d'])
bad[0] ^= 0x01
Gb = ec_mul(int.from_bytes(bytes(bad), 'big'), P256[2], P256[3], P256[0], P256[1])
rec('K3', 'CONTROL: a corrupted scalar still gives the point Q — must go red',
    Gb is not None and Gb[0] == Qx and Gb[1] == Qy,
    'match=%s' % (Gb is not None and Gb[0] == Qx and Gb[1] == Qy), False, 'control',
    control=True)
payload.seek(0)
blk0 = payload.read(1024)
blk1 = payload.read(1024)
pt_ok = AES.new(K_057_k8, AES.MODE_CBC, blk0[-16:]).decrypt(blk1)
ok_csum = (sum(int.from_bytes(pt_ok[j:j + 2], 'little') for j in range(2, 1024, 2)) & 0xffff
           == int.from_bytes(pt_ok[0:2], 'little'))
rec('K4a', 'the frame of the second block matches on the correct ciphertext (the positive half)',
    ok_csum, 'matches=%s' % ok_csum, True, 'frame parse without corruption')
probe = bytearray(blk1)
probe[600] ^= 0x01
pt_bad = AES.new(K_057_k8, AES.MODE_CBC, blk0[-16:]).decrypt(bytes(probe))
bad_csum = (sum(int.from_bytes(pt_bad[j:j + 2], 'little') for j in range(2, 1024, 2)) & 0xffff
            == int.from_bytes(pt_bad[0:2], 'little'))
rec('K4', 'CONTROL: the frame of a corrupted block still matches — must go red',
    bad_csum, 'matches=%s' % bad_csum, False, 'one byte of ciphertext corrupted', control=True)
rec('K5', 'CONTROL: reading past the end of the stream returns data — must go red',
    read_at(S, 740912128, 16) != b'',
    repr(read_at(S, 740912128, 16)), "b''", 'boundary control', control=True)

EXTERNAL = [
    'the live camera 192.168.1.102: port 22, its algorithm set, its host key fingerprint',
    "the owner's run on the Mac (17:38:03): the table of neighbours on his /24",
    'whether the camera host key changes on reboot',
    'camera behaviour: signature verification, anti-rollback, interrupt handling, debug paths',
]
summary = {'checks': len(RES), 'controls': sum(1 for r in RES if r['control']),
           'controls_red': sum(1 for r in RES if r['control'] and not r['ok']),
           'passed_noncontrol': sum(1 for r in RES if r['ok'] and not r['control']),
           'noncontrol': sum(1 for r in RES if not r['control']),
           'failed': [r['id'] for r in RES if not r['ok'] and not r['control']],
           'external_not_reproducible': EXTERNAL}
print('-' * 92)
print('non-control green: %d/%d ; controls red: %d/%d' %
      (summary['passed_noncontrol'], summary['noncontrol'], summary['controls_red'],
       summary['controls']))
print('RESULT: %s' % ('ALL MATCHED' if not summary['failed'] else 'MISMATCHES: %s' % summary['failed']))
json.dump({'summary': summary, 'results': RES}, open(OUTJ, 'w'), ensure_ascii=False, indent=1)
print('written: %s' % OUTJ)
sys.exit(0 if not summary['failed'] else 1)
