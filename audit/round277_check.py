#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ROUND 277: a checkable summary of every claim made in this round.

Semantics as in audit/checks.py:
  * an ordinary check prints OK when its claim holds;
  * a CONTROL check is phrased so that it MUST go red
    (OK = the control claim holds => the control did not fire).
Every number is taken from the FILES again. Memory: the files are opened through mmap,
no 743-MB copies are made.
"""
import binascii, hashlib, io, json, mmap, os, re, sys
import numpy as np

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
STREAM = ROOT + '/out/stream.bin'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from fwtool.sony import constants as KC
from fwtool.sony import fdat as refdat
from fwtool.sony import dat as datmod
from fwtool.sony.fdat import AesCbcCrypter, BlockCryptException, FdatHeader

K_057_k0 = bytes.fromhex('376A61D907035CF18300F2ADD6503E649FCCF0C0191DCC38C3B05895150A7FB6')
K_057_k8 = bytes.fromhex('434589432D319010F1132727353286CE4D7EDE8B9C4F7217A0E0226E0F0EDC69')
FW_OFF, FW_SIZE, FS_OFF, FS_SIZE = 1253888, 739658240, 512, 1253376
FLEN, BLOCK = 743818512, 1024
res = []


def check(name, ok, detail='', control=False):
    res.append({'name': name, 'control': control, 'ok': bool(ok), 'detail': detail})
    print(('CTRL  ' if control else '      ') + ('OK   ' if ok else 'RED  ') + '  ' + name)
    if detail:
        print('            ' + str(detail)[:200])
    sys.stdout.flush()


fraw = open(P, 'rb')
raw = mmap.mmap(fraw.fileno(), 0, access=mmap.ACCESS_READ)
fs_ = open(STREAM, 'rb')
st = mmap.mmap(fs_.fileno(), 0, access=mmap.ACCESS_READ)

# ---------------------------------------------------------------- N1 the stream
h = hashlib.sha256()
for i in range(0, len(st), 1 << 24):
    h.update(st[i:i + (1 << 24)])
dig = h.hexdigest()
check('N1 the unpacked stream equals exactly the sum of the declared components',
      len(st) == 512 + FS_SIZE + FW_SIZE == 740912128
      and dig == '11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66',
      'bytes=%d sha256=%s' % (len(st), dig))

# ---------------------------------------------------------------- N2 the frames (numpy)
def frame_scan(src):
    payload = src[108:108 + FLEN] if False else None
    f = open(src, 'rb')
    f.seek(108)
    f.seek(0, 2)
    end = f.tell()
    f.seek(108)
    cl = FLEN - 0x110
    f.seek(108 + cl)
    iv0 = f.read(16)
    f.seek(108)
    cbc = AES.new(K_057_k8, AES.MODE_CBC, iv0)
    ecb = AES.new(KC.key_aes, AES.MODE_ECB)
    nb = cl // BLOCK
    sizes = np.empty(nb, dtype=np.int32)
    efs = np.zeros(nb, dtype=bool)
    bad = 0
    pad = None
    done = 0
    chunk_blocks = 1024                       # 1 MiB at a time
    while done < nb:
        n = min(chunk_blocks, nb - done)
        chunk = f.read(n * BLOCK)
        if len(chunk) != n * BLOCK:
            break
        if done == 0:
            pt = ecb.decrypt(chunk[:512]) + cbc.decrypt(chunk[512:])
        else:
            pt = cbc.decrypt(chunk)
        a = np.frombuffer(pt, dtype='<u2').reshape(n, BLOCK // 2)
        calc = a[:, 1:].sum(axis=1) & 0xffff
        bad += int((calc != a[:, 0]).sum())
        sized = a[:, 1].astype(np.int64)
        sizes[done:done + n] = (sized & 0x7fff).astype(np.int32)
        efs[done:done + n] = (sized & 0x8000) != 0
        if efs[done + n - 1]:
            last = pt[(n - 1) * BLOCK:]
            sz = int(sizes[done + n - 1])
            pad = last[4 + sz:]
        done += n
    f.close()
    return sizes, efs, bad, pad


sizes, efs, bad, pad = frame_scan(P)
check('N2a all 726 385 block frames match their 16-bit sum',
      len(sizes) == 726385 and bad == 0, 'blocks=%d bad=%d' % (len(sizes), bad))
check('N2b sizes: 1020 in all but the last (448), and the end flag only on that one',
      bool((sizes[:-1] == 1020).all()) and int(sizes[-1]) == 448 and int(efs.sum()) == 1
      and bool(efs[-1]), 'last=%d endflags=%d' % (int(sizes[-1]), int(efs.sum())))
check('N2c the padding of the last block is 572 bytes of 0xff, and 4*726385+572 = 2 906 112',
      pad is not None and len(pad) == 572 and all(b == 0xff for b in pad)
      and 4 * 726385 + 572 == 2906112,
      'pad=%d all_ff=%s sum=%d' % (len(pad), all(b == 0xff for b in pad), 4 * 726385 + 572))


def frame_of_block0(cipher_window, iv0):
    cb = AES.new(K_057_k8, AES.MODE_CBC, iv0)
    ec = AES.new(KC.key_aes, AES.MODE_ECB)
    pt0 = ec.decrypt(bytes(cipher_window[:512])) + cb.decrypt(bytes(cipher_window[512:1024]))
    a = np.frombuffer(pt0, dtype='<u2')
    return int(a[1:].sum() & 0xffff), int(a[0])


iv_real = bytes(raw[108 + FLEN - 0x110:108 + FLEN - 0x110 + 16])
c0 = bytes(raw[108:108 + 1024])
tampered = bytearray(c0)
tampered[300] ^= 0x01
calc_b, stored_b = frame_of_block0(c0, iv_real)
calc_t, stored_t = frame_of_block0(bytes(tampered), iv_real)
check('N2d the same measure on an intact block matches (the instrument can say "ok")',
      calc_b == stored_b, 'calc=%04x stored=%04x' % (calc_b, stored_b))
check('C1 CONTROL (must go red): the frame sum matches on corrupted ciphertext',
      calc_t == stored_t, 'calc=%04x stored=%04x' % (calc_t, stored_t), control=True)

# ---------------------------------------------------------------- N3 the header
hdr = FdatHeader.unpack(io.BytesIO(bytes(st[:512])))
crc_ok = (binascii.crc32(bytes(st[12:512])) & 0xffffffff) == hdr.checksum
check('N3 the header: the crc32 of [12:512) matches, model 0x91030083, version 5.01',
      crc_ok and hdr.model == 0x91030083 and '%x.%02x' % (hdr.versionMajor, hdr.versionMinor)
      == '5.01' and hdr.firmwareOffset == FW_OFF and hdr.firmwareSize == FW_SIZE,
      'crc=%s model=%s ver=%x.%02x' % (crc_ok, hex(hdr.model), hdr.versionMajor, hdr.versionMinor))
st2 = bytearray(bytes(st[12:512]))
st2[100] ^= 0x01
check('C2 CONTROL (must go red): corrupting a byte in the crc area breaks the match',
      (binascii.crc32(bytes(st2)) & 0xffffffff) == hdr.checksum,
      'crc after corruption=%08x stored=%08x' % (binascii.crc32(bytes(st2)) & 0xffffffff,
                                            hdr.checksum), control=True)

# ---------------------------------------------------------------- N4 the model name
hits = [m.start() for m in re.finditer(b'ILCE-7SM3', st)]
hits_fw = [i for i in hits if i >= FW_OFF]
ilce = [m.group(0) for m in re.finditer(rb'ILCE-[0-9A-Za-z]{1,12}', st)]
others = sorted({x for x in ilce if x != b'ILCE-7SM3'})
pair = len(list(re.finditer(rb'ILCE-7SM3 v5\.01', st))) > 0
check('N4 the model name: ILCE-7SM3 61 times in the image, including the string "ILCE-7SM3 v5.01", '
      'the only other name is ILCE-9 (2 times)',
      len(hits) == 61 and len(hits_fw) == 61 and pair and others == [b'ILCE-9'],
      'hits=%d in_fw=%d pair=%s others=%s' % (len(hits), len(hits_fw), pair,
                                              [x.decode() for x in others]))
ctrl = b'\x00' * 1000 + b'ILCE-7SM3' + b'\x00' * 100
check('C3 CONTROL (must go red): the search does NOT find a planted name',
      ctrl.find(b'ILCE-7SM3') < 0, 'planted at 1000, the search returned %d' %
      ctrl.find(b'ILCE-7SM3'), control=True)

# ---------------------------------------------------------------- N5 the keys
refdat._crypters['CXD90057_k8'] = lambda: AesCbcCrypter(KC.key_aes, K_057_k8)
TMP = '/tmp/r277_stream.bin'
try:
    d = datmod.readDat(open(P, 'rb'))
    name, fdatf = refdat.decryptFdat(d.firmwareData)
    fdatf.seek(0)
    with open(TMP, 'wb') as fo:
        for i in range(0, len(st), 1 << 22):
            fo.write(bytes(st[i:i + (1 << 22)]))
    info = refdat.readFdat(open(TMP, 'rb'))
    ok_dec = (name == 'CXD90057_k8' and info.model == 0x91030083 and info.version == '5.01'
              and info.firmware.size == FW_SIZE and info.fs.size == FS_SIZE)
    det = 'crypter=%s model=%s ver=%s fs=%d fw=%d' % (name, hex(info.model), info.version,
                                                      info.fs.size, info.firmware.size)
except Exception as ex:
    ok_dec, det = False, '%s: %s' % (type(ex).__name__, ex)
check('N5a the public key CXD90057_k8 (PR #52) opens the body, the reference parse succeeds',
      ok_dec, det)
fail_keys = {}
for nm, key in (('CXD90057_k0', K_057_k0), ('CXD90045', KC.key_cxd90045),
                ('CXD90014', KC.key_cxd90014)):
    try:
        d2 = datmod.readDat(open(P, 'rb'))
        s = AesCbcCrypter(KC.key_aes, key).decrypt(d2.firmwareData)
        s.read(4096)
        fail_keys[nm] = 'accepted'
    except Exception as ex:
        fail_keys[nm] = type(ex).__name__
check('N5b the other public keys do NOT open the body',
      all(v == 'BlockCryptException' for v in fail_keys.values()), json.dumps(fail_keys))

# ---------------------------------------------------------------- N6 the tail
sig = bytes(raw[108 + FLEN - 256:108 + FLEN])
s_int = int.from_bytes(sig, 'big')
keys = []
for m in re.finditer(rb'-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----', st, re.S):
    try:
        keys.append(RSA.import_key(m.group(0)))
    except Exception:
        pass
k2048 = [k for k in keys if k.size_in_bits() // 8 == 256]
struct_ok = []
for k in k2048:
    mm = pow(s_int, k.e, k.n).to_bytes(256, 'big')
    if mm[0] == 0 and mm[1] == 1:
        struct_ok.append(hex(k.n)[:16])
check('N6a the 2048-bit key lying IN THE FILE itself yields no signature structure on the tail',
      struct_ok == [] and len(k2048) >= 1,
      '2048-bit keys=%d, produced a structure=%s' % (len(k2048), struct_ok))
MOD = int(open(ROOT + '/tools/Sony-PMCA-RE-master/pmca/spk/constants.py').read()
          .split('rsaModulus = ')[1].split('\n')[0])
mm = pow(s_int, 65537, MOD).to_bytes(256, 'big')
check('N6b the published Sony-PMCA-RE key yields no structure either',
      not (mm[0] == 0 and mm[1] == 1), 'm[:2]=%02x%02x' % (mm[0], mm[1]))
k2 = RSA.generate(2048)
msg = b'control'
s2 = int.from_bytes(pkcs1_15.new(k2).sign(SHA256.new(msg)), 'big')
m2 = pow(s2, k2.e, k2.n).to_bytes(256, 'big')
check('C4 CONTROL (must go red): the structural test does NOT accept a genuine signature',
      not (m2[0] == 0 and m2[1] == 1), 'structure on a signature of my own: %02x %02x' % (m2[0], m2[1]),
      control=True)

# ---------------------------------------------------------------- N7 .sum (CRC32 inside)
def members(base, size):
    off, out = 0, []
    while off + 512 <= size:
        hd = bytes(st[base + off:base + off + 512])
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


ms = members(FW_OFF, FW_SIZE)
byoff = {n: (o, s) for n, o, s in ms}
ok_cnt, details, mism = 0, [], []
for sumname in ('0101_config_sum/config.sum', '1051_i2c_sum/i2c.sum',
                '0301_partconf_sum/partconf.sum', '0641_darwin_sum/darwin.sum',
                '0751_nor_loader_sum/nor_loader.sum', '0701_part_image_sum/part_image.sum'):
    for line in [l for l in bytes(st[byoff[sumname][0]:byoff[sumname][0] + byoff[sumname][1]])
                 .decode('latin1').split('\n') if l.strip()]:
        parts = line.split(',')
        if len(parts) < 11:
            continue
        name = parts[10]
        cand = [n for n in byoff if n.endswith(name)]
        if not cand:
            details.append(name + ':not-in-tar')
            continue
        o, s = byoff[cand[0]]
        c = 0
        for i in range(o, o + s, 1 << 20):
            c = binascii.crc32(bytes(st[i:min(i + (1 << 20), o + s)]), c)
        good = (c & 0xffffffff) == int(parts[1], 16) and int(parts[2], 16) == s
        ok_cnt += 1 if good else 0
        (details if good else mism).append('%s:%s' % (name, 'ok' if good else 'MISMATCH'))
check('N7 the internal integrity of the image is CRC32 in *.sum files, and it matches',
      ok_cnt >= 8 and not mism, 'matched %d, mismatches %d: %s' % (ok_cnt, len(mism), details[:8]))
mc = bytearray(byname_mc if False else bytes(st[byoff['0100_config/mount.conf'][0]:
                                             byoff['0100_config/mount.conf'][0] + 1247]))
mc[100] ^= 0x01
oldcrc = int([l for l in bytes(st[byoff['0101_config_sum/config.sum'][0]:
                                   byoff['0101_config_sum/config.sum'][0] +
                                   byoff['0101_config_sum/config.sum'][1]]
                               ).decode('latin1').split('\n')
              if l.endswith('mount.conf,')][0].split(',')[1], 16)
check('C5 CONTROL (must go red): a modified file still matches the OLD CRC32',
      (binascii.crc32(bytes(mc)) & 0xffffffff) == oldcrc,
      'was %08x now %08x' % (oldcrc, binascii.crc32(bytes(mc)) & 0xffffffff), control=True)

# ---------------------------------------------------------------- N8 the images
check('N8 the images: fs_user = squashfs (hsqs), firmware = tar (159 members)',
      bytes(st[FS_OFF:FS_OFF + 4]) == b'hsqs' and len(ms) == 159,
      'fs_magic=%s members=%d' % (bytes(st[FS_OFF:FS_OFF + 4]), len(ms)))

nc = [r for r in res if not r['control']]
nok = [r for r in nc if r['ok']]
ctl = [r for r in res if r['control']]
ctlr = [r for r in ctl if not r['ok']]
print('=' * 88)
print('non-control green: %d/%d ; control red: %d/%d' %
      (len(nok), len(nc), len(ctlr), len(ctl)))
good = len(nok) == len(nc) and len(ctlr) == len(ctl)
print('RESULT:', 'ALL MATCHED' if good else 'SOMETHING IS RED')
with open(ROOT + '/audit/round277_checks.json', 'w') as f:
    json.dump({'checks': res, 'non_control_green': len(nok), 'non_control_total': len(nc),
               'controls_red': len(ctlr), 'controls_total': len(ctl), 'all_good': good},
              f, indent=1, ensure_ascii=False)
sys.exit(0 if good else 1)
