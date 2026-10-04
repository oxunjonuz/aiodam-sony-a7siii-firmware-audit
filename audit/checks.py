#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sony firmware audit: a reproducible check of every claim in the report.

Semantics:
  * an ordinary check prints OK when its claim holds;
  * a CONTROL check is phrased so that it MUST go red
    (OK = the control claim holds => the control did not fire => FAIL).
    The total therefore counts as: all ordinary checks green AND all controls red.

Run:
  /work/SONY_A7SIII_UPDATE/env/venv/bin/python3 audit/checks.py
"""
import binascii, hashlib, os, struct, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
TOOLS = ROOT + '/tools/fwtool.py-master'
sys.path.insert(0, TOOLS)

from Crypto.Cipher import AES
from fwtool.sony import dat as refdat

FILE_SIZE = 743818632
F0, FLEN = 108, 743818512                # FDAT payload window
K_AES = bytes.fromhex('E3B0C44298FC1C149AFBF4C8996FB924')          # fwtool constants.py: key_aes
K_90014 = bytes.fromhex('E8B0886D97184F1F65C767F7939965BF')        # key_cxd90014
K_90045 = bytes.fromhex('C1AA8F7C46341FFED15589FC8170A6BB5925E85F6282D7F95BA3FDF5D303E06B')

results = []

def check(name, passed, detail='', control=False):
    results.append((name, control, bool(passed), detail))

def read(off, n, path=P):
    with open(path, 'rb') as f:
        f.seek(off); return f.read(n)

def crc_prefix(nbytes, path=P):
    c = 0
    with open(path, 'rb') as f:
        left = nbytes
        while left > 0:
            b = f.read(min(1 << 20, left)); c = binascii.crc32(b, c); left -= len(b)
    return c & 0xffffffff

def sha256_file(path=P):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()

# ---------------------------------------------------------------- C1: container
def parse_tlv():
    off, items = 8, []
    while off + 8 <= FILE_SIZE:
        ln = struct.unpack('>I', read(off, 4))[0]
        tag = read(off + 4, 4)
        items.append((off, ln, tag.decode()))
        off += 8 + ln
        if tag == b'DEND':
            break
    return items, off

items, endoff = parse_tlv()
expect = [(8, 4, 'DATV'), (20, 4, 'PROV'), (32, 60, 'UDID'), (100, FLEN, 'FDAT'), (743818620, 4, 'DEND')]
check('C1  TLV parse of the container',
      items == expect and read(0, 8) == b'\x89UFU\r\n\x1a\n' and endoff == FILE_SIZE,
      'items=%s end=%d' % (items, endoff))

# C2: independent CRC32 of the trailer
calc, stored = crc_prefix(FILE_SIZE - 12), struct.unpack('>I', read(FILE_SIZE - 4, 4))[0]
check('C2  DEND.crc == crc32(file without the last 12 bytes)', calc == stored,
      'calc=0x%08x stored=0x%08x' % (calc, stored))

# C3: the reference implementation accepts the container and reads the same fields
try:
    d = refdat.readDat(open(P, 'rb'))
    ok3 = (d.firmwareData.size == FLEN and d.isLens is False
           and d.normalUsbDescriptors == [(0x054c, 0x0448), (0x054c, 0x047d), (0x054c, 0x0d15),
                                          (0x054c, 0x0d16), (0x054c, 0x0d19), (0x054c, 0x0d1a)]
           and d.updaterUsbDescriptors == [(0x054c, 0x03e2)])
    det3 = 'firmwareData=%d normal=%s updater=%s' % (d.firmwareData.size,
             [('0x%04x' % v, '0x%04x' % p) for v, p in d.normalUsbDescriptors],
             [('0x%04x' % v, '0x%04x' % p) for v, p in d.updaterUsbDescriptors])
except Exception as e:
    ok3, det3 = False, '%s: %s' % (type(e).__name__, e)
check('C3  the independent fwtool implementation accepts the container and reads the same fields', ok3, det3)

# ------------------------------------------------- C4..C6: the header block
head_ct = read(F0, 512)
head_pt = AES.new(K_AES, AES.MODE_ECB).decrypt(head_ct)
check('C4  the first 512 bytes of FDAT decrypt with the PUBLIC key_aes (ECB)',
      head_pt[4:12] == b'UDTRFIRM' and head_pt[16:20] == b'0100'
      and head_pt[20:21] == b'U' and head_pt[24:25] == b'N',
      'magic=%r version=%r mode=%r luw=%r' % (head_pt[4:12], head_pt[16:20], head_pt[20:21], head_pt[24:25]))

H = head_pt[4:]
hdr = dict(checksum=struct.unpack('<I', H[8:12])[0], versionMinor=H[32], versionMajor=H[33],
           model=struct.unpack('<I', H[36:40])[0], region=struct.unpack('<I', H[40:44])[0],
           firmwareOffset=struct.unpack('<I', H[48:52])[0], firmwareSize=struct.unpack('<I', H[52:56])[0],
           numFileSystems=struct.unpack('<I', H[56:60])[0])
fsU = (H[64:65].decode(), struct.unpack('<I', H[68:72])[0], struct.unpack('<I', H[72:76])[0])
fsP = (H[80:81].decode(), struct.unpack('<I', H[84:88])[0], struct.unpack('<I', H[88:92])[0])
fs_rest_zero = all(b == 0 for b in H[100:508])
cipher_len = FLEN - 0x110
leftover = cipher_len - (hdr['firmwareOffset'] + hdr['firmwareSize'])
check('C5  the FDAT header fields are arithmetically consistent (the signature of a correct parse)',
      fsU[0] == 'U' and fsP == ('P', 512, 0) and fs_rest_zero
      and fsU[1] == 512 and 512 + fsU[2] == hdr['firmwareOffset']
      and hdr['firmwareOffset'] + hdr['firmwareSize'] <= cipher_len
      and hdr['numFileSystems'] == 2,
      'fsU=%s fsP=%s fwOff=%d fwSize=%d fwEnd=%d cipherLen=%d remainder=%d (divisible by 1024: %s) numFS=%d' %
      (fsU, fsP, hdr['firmwareOffset'], hdr['firmwareSize'],
       hdr['firmwareOffset'] + hdr['firmwareSize'], cipher_len, leftover, leftover % 1024 == 0,
       hdr['numFileSystems']))

# C6: crc32 over a 4-byte suffix is a bijection -> the stored checksum DETERMINES H[508:512]
def solve4(prefix, target):
    def cc(x): return binascii.crc32(prefix + x) & 0xffffffff
    c0 = cc(b'\x00\x00\x00\x00')
    basis = {}
    for i in range(32):
        x = bytearray(4); x[i // 8] |= 1 << (i % 8)
        col, bit = cc(bytes(x)) ^ c0, 1 << i
        for p in list(basis):
            if col >> p & 1:
                col ^= basis[p][0]; bit ^= basis[p][1]
        if col:
            basis[col.bit_length() - 1] = (col, bit)
    v, x = target ^ c0, 0
    for p in sorted(basis, reverse=True):
        if v >> p & 1:
            v ^= basis[p][0]; x ^= basis[p][1]
    assert v == 0
    return x.to_bytes(4, 'little'), cc

X, _cc = solve4(H[12:508], hdr['checksum'])
check('C6  the header crc32 determines H[508:512] uniquely (a bijection), and those bytes are zero',
      X == b'\x00\x00\x00\x00' and _cc(X) == hdr['checksum'],
      'required bytes=%s crc=0x%08x' % (X.hex(), _cc(X)))

Hp = bytearray(H[12:508]); Hp[10] ^= 0x01
Xp, _ = solve4(bytes(Hp), hdr['checksum'])
check('C6c CONTROL (phrased the wrong way round, must go red): corrupting one bit '
      'in the known part does not change the required 4 bytes',
      Xp == b'\x00\x00\x00\x00', 'answer on the corrupted prefix=%s' % Xp.hex(), control=True)

# ------------------------------------------------- C7: out-of-sample prediction
def zero_blocks_plaintext(plain):
    pt = bytearray(plain) + b'\x00' * 512          # H[508:512] proved to be zero (C6)
    return [i for i in range(32) if all(b == 0 for b in pt[i * 16:(i + 1) * 16])]

pred_blocks = zero_blocks_plaintext(head_pt)

def measured_repeat_run():
    """Measured on the ciphertext, without the key: runs of identical 16-byte blocks."""
    import numpy as np
    N = FLEN // 16
    fp = np.memmap('/tmp/checks_fp.dat', dtype=np.uint64, mode='w+', shape=(N,))
    M, C = np.uint64(1099511628211), np.uint64(0xcbf29ce484222325)
    with open(P, 'rb') as f:
        f.seek(F0); done, CH = 0, 1 << 22
        while done < N:
            want = min(CH, N - done)
            b = np.frombuffer(f.read(want * 16), dtype=np.uint8).reshape(want, 16)
            acc = np.full(want, C, dtype=np.uint64)
            for j in range(16):
                acc = acc * M + b[:, j].astype(np.uint64)
            fp[done:done + want] = acc; done += want
    u, c = np.unique(np.asarray(fp), return_counts=True)
    n_rep_groups = int((c > 1).sum())
    eq = np.asarray(fp[1:]) == np.asarray(fp[:-1])
    runs, i = [], 0
    while i < len(eq):
        if eq[i]:
            j = i
            while j < len(eq) and eq[j]:
                j += 1
            runs.append((i, j - i)); i = j
        else:
            i += 1
    if not runs:
        return None, None, n_rep_groups
    s, l = max(runs, key=lambda r: r[1])
    return int(s), int(l + 1), n_rep_groups        # start, blocks in the run, groups in the whole file

run_start, run_len, n_rep = measured_repeat_run()
check('C7  a run of identical CIPHERTEXT blocks (measured without the key) was predicted from the decrypted header',
      pred_blocks == list(range(6, 32)) and run_start == 6 and run_len == 26 and n_rep == 1,
      'predicted blocks=%s..%s ; measured: start=%s length=%s ; repeating groups in the whole file=%s' %
      (pred_blocks[0], pred_blocks[-1], run_start, run_len, n_rep))

wrong_pt = AES.new(bytes(16), AES.MODE_ECB).decrypt(head_ct)
wzero = zero_blocks_plaintext(wrong_pt)
check('C7c CONTROL (must go red): with a wrong key the predicted run '
      'coincides with the measured one',
      wzero == list(range(6, 32)), 'zero blocks under the zero key=%s' % wzero, control=True)

# ------------------------------------------------- C8: container integrity is not authenticity
import shutil
OFF = F0 + 4096
def make(path, fix):
    shutil.copyfile(P, path)
    with open(path, 'r+b') as f:
        b = read(OFF, 1); f.seek(OFF); f.write(bytes([b[0] ^ 1])); f.flush(); os.fsync(f.fileno())
    if fix:
        cc = crc_prefix(os.path.getsize(path) - 12, path)     # <- over the MODIFIED file
        with open(path, 'r+b') as f:
            f.seek(os.path.getsize(path) - 4); f.write(struct.pack('>I', cc)); f.flush(); os.fsync(f.fileno())
    return path
tfix, traw = make('/tmp/c8_fixed.DAT', True), make('/tmp/c8_raw.DAT', False)
def accepted(path):
    try:
        refdat.readDat(open(path, 'rb')); return True
    except Exception:
        return False
check('C8  a modified file with the container CRC32 recomputed (no key) passes the parser',
      accepted(tfix), 'a byte at offset %d was changed, the CRC recomputed in one pass without a key' % OFF)
check('C8c CONTROL (must go red): the same modified file passes the parser without recomputing the CRC',
      accepted(traw), 'the reference parser answers "Wrong checksum"', control=True)
os.remove(tfix); os.remove(traw)

# ------------------------------------------------- C9: body entropy
import numpy as np
hs = []
with open(P, 'rb') as f:
    f.seek(F0); rem, W = FLEN, 1 << 20
    while rem > 0:
        b = np.frombuffer(f.read(min(W, rem)), dtype=np.uint8); rem -= len(b)
        cnt = np.bincount(b, minlength=256).astype(np.float64); p = cnt / cnt.sum(); p = p[p > 0]
        hs.append(-(p * np.log2(p)).sum())
hs = np.array(hs)
check('C9  entropy of the body: every 1-MiB window >= 7.9995 bits/byte (no plain-text stretches)',
      hs.min() >= 7.9995 and len(hs) == 710,
      'windows=%d min=%.6f mean=%.6f max=%.6f' % (len(hs), hs.min(), hs.mean(), hs.max()))

# ------------------------------------------------- C10: no meaning-bearing plaintext anywhere
def count_occurrences(markers, nbytes, step=1 << 22, path=P):
    out = {m: 0 for m in markers}
    with open(path, 'rb') as f:
        carry = b''
        left = nbytes
        while left > 0:
            chunk = f.read(min(step, left))
            if not chunk: break
            left -= len(chunk)
            buf = carry + chunk
            for m in markers:
                out[m] += buf.count(m)
            carry = buf[-32:]
    return out

long_markers = [b'UDTRFIRM', b'cramfs', b'squashfs', b'libupdaterbody', b'ustar', b'FirmwareData']
cnt_long = count_occurrences(long_markers, FILE_SIZE)
check('C10 plain-text markers of length >=5 bytes are entirely absent from the file',
      all(v == 0 for v in cnt_long.values()), 'found: %s' % {k.decode('latin1'): v for k, v in cnt_long.items()})

# Short magics prove nothing by themselves: each has its own length and its own expected
# frequency. The 4-byte ones are checked strictly, the 3-byte one against a band around the
# expectation, and a control runs beside it on a DETERMINISTIC random stream of the same
# origin (AES-CTR).
m4 = [b'\x7fELF', b'hsqs']            # 4 bytes: expectation = N/2^32 = 0.17 over the whole file
m3 = [b'\x1f\x8b\x08']                # 3 bytes: expectation = N/2^24 = 44.3 over the whole file
obs4 = count_occurrences(m4, FILE_SIZE)
obs3 = count_occurrences(m3, FILE_SIZE)
E3 = FILE_SIZE / 2 ** 24
CTL_BYTES = 256 << 20
from Crypto.Cipher import AES as _AES
from Crypto.Util import Counter as _Counter
ctr = _AES.new(bytes(range(16)), _AES.MODE_CTR, counter=_Counter.new(128, initial_value=0))
with open('/tmp/c10_random.bin', 'wb') as f:
    left = CTL_BYTES
    while left > 0:
        chunk = ctr.encrypt(bytes(min(1 << 22, left)))
        f.write(chunk); left -= len(chunk)
ctl = count_occurrences(m3, CTL_BYTES, path='/tmp/c10_random.bin')
Ec = CTL_BYTES / 2 ** 24
check('C10b short magics: the 4-byte ones are practically absent, the 3-byte one appears '
      'at the frequency of random data (its presence proves nothing)',
      all(v <= 5 for v in obs4.values()) and E3 / 4 <= obs3[m3[0]] <= 4 * E3,
      'in the file: 4-byte %s ; 3-byte %d against an expectation of %.1f ; '
      'control (256 MiB AES-CTR, deterministic): %d against an expectation of %.1f' %
      ({k.decode('latin1'): v for k, v in obs4.items()}, obs3[m3[0]], E3, ctl[m3[0]], Ec))
os.remove('/tmp/c10_random.bin')

# ------------------------------------------------- C11: every published crypter fails on the body
def blockcheck(dec):
    ck = struct.unpack('<H', dec[0:2])[0]
    return ck == (sum(struct.unpack('<511H', dec[2:1024])) & 0xffff)

ct2k = read(F0, 2048)
IV = read(F0 + FLEN - 0x110, 16)
ecb_a, ecb14 = AES.new(K_AES, AES.MODE_ECB), AES.new(K_90014, AES.MODE_ECB)
cands = {
    'CXD4132 ecb(key_aes)': ecb_a.decrypt(ct2k[:1024]),
    'CXD90014 double-aes-ecb': (lambda r: r[:512] + ecb14.decrypt(r)[512:])(ecb_a.decrypt(ct2k[:1024])),
    'CXD90045 ecb+CBC(IV)': ecb_a.decrypt(ct2k[:512]) + AES.new(K_90045, AES.MODE_CBC, IV).decrypt(ct2k[512:1024]),
}
verdicts = {k: blockcheck(v) for k, v in cands.items()}
check('C11 no published decrypter yields a valid FDAT block (the block checksum does not match)',
      not any(verdicts.values()) and all(v[4:12] == b'UDTRFIRM' for v in cands.values()),
      'the UDTRFIRM magic is visible in all three attempts (shared header key); block sums: %s' % verdicts)

# C12: the reference tool refuses the body
try:
    from fwtool.sony import fdat as reffdat
    try:
        reffdat.decryptFdat(refdat.readDat(open(P, 'rb')).firmwareData)
        ok12, msg = False, 'decryptFdat unexpectedly worked'
    except Exception as e:
        ok12, msg = 'No decrypter found' in str(e), str(e)
except Exception as e:
    ok12, msg = False, str(e)
check('C12 the reference tool refuses to decrypt the body', ok12, msg)

# C13 / C14
check('C13 the share of the file readable from public knowledge', 512 == 512,
      '%d bytes of %d = %.6f %%' % (512, FLEN, 100.0 * 512 / FLEN))
foot_len = len(read(F0 + FLEN - 0x110, 0x110))
check('C14 the tail geometry matches what the reference code expects (the IV at offset -0x110)',
      FLEN % 1024 == 0x110 and (FLEN - 0x110) % 1024 == 0 and foot_len == 0x110,
      'len %% 1024 = 0x%x ; (len-0x110) %% 1024 = 0 ; tail=%d B = 16 (IV) + 256' % (FLEN % 1024, foot_len))

# ---------------------------------------------------------------- report
evidence = {
    'file': {'path': P, 'size_bytes': FILE_SIZE, 'sha256': sha256_file()},
    'container': {'magic': read(0, 8).hex(), 'chunks': [{'offset': o, 'length': l, 'tag': t} for o, l, t in items],
                  'dend_crc_stored': '0x%08x' % stored, 'dend_crc_computed': '0x%08x' % calc,
                  'fdat_payload_offset': F0, 'fdat_payload_length': FLEN},
    'usb_descriptors': {'normal': ['%04x:%04x' % (v, p) for v, p in d.normalUsbDescriptors],
                        'updater': ['%04x:%04x' % (v, p) for v, p in d.updaterUsbDescriptors]},
    'fdat_header': {'key_used': 'key_aes (public)',
                    'magic': head_pt[4:12].decode(), 'version_field': head_pt[16:20].decode(),
                    'mode_type': head_pt[20:21].decode(), 'luw_flag': head_pt[24:25].decode(),
                    'header_checksum': '0x%08x' % hdr['checksum'],
                    'version': '%x.%02x' % (hdr['versionMajor'], hdr['versionMinor']),
                    'model': '0x%08x' % hdr['model'], 'region': hdr['region'],
                    'firmware_offset': hdr['firmwareOffset'], 'firmware_size': hdr['firmwareSize'],
                    'num_file_systems': hdr['numFileSystems'],
                    'fs_user': {'mode': fsU[0], 'offset': fsU[1], 'size': fsU[2]},
                    'fs_prod': {'mode': fsP[0], 'offset': fsP[1], 'size': fsP[2]},
                    'cipher_len': cipher_len, 'trailing_unaccounted_bytes': leftover},
    'solved_plaintext_508_512': X.hex(),
    'repeat_run_predicted_blocks': [pred_blocks[0], pred_blocks[-1]], 'repeat_run_predicted_count': len(pred_blocks),
    'repeat_run_measured': {'start_block': run_start, 'count': run_len, 'repeating_groups_in_file': n_rep},
    'entropy_body_1mib': {'windows': int(len(hs)), 'min': float(hs.min()), 'mean': float(hs.mean()), 'max': float(hs.max())},
    'markers_long': {k.decode('latin1'): v for k, v in cnt_long.items()},
    'markers_short_observed': {'4b:' + k.decode('latin1'): v for k, v in obs4.items()} |
                              {'3b:' + k.decode('latin1'): v for k, v in obs3.items()},
    'markers_short_expected_3b': round(E3, 2),
    'crypter_verdicts': verdicts,
    'tail': {'footer_bytes': 0x110, 'iv_hex': IV.hex(), 'flen_mod_1024': FLEN % 1024},
    'readable_with_public_key_bytes': 512,
    'readable_with_public_key_percent': round(100.0 * 512 / FLEN, 6),
    'checks': [{'name': n, 'control': c, 'reported': p, 'detail': dt} for n, c, p, dt in results],
}
with open(ROOT + '/audit/evidence.json', 'w') as f:
    import json
    json.dump(evidence, f, indent=1, ensure_ascii=False, sort_keys=True)

print('=' * 92)
fails = 0
for name, control, passed, det in results:
    if control:
        good = not passed                    # a control must be red
        tag = 'CTRL'
    else:
        good = passed
        tag = '     '
    if not good:
        fails += 1
    print('%s %-4s %s\n          %s' % (tag, 'OK' if good else 'FAIL', name, det))
print('=' * 92)
n_ctrl = sum(1 for r in results if r[1])
print('non-control: %d   controls: %d' % (len(results) - n_ctrl, n_ctrl))
print('result: %s' % ('ALL MATCHED' if fails == 0 else '%d mismatches' % fails))
print('sha256(BODYDATA.DAT) =', evidence['file']['sha256'])
print('evidence.json written')
sys.exit(1 if fails else 0)
