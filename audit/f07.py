#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F-07: the 2 906 112 "unexplained" bytes at the end of the FDAT image.

Every measurement is without the body key, without the camera, without new files.
Result: audit/f07.json + the printout below.

What is measured (following the owner's list):
  G1 geometry: where the region is, what sits in the 28 FS-header slots, alignments
  B  boundaries: the first 64 bytes of the region, the 64 before it, the IV and 256 after it, magics
  E  entropy over 4 KiB / 1 KiB / 256 B inside the region + a comparison with the body
  C  statistics against the body: chi-square, entropy distribution (KS), compressibility
  D  duplicate blocks of 16/32/64/1024 B (ECB leakage) — inside and against the body
  S  strings: ASCII >=5, >=8, UTF-16LE >=4
  F  the BlockCrypter frame (a 16-bit sum in every 1024-B block) under three
     published keys + a CONTROL on a synthetically assembled frame
  H  a search in the file for region digests and published keys
  M  factoring 2 906 112 and checking it against meaningful sizes
"""
import binascii, hashlib, io, json, struct, sys, zlib
import numpy as np

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
OUT = ROOT + '/audit/f07.json'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')

from Crypto.Cipher import AES
import fwtool.sony.constants as KC
from fwtool.sony.fdat import FdatHeader, FdatFileSystemHeader, maxNumFileSystems

F0, FLEN, FILE_SIZE = 108, 743818512, 743818632      # the container (measured in C1)
TAIL = 0x110                                          # IV(16) + 256 at the end of FDAT
K_AES, K_90014, K_90045 = KC.key_aes, KC.key_cxd90014, KC.key_cxd90045

E = {}


def rd(off, n):
    with open(P, 'rb') as f:
        f.seek(off)
        return f.read(n)


# ------------------------------------------------------------------ tools
def shannon(b):
    a = np.frombuffer(b, dtype=np.uint8)
    if a.size == 0:
        return 0.0
    c = np.bincount(a, minlength=256).astype(np.float64)
    p = c[c > 0] / a.size
    return float(-(p * np.log2(p)).sum())


def chi2_bytes(b):
    a = np.frombuffer(b, dtype=np.uint8)
    c = np.bincount(a, minlength=256).astype(np.float64)
    exp = a.size / 256.0
    return float(((c - exp) ** 2 / exp).sum())


def runs(b):
    a = np.frombuffer(b, dtype=np.uint8)
    return 0 if a.size < 2 else int(1 + (a[1:] != a[:-1]).sum())


def ascii_runs(b, minlen=5):
    out, cur = [], bytearray()
    for x in b:
        if 32 <= x < 127:
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(bytes(cur))
    return out


def utf16_runs(b, minlen=4):
    out, cur = [], []
    i = 0
    while i + 1 < len(b):
        lo, hi = b[i], b[i + 1]
        if hi == 0 and 32 <= lo < 127:
            cur.append(chr(lo))
            i += 2
            continue
        if len(cur) >= minlen:
            out.append(''.join(cur))
        cur = []
        i += 2
    if len(cur) >= minlen:
        out.append(''.join(cur))
    return out


def dupblocks(b, bs):
    n = len(b) // bs
    seen, dups = {}, 0
    for i in range(n):
        k = b[i * bs:(i + 1) * bs]
        if k in seen:
            dups += 1
        else:
            seen[k] = i
    return {'blocks': n, 'duplicates': dups}


def ent_windows(b, w):
    n = len(b) // w
    arr = np.frombuffer(b[:n * w], dtype=np.uint8).reshape(n, w)
    out = np.empty(n, dtype=np.float64)
    for i, row in enumerate(arr):
        c = np.bincount(row, minlength=256).astype(np.float64)
        p = c[c > 0] / w
        out[i] = -(p * np.log2(p)).sum()
    return out


def ks2(a, b):
    a = np.sort(np.asarray(a, dtype=np.float64))
    b = np.sort(np.asarray(b, dtype=np.float64))
    alld = np.concatenate([a, b])
    ca = np.searchsorted(a, alld, side='right') / a.size
    cb = np.searchsorted(b, alld, side='right') / b.size
    return float(np.max(np.abs(ca - cb)))


def deflate_ratio(b):
    return len(zlib.compress(bytes(b), 6)) / len(b)


def random_control(n, seed=b'F-07 control stream'):
    key = hashlib.sha256(seed).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += cipher.encrypt(ctr.to_bytes(16, 'little'))
        ctr += 1
    return bytes(out[:n])


def chi2_1024(buf):
    n = len(buf) // 1024
    a = np.frombuffer(buf[:n * 1024], dtype=np.uint8).reshape(n, 1024)
    vals = np.empty(n)
    for i, row in enumerate(a):
        c = np.bincount(row, minlength=256).astype(np.float64)
        vals[i] = ((c - 4.0) ** 2 / 4.0).sum()
    return vals


# ------------------------------------------------------------------ G1 geometry
def header_geometry():
    # the 4-byte block frame (checksum16, size|endflag) sits BEFORE the stream:
    # 'UDTRFIRM' was found at offset 4, not 0 (see frame_probe.py, P1/P2)
    hdr_pt = AES.new(K_AES, AES.MODE_ECB).decrypt(rd(F0, 1024))
    h = FdatHeader.unpack(io.BytesIO(hdr_pt[4:]))
    slots = []
    for i in range(maxNumFileSystems):
        fs = FdatFileSystemHeader.unpack(h.fileSystemHeaders, i * FdatFileSystemHeader.size)
        slots.append({'i': i, 'mode': fs.modeType.decode('latin1'), 'offset': fs.offset,
                      'size': fs.size})
    cipher_len = FLEN - TAIL
    fw_end = h.firmwareOffset + h.firmwareSize
    n = cipher_len - fw_end
    return {
        'magic': h.magic.decode('latin1'), 'checksum_stored': hex(h.checksum),
        'model': hex(h.model), 'version': '%x.%02x' % (h.versionMajor, h.versionMinor),
        'num_file_systems': h.numFileSystems,
        'firmware_offset': h.firmwareOffset, 'firmware_size': h.firmwareSize,
        'firmware_end': fw_end, 'cipher_len': cipher_len,
        'f07_start_payload': fw_end, 'f07_size': n,
        'f07_start_file': F0 + fw_end, 'f07_end_file': F0 + cipher_len,
        'tail_start_file': F0 + cipher_len, 'iv_file': F0 + FLEN - TAIL,
        'last256_file': F0 + FLEN - 256,
        'fs_slots_nonzero': [s for s in slots if s['size'] != 0 or s['mode'] != '\x00'],
        'fs_slots_all': slots,
        'f07_start_offset_payload_512': fw_end % 512,
        'f07_size_mod': {str(m): n % m for m in (512, 1024, 2048, 4096, 8192, 16384, 65536, 131072)},
        'fwsize_mod_1024': h.firmwareSize % 1024,
        'fwsize_mod_512': h.firmwareSize % 512,
        'cipherlen_mod_1024': cipher_len % 1024,
        'f07_size_eq_2838_kib': n == 2838 * 1024,
    }


GEO = header_geometry()
F7_N, F7_A, F7_B = GEO['f07_size'], GEO['f07_start_file'], GEO['f07_end_file']
IV0, T0 = GEO['iv_file'], GEO['tail_start_file']
assert F7_N == 2906112 and F7_B - F7_A == F7_N
f07 = rd(F7_A, F7_N)
GEO['f07_first_bytes_hex'] = f07[:64].hex()
GEO['before_f07_hex'] = rd(F7_A - 64, 64).hex()
GEO['last_64_before_tail_hex'] = rd(T0 - 64, 64).hex()
GEO['iv_hex'] = rd(IV0, 16).hex()
GEO['after_iv_hex'] = rd(IV0 + 16, 64).hex()
GEO['last_64_after_iv_hex'] = rd(F7_B - 64, 64).hex()
_ev = json.load(open(ROOT + '/audit/evidence.json'))
GEO['iv_matches_evidence_json'] = (GEO['iv_hex'] == _ev['tail']['iv_hex'])
assert GEO['iv_matches_evidence_json'], 'IV offset disagrees with evidence.json'
E['G1_geometry'] = GEO

body_windows = []
for name, off in (('fw_head', F0 + GEO['firmware_offset']),
                  ('fw_mid', F0 + GEO['firmware_offset'] + GEO['firmware_size'] // 2),
                  ('fw_tail', F0 + GEO['firmware_end'] - F7_N)):
    body_windows.append((name, off, rd(off, F7_N)))

CTRL = random_control(F7_N)
STRUCT = b'\x00' * F7_N

# ------------------------------------------------------------------ B boundaries
magics = [b'UDTRFIRM', b'FirmwareData', b'cramfs', b'hsqs', b'\x7fELF', b'ustar',
          b'libupdaterbody', b'ANDROID!', b'\x1f\x8b\x08', b'PK\x03\x04', b'UBIFS',
          b'BZh9', b'\x28\xb5\x2f\xfd', b'rootfs', b'jffs2', b'\x00\x00\x00\x00']
E['B_boundary'] = {
    'magics_found_in_first_512': [m.hex() for m in magics if m in f07[:512]],
    'magics_found_anywhere_in_region': [m.hex() for m in magics if m in f07],
    'zero_bytes_in_first_64': sum(1 for x in f07[:64] if x == 0),
    'zero_bytes_in_first_512': sum(1 for x in f07[:512] if x == 0),
    'zero_bytes_in_whole_region': int((np.frombuffer(f07, dtype=np.uint8) == 0).sum()),
    'public_constants_inside_f07': {
        'key_aes': K_AES in f07, 'key_cxd90014': K_90014 in f07,
        'key_cxd90045': K_90045 in f07, 'iv_from_tail': rd(IV0, 16) in f07,
    },
}


# ------------------------------------------------------------------ E entropy
def ent_report(name, buf):
    w4, w1, w2 = ent_windows(buf, 4096), ent_windows(buf, 1024), ent_windows(buf, 256)
    order = np.argsort(w4)[:10]
    return {
        'name': name, 'bytes': len(buf), 'entropy_whole': shannon(buf),
        'w4096': {'n': int(w4.size), 'min': float(w4.min()), 'mean': float(w4.mean()),
                  'max': float(w4.max()), 'below_7.99': int((w4 < 7.99).sum()),
                  'below_7.5': int((w4 < 7.5).sum()), 'below_7.0': int((w4 < 7.0).sum()),
                  'ten_lowest': [[int(o) * 4096, float(w4[o])] for o in order]},
        'w1024': {'n': int(w1.size), 'min': float(w1.min()), 'mean': float(w1.mean()),
                  'max': float(w1.max()), 'below_7.5': int((w1 < 7.5).sum()),
                  'below_6.0': int((w1 < 6.0).sum())},
        'w256': {'n': int(w2.size), 'min': float(w2.min()), 'mean': float(w2.mean()),
                 'max': float(w2.max()), 'below_6.0': int((w2 < 6.0).sum())},
        'chi2_bytes': chi2_bytes(buf), 'runs': runs(buf),
        'runs_expected_random': len(buf) * (1 - 1.0 / 256),
        'deflate_ratio': deflate_ratio(buf),
    }


E['E_entropy'] = {'f07': ent_report('f07', f07),
                  'control_random': ent_report('control_random', CTRL),
                  'control_zeros': ent_report('control_zeros', STRUCT)}
for name, off, buf in body_windows:
    E['E_entropy']['body_' + name] = ent_report('body_' + name, buf)
_chi_src = {'f07': f07, 'control_random': CTRL}
_chi_src.update({'body_' + name: buf for name, off, buf in body_windows})
for key in ('f07', 'control_random', 'body_fw_head', 'body_fw_mid', 'body_fw_tail'):
    c = chi2_1024(_chi_src[key])
    E['E_entropy'][key]['chi2_per_1024'] = {
        'n': int(c.size), 'min': float(c.min()), 'mean': float(c.mean()),
        'max': float(c.max()), 'below_200': int((c < 200).sum()),
        'above_320': int((c > 320).sum())}

# ------------------------------------------------------------------ C against the body
ent_f07 = ent_windows(f07, 1024)
E['C_vs_body'] = {}
for name, off, buf in body_windows + [('control_random', -1, CTRL)]:
    eb = ent_windows(buf, 1024)
    E['C_vs_body'][name] = {
        'ks_vs_f07': ks2(ent_f07, eb), 'mean_entropy': float(eb.mean()),
        'min_entropy': float(eb.min()), 'chi2_bytes_total': chi2_bytes(buf),
        'deflate_ratio': deflate_ratio(buf),
        'ascii_runs_5': len(ascii_runs(buf, 5)), 'ascii_runs_8': len(ascii_runs(buf, 8))}
E['C_vs_body']['f07_reference'] = {
    'mean_entropy': float(ent_f07.mean()), 'min_entropy': float(ent_f07.min()),
    'max_entropy': float(ent_f07.max()), 'n_windows_1024': int(ent_f07.size),
    'chi2_bytes_total': chi2_bytes(f07), 'deflate_ratio': deflate_ratio(f07),
    'ascii_runs_5': len(ascii_runs(f07, 5)), 'ascii_runs_8': len(ascii_runs(f07, 8))}

# ------------------------------------------------------------------ D duplicates
dup = {}
for bs in (16, 32, 64, 1024):
    dup['f07_%d' % bs] = dupblocks(f07, bs)
    dup['control_random_%d' % bs] = dupblocks(CTRL, bs)
    dup['body_fw_head_%d' % bs] = dupblocks(body_windows[0][2], bs)
set_f07 = {f07[i:i + 16] for i in range(0, F7_N - 15, 16)}
set_body = {body_windows[0][2][i:i + 16] for i in range(0, F7_N - 15, 16)}
dup['shared_16B_blocks_f07_vs_body_head'] = len(set_f07 & set_body)
E['D_duplicates'] = dup

# ------------------------------------------------------------------ S strings
E['S_strings'] = {
    'f07_ascii5_count': len(ascii_runs(f07, 5)),
    'f07_ascii5_sample': [s.decode('latin1') for s in ascii_runs(f07, 5)][:40],
    'f07_ascii8_count': len(ascii_runs(f07, 8)),
    'f07_utf16_count': len(utf16_runs(f07, 4)),
    'f07_utf16_sample': utf16_runs(f07, 4)[:20],
    'control_random_ascii5_count': len(ascii_runs(CTRL, 5)),
    'control_text_ascii5_count': len(ascii_runs(('Sony update payload ' * 100000).encode(), 5)),
    'body_fw_head_ascii5_count': len(ascii_runs(body_windows[0][2], 5)),
}

# ------------------------------------------------------------------ F the frame
def framing_test(buf, name):
    n = len(buf) // 1024
    ok = 0
    for i in range(n):
        blk = buf[i * 1024:(i + 1) * 1024]
        csum = int.from_bytes(blk[0:2], 'little')
        s = sum(int.from_bytes(blk[j:j + 2], 'little') for j in range(2, 1024, 2)) & 0xffff
        if csum == s:
            ok += 1
    return {'name': name, 'blocks': n, 'checksum_ok': ok,
            'rate': ok / n if n else 0.0, 'expected_random': 1.0 / 65536.0,
            'expected_random_blocks': n / 65536.0}


def pack_block(payload, end=False):
    sized = len(payload) | (0x8000 if end else 0)
    data = sized.to_bytes(2, 'little') + payload + b'\xff' * (1024 - 4 - len(payload))
    s = sum(int.from_bytes(data[j:j + 2], 'little') for j in range(0, len(data), 2)) & 0xffff
    return s.to_bytes(2, 'little') + data


def dec_ecb(buf, keys):
    out = buf[:len(buf) // 16 * 16]
    for k in keys:
        out = AES.new(k, AES.MODE_ECB).decrypt(out)
    return out


f7_16 = f07[:len(f07) // 16 * 16]
f7_1024 = f07[:len(f07) // 1024 * 1024]
prev = rd(F7_A - 16, 16)                     # the previous ciphertext block = the CBC IV of this window
f7_cbc = AES.new(K_90045, AES.MODE_CBC, prev).decrypt(f7_16)
bh = body_windows[0][2]
bh16 = bh[:len(bh) // 16 * 16]
fh = body_windows[0][2]
synth = b''.join(pack_block(b'P' * 996, end=(i == 2827)) for i in range(2838))
synth_broken = bytearray(synth)
synth_broken[100 * 1024 + 700] ^= 0x01
E['F_framing'] = {
    'f07_raw_ciphertext': framing_test(f7_1024, 'f07_raw'),
    'f07_aes_ecb_key_aes': framing_test(dec_ecb(f7_16, [K_AES]), 'f07_k1'),
    'f07_double_aes_keyaes_x90014': framing_test(dec_ecb(f7_16, [K_AES, K_90014]), 'f07_k2'),
    'f07_cbc_key_cxd90045_chained': framing_test(f7_cbc, 'f07_cbc'),
    'body_raw_ciphertext': framing_test(fh[:len(fh) // 1024 * 1024], 'body_raw'),
    'body_double_aes': framing_test(dec_ecb(bh16, [K_AES, K_90014]), 'body_k2'),
    'CONTROL_synthetic_framed': framing_test(synth, 'synth'),
    'CONTROL_synthetic_framed_one_flip': framing_test(bytes(synth_broken), 'synth1'),
    'control_zeros': framing_test(STRUCT, 'zeros'),
    'control_random': framing_test(CTRL, 'random'),
}
E['F_after_decrypt'] = {
    'entropy_raw': shannon(f7_16), 'entropy_key_aes': shannon(dec_ecb(f7_16, [K_AES])),
    'entropy_double_aes': shannon(dec_ecb(f7_16, [K_AES, K_90014])),
    'entropy_cbc_90045': shannon(f7_cbc),
    'ascii5_raw': len(ascii_runs(f7_16, 5)),
    'ascii5_key_aes': len(ascii_runs(dec_ecb(f7_16, [K_AES]), 5)),
    'ascii5_double_aes': len(ascii_runs(dec_ecb(f7_16, [K_AES, K_90014]), 5)),
    'ascii5_cbc_90045': len(ascii_runs(f7_cbc, 5)),
}

# ------------------------------------------------------------------ H search in the file
def digest(off, n):
    hs = {k: hashlib.new(k) for k in ('md5', 'sha1', 'sha256', 'sha512')}
    hs['blake2b'] = hashlib.blake2b(digest_size=32)
    crc = 0
    with open(P, 'rb') as f:
        f.seek(off)
        left = n
        while left > 0:
            b = f.read(min(1 << 20, left))
            for h in hs.values():
                h.update(b)
            crc = binascii.crc32(b, crc)
            left -= len(b)
    out = {k: v.digest() for k, v in hs.items()}
    out['crc32'] = struct.pack('<I', crc & 0xffffffff)
    return out


regions = {
    'whole_fdat_payload': (F0, FLEN), 'payload_minus_tail': (F0, FLEN - TAIL),
    'header_512': (F0, 512), 'fs_user': (F0 + 512, 1253376),
    'firmware': (F0 + GEO['firmware_offset'], GEO['firmware_size']),
    'f07_region': (F7_A, F7_N), 'tail_272': (T0, 272), 'last_256': (IV0 + 16, 256),
    'first_1024': (F0, 1024),
}
pats = {}
for rname, (off, n) in regions.items():
    for algo, d in digest(off, n).items():
        pats['%s/%s' % (rname, algo)] = d
pats['const/key_aes'] = K_AES
pats['const/key_cxd90014'] = K_90014
pats['const/key_cxd90045'] = K_90045
pats['const/iv_from_tail'] = rd(IV0, 16)

hits = {k: [] for k in pats}
with open(P, 'rb') as f:
    ov = max(len(v) for v in pats.values()) - 1
    pos, carry = 0, b''
    while True:
        chunk = f.read(1 << 22)
        if not chunk:
            break
        buf = carry + chunk
        base = pos - len(carry)
        for k, v in pats.items():
            start = 0
            while True:
                i = buf.find(v, start)
                if i < 0:
                    break
                hits[k].append(base + i)
                start = i + 1
        carry = buf[-ov:]
        pos += len(chunk)
E['H_hash_search'] = {
    'patterns': sorted(pats.keys()),
    'hits_by_pattern': {k: v for k, v in hits.items() if v},
    'patterns_with_zero_hits': sum(1 for v in hits.values() if not v),
    'n_patterns': len(pats),
}
planted = pats['header_512/sha256']
blob = bytearray(f07)
blob[1000:1032] = planted
E['H_hash_search']['CONTROL_planted'] = {
    'pattern': 'header_512/sha256', 'found_at': bytes(blob).find(planted), 'expected_at': 1000,
    'searched_where': 'copy of the f07 region only'}

# ------------------------------------------------------------------ M factorization
def factorize(n):
    f, d = {}, 2
    while d * d <= n:
        while n % d == 0:
            f[d] = f.get(d, 0) + 1
            n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        f[n] = f.get(n, 0) + 1
    return f


fac = factorize(F7_N)
divs = []
d = 1
while d * d <= F7_N:
    if F7_N % d == 0:
        divs += [d, F7_N // d]
        d += 1
    else:
        d += 1
divs = sorted(set(divs))
E['M_factorization'] = {
    'n': F7_N, 'factorization': {str(k): v for k, v in sorted(fac.items())},
    'as_kib': F7_N // 1024, 'kib_factorization': dict(factorize(F7_N // 1024)),
    'divisors_not_multiple_of_1024': [d for d in divs if d % 1024 != 0][:40],
    'kib_divisors': [d // 1024 for d in divs if d % 1024 == 0],
    'nice_sizes': {
        'F07/1024': F7_N / 1024, 'F07/2048': F7_N / 2048, 'F07/4096': F7_N / 4096,
        'F07/512': F7_N / 512, 'F07/16': F7_N / 16, 'F07/256': F7_N / 256,
        'firmware/N': GEO['firmware_size'] / F7_N, 'cipherlen/N': GEO['cipher_len'] / F7_N,
        'N/fsuser': F7_N / 1253376, 'N/header512': F7_N / 512,
        'N/473': F7_N / 473, 'N/1419': F7_N / 1419, 'N/2838': F7_N / 2838,
        'N/256_rsa': F7_N / 256, 'fwsize/2048': GEO['firmware_size'] / 2048,
        'cipherlen/2048': GEO['cipher_len'] / 2048,
        'cipherlen/2838': GEO['cipher_len'] / 2838,
    },
    'framing_decomposition': {
        'stream_end_from_header': GEO['firmware_end'],
        'blocks_if_framed_1020': -(-GEO['firmware_end'] // 1020),
        'predicted_cipher_len': 1024 * (-(-GEO['firmware_end'] // 1020)),
        'observed_cipher_len': GEO['cipher_len'],
        'framing_overhead_bytes': 4 * (-(-GEO['firmware_end'] // 1020)),
        'last_block_padding_bytes': 1020 - (
            GEO['firmware_end'] - 1020 * (-(-GEO['firmware_end'] // 1020) - 1)),
        'leftover_as_reported': F7_N,
        'overhead_plus_padding': 4 * (-(-GEO['firmware_end'] // 1020)) + 1020 - (
            GEO['firmware_end'] - 1020 * (-(-GEO['firmware_end'] // 1020) - 1)),
        'components_sum': 512 + 1253376 + GEO['firmware_size'],
    },
    'mods': {str(m): F7_N % m for m in (1024, 2048, 4096, 8192, 16384, 65536, 131072, 1024 * 1024)},
    'firmware_size_factorization': dict(factorize(GEO['firmware_size'])),
    'cipher_len_factorization': dict(factorize(GEO['cipher_len'])),
    'fs_user_factorization': dict(factorize(1253376)),
}

with open(OUT, 'w') as f:
    json.dump(E, f, indent=1, sort_keys=True, default=str)

# ------------------------------------------------------------------ the printout
print('=== G1 geometry ===')
for k in ('model', 'version', 'firmware_offset', 'firmware_size', 'firmware_end', 'cipher_len',
          'f07_start_payload', 'f07_size', 'f07_start_file', 'f07_end_file', 'iv_file',
          'f07_size_eq_2838_kib', 'fwsize_mod_1024', 'fwsize_mod_512', 'cipherlen_mod_1024'):
    print('  %-22s %s' % (k, GEO[k]))
print('  FS slots (non-empty):', GEO['fs_slots_nonzero'])
print('  region size mod:', GEO['f07_size_mod'])
print('  first 64 B of the region:', GEO['f07_first_bytes_hex'])
print('  64 B before the region:', GEO['before_f07_hex'])
print('  IV from the tail   :', GEO['iv_hex'])
print('  first 64 B of tail :', GEO['after_iv_hex'])
print('=== B boundaries ===')
for k, v in E['B_boundary'].items():
    print('  %-34s %s' % (k, v))
print('=== E entropy (bits/byte) ===')
print('  %-18s %-10s %-10s %-10s %-10s %-9s' % ('set', 'all', 'w4096min', 'w1024min', 'w256min', 'deflate'))
for k, v in sorted(E['E_entropy'].items()):
    print('  %-18s %-10.6f %-10.6f %-10.6f %-10.6f %-9.4f' % (
        k, v['entropy_whole'], v['w4096']['min'], v['w1024']['min'], v['w256']['min'],
        v['deflate_ratio']))
print('  f07 chi2/1024:', E['E_entropy']['f07']['chi2_per_1024'])
print('  f07, the 10 lowest 4-KiB windows:', E['E_entropy']['f07']['w4096']['ten_lowest'])
print('=== C against the body ===')
for k, v in E['C_vs_body'].items():
    print('  %-16s %s' % (k, v))
print('=== D duplicates ===')
for k, v in E['D_duplicates'].items():
    print('  %-32s %s' % (k, v))
print('=== S strings ===')
for k in ('f07_ascii5_count', 'f07_ascii8_count', 'f07_utf16_count',
          'control_random_ascii5_count', 'control_text_ascii5_count',
          'body_fw_head_ascii5_count'):
    print('  %-32s %s' % (k, E['S_strings'][k]))
print('  sample:', E['S_strings']['f07_ascii5_sample'][:10])
print('=== F the frame ===')
for k, v in E['F_framing'].items():
    print('  %-36s %s' % (k, v))
print('  after decryption:', E['F_after_decrypt'])
print('=== H search ===')
print('  patterns:', E['H_hash_search']['n_patterns'],
      'with no hits:', E['H_hash_search']['patterns_with_zero_hits'])
print('  hits:', E['H_hash_search']['hits_by_pattern'])
print('  control:', E['H_hash_search']['CONTROL_planted'])
print('=== M factorization ===')
print('  ', E['M_factorization']['factorization'], '= %d KiB' % E['M_factorization']['as_kib'])
print('   KiB divisors:', E['M_factorization']['kib_divisors'])
for k, v in E['M_factorization']['nice_sizes'].items():
    print('   %-18s %s' % (k, v))
print('   mods:', E['M_factorization']['mods'])
print('written:', OUT)
