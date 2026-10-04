#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The 256 B tail: testing the hypothesis "this is an RSA-2048 signature" by what is
checkable without a private key. Plus everything that is checkable about the tail at all.

Key points:
  * we have ONE published RSA-2048 public key from this same family
    (Sony-PMCA-RE, pmca/spk/constants.py, the modulus from
    lib/camera/...librsaforinstaller.so; e = 65537);
  * for a signature and for RSA encryption the structure after exponentiation is
    checked WITHOUT the private key: PKCS#1 v1.5 (00 01 FF..FF 00 || DER),
    or encryption (00 02 <odd non-zero> 00 || key), or PSS;
  * the tail is the only 256 bytes in the file that lie OUTSIDE the encrypted
    area (16 B of IV + 256 B after it), which is why the hypothesis is worth testing.
"""
import binascii, hashlib, json, math, sys
import numpy as np

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
OUT = ROOT + '/audit/tail_rsa.json'
F0, FLEN = 108, 743818512
E = {}


def rd(off, n):
    with open(P, 'rb') as f:
        f.seek(off)
        return f.read(n)


iv = rd(F0 + FLEN - 272, 16)
tail = rd(F0 + FLEN - 256, 256)
assert len(tail) == 256
s_be = int.from_bytes(tail, 'big')
s_le = int.from_bytes(tail, 'little')

MODULUS = int(open(ROOT + '/tools/Sony-PMCA-RE-master/pmca/spk/constants.py').read()
              .split('rsaModulus = ')[1].split('\n')[0])
E['tail_stats'] = {
    'tail_hex_first32': tail[:32].hex(),
    'tail_hex_last32': tail[-32:].hex(),
    'iv_hex': iv.hex(),
    'entropy_bits_per_byte': float(-sum(
        (c / 256) * math.log2(c / 256) for c in np.bincount(np.frombuffer(tail, dtype=np.uint8),
                                                            minlength=256) if c)),
    'zeros_in_tail': int((np.frombuffer(tail, dtype=np.uint8) == 0).sum()),
    'zero_bytes_at_start': len(tail) - len(tail.lstrip(b'\x00')),
    'first_byte': tail[0], 'last_byte': tail[-1],
}
E['key_from_pmca'] = {
    'source': 'tools/Sony-PMCA-RE-master/pmca/spk/constants.py',
    'source_note': 'ScalarAInstaller.apk/lib/librsaforinstaller.so',
    'modulus_bits': MODULUS.bit_length(),
    'exponent': 65537,
    'tail_as_int_be_lt_modulus': s_be < MODULUS,
    'tail_as_int_le_lt_modulus': s_le < MODULUS,
}


def pkcs1_v15_signature_structure(m):
    """00 01 FF..FF 00 || DigestInfo?"""
    if m[0] != 0 or m[1] != 0x01:
        return {'ok': False, 'why': 'first byte is not 00 01: %02x %02x' % (m[0], m[1])}
    i = 2
    while i < len(m) and m[i] == 0xff:
        i += 1
    if i < 10 or i >= len(m) or m[i] != 0:
        return {'ok': False, 'why': 'no 00 after the run of FF (ff_run=%d)' % (i - 2)}
    di = m[i + 1:]
    return {'ok': True, 'ff_run': i - 2, 'digestinfo_len': len(di),
            'digestinfo_hex': di.hex()[:80],
            'looks_like_sha256_prefix': di[:19] == bytes.fromhex(
                '3031300d060960864801650304020105000420'),
            'looks_like_sha1_prefix': di[:15] == bytes.fromhex('3021300906052b0e03021a05000414'),
            'looks_like_sha384_prefix': di[:19] == bytes.fromhex(
                '3041300d060960864801650304020205000430'),
            'looks_like_sha512_prefix': di[:19] == bytes.fromhex(
                '3051300d060960864801650304020305000440')}


def pkcs1_v15_encryption_structure(m):
    if m[0] != 0 or m[1] != 0x02:
        return {'ok': False, 'why': 'first byte is not 00 02: %02x %02x' % (m[0], m[1])}
    j = tail.find(b'\x00', 2)
    return {'ok': j > 0, 'nonzero_run': j - 2 if j > 0 else None,
            'payload_len': len(m) - j - 1 if j > 0 else None,
            'payload_hex': m[j + 1:].hex() if j > 0 else None}


def pss_structure(m):
    return {'ok': (m[0] & 0x80) == 0 and m[-1] == 0xbc,
            'first_byte': m[0], 'last_byte': m[-1]}


results = {}
for name, val, order in (('be_e65537', s_be, 'big'), ('le_e65537', s_le, 'big')):
    if val >= MODULUS:
        # RSA requires 0 <= s < n; with s >= n the modular exponentiation is
        # still formally computable, but such a tail cannot be a signature
        results[name] = {'s_lt_n': False, 'note': 's >= n: this cannot be a signature, '
                                                  'but we look at the structure anyway'}
    m = pow(val, 65537, MODULUS).to_bytes(256, 'big')
    results[name] = dict(results.get(name, {}), **{
        'm_first16_hex': m[:16].hex(), 'm_last16_hex': m[-16:].hex(),
        'pkcs1_v15_signature': pkcs1_v15_signature_structure(m),
        'pkcs1_v15_encryption': pkcs1_v15_encryption_structure(m),
        'pss': pss_structure(m),
        'm_entropy': float(-sum((c / 256) * math.log2(c / 256) for c in
                                np.bincount(np.frombuffer(m, dtype=np.uint8), minlength=256) if c)),
    })
# e = 3 is tested too (rare schemes)
m3 = pow(s_be, 3, MODULUS).to_bytes(256, 'big')
results['be_e3'] = {'pkcs1_v15_signature': pkcs1_v15_signature_structure(m3),
                    'm_first16_hex': m3[:16].hex()}
E['public_key_tests'] = results

# ---------------------------------------------------------------- the tail as a hash
def digests_of(off, n):
    hs = {k: hashlib.new(k) for k in ('md5', 'sha1', 'sha256', 'sha512')}
    hs['blake2b'] = hashlib.blake2b(digest_size=32)
    crc = 0
    with open(P, 'rb') as f:
        f.seek(off)
        left = n
        while left:
            b = f.read(min(1 << 20, left))
            for h in hs.values():
                h.update(b)
            crc = binascii.crc32(b, crc)
            left -= len(b)
    d = {k: v.digest() for k, v in hs.items()}
    d['crc32'] = binascii.crc32(rd(off, n)).to_bytes(4, 'big') if n < (1 << 24) else None
    return d


regions = {'tail256': (F0 + FLEN - 256, 256), 'iv16': (F0 + FLEN - 272, 16),
           'payload_minus_tail': (F0, FLEN - 272), 'header512': (F0, 512),
           'firmware': (F0 + 1253888, 739658240), 'whole_payload': (F0, FLEN)}
hits = {}
for rname, (off, n) in regions.items():
    for algo, d in digests_of(off, n).items():
        if d is None:
            continue
        where = []
        pos = 0
        while True:
            i = tail.find(d, pos)
            if i < 0:
                break
            where.append(i)
            pos = i + 1
        hits['%s/%s' % (rname, algo)] = where
E['hashes_inside_tail'] = {
    'tested': sorted(hits), 'found_in_tail': {k: v for k, v in hits.items() if v},
    'n_tested': len(hits), 'n_found': sum(1 for v in hits.values() if v),
}
# CONTROL: a digest planted in the tail is found
planted = hashlib.sha256(rd(F0, 512)).digest()
blob = bytearray(tail)
blob[100:132] = planted
E['hashes_inside_tail']['CONTROL_planted'] = {'found_at': bytes(blob).find(planted),
                                              'expected': 100}
# ---------------------------------------------------------------- what protects the tail
E['container_protection'] = {
    'dend_crc_covers_tail': True,   # DEND.crc is computed over all bytes up to it, the tail included
    'dend_crc_recomputable_without_any_key': True,
    'note': 'C8 of an earlier round: a changed body byte + a recomputed DEND.crc is accepted '
            'by the reference parser. So neither the body nor the tail is authenticated by the container CRC.',
    'tail_changes_would_be_invisible_without_signature_file': True,
}
# whether the IV/tail changes from file to file cannot be checked (one file only):
E['container_protection']['second_file_available'] = False

# ---------------------------------------------------------------- the entropy control
def win_entropies(buf, w):
    n = len(buf) // w
    a = np.frombuffer(buf[:n * w], dtype=np.uint8).reshape(n, w)
    out = []
    for row in a:
        c = np.bincount(row, minlength=256).astype(np.float64)
        p = c[c > 0] / w
        out.append(float(-(p * np.log2(p)).sum()))
    return np.array(out)


_ctrl = hashlib.sha256(b'tail control').digest()
_stream = bytearray()
_ct = 0
from Crypto.Cipher import AES as _AES
_c = _AES.new(_ctrl, _AES.MODE_ECB)
while len(_stream) < 300000:
    _stream += _c.encrypt(_ct.to_bytes(16, 'little'))
    _ct += 1
_ce = win_entropies(bytes(_stream), 256)
_f07 = rd(F0 + 740912128, 2906112)
_fe = win_entropies(_f07, 256)
E['tail_stats']['entropy_control'] = {
    'control_random_256B_windows': {'n': int(_ce.size), 'mean': float(_ce.mean()),
                                    'min': float(_ce.min()), 'max': float(_ce.max()),
                                    'sd': float(_ce.std())},
    'f07_256B_windows': {'n': int(_fe.size), 'mean': float(_fe.mean()),
                         'min': float(_fe.min()), 'max': float(_fe.max())},
    'tail_entropy': E['tail_stats']['entropy_bits_per_byte'],
    'tail_percentile_in_control': float((_ce < E['tail_stats']['entropy_bits_per_byte']).mean()),
    'tail_percentile_in_f07': float((_fe < E['tail_stats']['entropy_bits_per_byte']).mean()),
}

with open(OUT, 'w') as f:
    json.dump(E, f, indent=1, sort_keys=True, default=str)

print(json.dumps(E, indent=1, ensure_ascii=False))
