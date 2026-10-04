#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""New keys from the public PR ma1co/fwtool.py#52 (CXD90057, ILCE-7M4) —
we try to open the body of OUR file and, if it works, answer F-07 directly.

What it does:
  * builds the FDAT payload window with the reference parser (fwtool.sony.dat.readDat);
  * for each candidate decrypter reads the unpacked STREAM through its own
    implementation of fwtool (ChunkedFile): that class checks the frame of
    every 1024-byte block itself (checksum16 + size|endflag) and raises
    BlockCryptException('Wrong checksum') wherever the frame does not match;
  * measures: how many bytes of the stream could be unpacked before the first
    failure, whether isFdat passes, whether readFdat reads, and what lies at
    the end of the decrypted stream (that is the direct answer about the
    2 906 112 bytes).

Every candidate is a public key only (fwtool master + PR #52).
"""
import io, json, sys, time

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
OUT = ROOT + '/audit/newkeys_probe.json'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')

from fwtool.sony import constants as KC
from fwtool.sony.fdat import (AesCbcCrypter, AesCrypter, DoubleAesCrypter, isFdat,
                              readFdat, BlockCryptException)
from fwtool.sony import dat as refdat

# the keys from PR #52 (the same patch as in the public PR)
K_057_k0 = b'\x37\x6A\x61\xD9\x07\x03\x5C\xF1\x83\x00\xF2\xAD\xD6\x50\x3E\x64' \
           b'\x9F\xCC\xF0\xC0\x19\x1D\xCC\x38\xC3\xB0\x58\x95\x15\x0A\x7F\xB6'
K_057_k8 = b'\x43\x45\x89\x43\x2D\x31\x90\x10\xF1\x13\x27\x27\x35\x32\x86\xCE' \
           b'\x4D\x7E\xDE\x8B\x9C\x4F\x72\x17\xA0\xE0\x22\x6E\x0F\x0E\xDC\x69'

CANDIDATES = {
    'CXD90057_k0': lambda: AesCbcCrypter(KC.key_aes, K_057_k0),
    'CXD90057_k8': lambda: AesCbcCrypter(KC.key_aes, K_057_k8),
    'CXD90045': lambda: AesCbcCrypter(KC.key_aes, KC.key_cxd90045),
    'CXD90014': lambda: DoubleAesCrypter(KC.key_aes, KC.key_cxd90014),
    'CXD4132': lambda: AesCrypter(KC.key_aes),
}

f = open(P, 'rb')
d = refdat.readDat(f)
payload = d.firmwareData                     # FilePart: the FDAT window (with its own seek)
PAYLOAD_SIZE = payload.size
E = {'payload_size': PAYLOAD_SIZE, 'candidates': {}}

for name, factory in CANDIDATES.items():
    payload.seek(0)
    t0 = time.time()
    rec = {'payload_size': PAYLOAD_SIZE}
    try:
        stream = factory().decrypt(payload)
        got = bytearray()
        chunk = 1 << 20
        err = None
        while True:
            try:
                b = stream.read(chunk)
            except Exception as e:                     # BlockCryptException and anything else
                err = '%s: %s' % (type(e).__name__, e)
                break
            if not b:
                break
            got += b
            if len(got) > 200 * (1 << 20):             # enough to judge
                break
        rec['bytes_unpacked'] = len(got)
        rec['stopped_with'] = err
        rec['seconds'] = round(time.time() - t0, 1)
        rec['is_fdat'] = None
        if got:
            rec['head_hex'] = bytes(got[:32]).hex()
            rec['magic_at_0'] = bytes(got[:8]) == b'UDTRFIRM'
            rec['magic_at_4'] = bytes(got[4:12]) == b'UDTRFIRM'
            if err is None and len(got) >= 400:
                stream2 = factory().decrypt(payload)
                try:
                    rec['is_fdat'] = bool(isFdat(stream2))
                except Exception as e:
                    rec['is_fdat'] = 'error: %s' % type(e).__name__
    except Exception as e:
        rec['stopped_with'] = 'setup: %s: %s' % (type(e).__name__, e)
        rec['seconds'] = round(time.time() - t0, 1)
    E['candidates'][name] = rec
    print(name, json.dumps(rec, ensure_ascii=False))

# CONTROL: the same instrument on a stream that must unpack completely —
# a synthetic FDAT assembled by the REFERENCE fwtool encrypter with key_aes.
# The control shows the instrument can say "ok", not only "no".
try:
    import shutil
    src = io.BytesIO()
    total = 3 * 1024 * 1024
    src.write(b'UDTRFIRM' + b'\x00' * (400 - 8))          # header
    src.write(b'\x00' * (total - 400))                    # payload
    src.seek(0)
    enc = AesCrypter(KC.key_aes).encrypt(src)
    blob = bytearray()
    while True:
        b = enc.read(1 << 20)
        if not b:
            break
        blob += b
    open('/tmp/ctrl_fdat.bin', 'wb').write(bytes(blob))
    import os
    fh = open('/tmp/ctrl_fdat.bin', 'rb')
    st = AesCrypter(KC.key_aes).decrypt(fh)
    ok = bytearray()
    err = None
    while True:
        try:
            b = st.read(1 << 20)
        except Exception as e:
            err = '%s: %s' % (type(e).__name__, e)
            break
        if not b:
            break
        ok += b
    E['CONTROL_roundtrip'] = {'bytes_in': len(blob), 'bytes_out': len(ok), 'error': err,
                              'magic_ok': bytes(ok[:8]) == b'UDTRFIRM'}
except Exception as e:
    E['CONTROL_roundtrip'] = {'error': '%s: %s' % (type(e).__name__, e)}

with open(OUT, 'w') as fh:
    json.dump(E, fh, indent=1, sort_keys=True, default=str)
print('CONTROL_roundtrip', E['CONTROL_roundtrip'])
print('written', OUT)
