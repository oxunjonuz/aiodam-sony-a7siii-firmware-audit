#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Independent check of the unpacking: two different codes must give the same bytes.

Route A: my block-wise unpacking (out/stream.bin).
Route B: the fwtool library (AesCbcCrypter + readFdat) — its own file, its own sha256.
In addition: the reference readFdat MUST fail on our file (it computes the header crc
over 388 bytes, while in this format the header is 512 B) — and it must work if
the reference is given the correct length of the crc area.
Control: corrupting one byte of ciphertext must break route B.
"""
import binascii, hashlib, io, json, os, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
from Crypto.Cipher import AES
from fwtool.sony import constants as KC
from fwtool.sony import fdat as refdat
from fwtool.sony.fdat import AesCbcCrypter, BlockCryptException, FdatHeader
from fwtool.sony import dat as datmod

K_057_k8 = b'\x43\x45\x89\x43\x2D\x31\x90\x10\xF1\x13\x27\x27\x35\x32\x86\xCE' \
           b'\x4D\x7E\xDE\x8B\x9C\x4F\x72\x17\xA0\xE0\x22\x6E\x0F\x0E\xDC\x69'
refdat._crypters['CXD90057_k8'] = lambda: AesCbcCrypter(KC.key_aes, K_057_k8)
E = {}
OUTB = ROOT + '/out/stream_fwtool.bin'


def decrypt_to_file(src, dst):
    d = datmod.readDat(open(src, 'rb'))
    name, fdatf = refdat.decryptFdat(d.firmwareData)
    fdatf.seek(0)
    h, n = hashlib.sha256(), 0
    with open(dst, 'wb') as f:
        while True:
            b = fdatf.read(1 << 20)
            if not b:
                break
            f.write(b)
            h.update(b)
            n += len(b)
    return name, n, h.hexdigest()


E['path_b'] = dict(zip(('crypter', 'bytes', 'sha256'), decrypt_to_file(P, OUTB)))
a = open(ROOT + '/out/stream.bin', 'rb').read()
E['path_a'] = {'bytes': len(a), 'sha256': hashlib.sha256(a).hexdigest()}
E['identical'] = (E['path_a']['bytes'] == E['path_b']['bytes']
                  and E['path_a']['sha256'] == E['path_b']['sha256'])

# the reference readFdat on the unpacked file
f = open(OUTB, 'rb')
try:
    info = refdat.readFdat(f)
    E['reference_readFdat'] = {'ok': True, 'model': hex(info.model), 'version': info.version}
except Exception as ex:
    E['reference_readFdat'] = {'ok': False, 'error': '%s: %s' % (type(ex).__name__, ex)}
# and the same call with the correct crc-area length (512-12 = 500)
hdr = FdatHeader.unpack(io.BytesIO(a))
E['manual_header'] = {'magic': hdr.magic.decode('latin1'), 'version': '%x.%02x' % (hdr.versionMajor, hdr.versionMinor),
                      'model': hex(hdr.model), 'firmware_offset': hdr.firmwareOffset,
                      'firmware_size': hdr.firmwareSize, 'region': hdr.region,
                      'num_fs': hdr.numFileSystems,
                      'crc_ok_500': (binascii.crc32(a[12:512]) & 0xffffffff) == hdr.checksum,
                      'crc_ok_388': (binascii.crc32(a[12:400]) & 0xffffffff) == hdr.checksum}
refdat._orig_calc = refdat._calcCrc
refdat._calcCrc = lambda file: binascii.crc32(a[12:512]) & 0xffffffff
f.seek(0)
try:
    info = refdat.readFdat(f)
    from fwtool.sony.fdat import FdatFileSystemHeader, maxNumFileSystems
    E['reference_readFdat_patched_crc'] = {'ok': True, 'model': hex(info.model),
                                           'version': info.version,
                                           'firmware_size': info.firmware.size,
                                           'fs_size': info.fs.size}
except Exception as ex:
    E['reference_readFdat_patched_crc'] = {'ok': False, 'error': '%s: %s' % (type(ex).__name__, ex)}
refdat._calcCrc = refdat._orig_calc

# control: one byte of ciphertext corrupted
tmp = '/tmp/tamper277.dat'
whole = open(P, 'rb').read()
data = bytearray(whole)
data[108 + 40000] ^= 0x01
open(tmp, 'wb').write(bytes(data))
try:
    r = decrypt_to_file(tmp, '/tmp/tamper277_out.bin')
    E['CONTROL_tampered'] = {'result': 'accepted', 'bytes': r[1]}
except BlockCryptException as ex:
    E['CONTROL_tampered'] = {'result': 'rejected', 'error': str(ex)}
except Exception as ex:
    E['CONTROL_tampered'] = {'result': 'rejected-other', 'error': '%s: %s' % (type(ex).__name__, ex)}
for p in (tmp, '/tmp/tamper277_out.bin'):
    if os.path.exists(p):
        os.unlink(p)
# control 2: an intact file but a wrong key -> must fail as well
refdat._crypters['WRONG'] = lambda: AesCbcCrypter(KC.key_aes, b'\x00' * 32)
d = datmod.readDat(open(P, 'rb'))
try:
    refdat._crypters['WRONG']().decrypt(d.firmwareData)
    E['CONTROL_wrong_key'] = {'result': 'accepted'}
except Exception as ex:
    E['CONTROL_wrong_key'] = {'result': 'rejected', 'error': type(ex).__name__}

with open(ROOT + '/audit/verify_stream.json', 'w') as fh:
    json.dump(E, fh, indent=1, default=str)
print(json.dumps(E, indent=1, default=str))
