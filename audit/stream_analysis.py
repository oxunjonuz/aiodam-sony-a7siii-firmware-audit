#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Analysis of the unpacked stream: block frames, contents, keys, the tail.

1) a clean unpacking (reading strictly in 1024 B steps to the end of the encrypted area):
   the sizes of all frames, the end flag of the last block, the 0xff padding and the
   checksum of each block -> a direct measurement of what the "2 906 112" bytes were;
2) the header crc32 over [12:512) — a check that the header is 512 B;
3) the context around the model names (ILCE-7SM3 / 7M4 / FX3) — that is the file name;
4) parsing the tar table of contents of the firmware image + a search for crypto material
   (DER/PEM/public keys) — in case the verification key lies in the file itself;
5) the fs_user image: its type, its entropy;
6) the 256 B tail: its relation to the stream.
"""
import binascii, hashlib, io, json, os, sys
import numpy as np

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
STREAM = ROOT + '/out/stream.bin'
OUT = ROOT + '/audit/stream_analysis.json'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
from Crypto.Cipher import AES
from fwtool.sony import constants as KC
from fwtool.sony import dat as refdat

K_057_k8 = b'\x43\x45\x89\x43\x2D\x31\x90\x10\xF1\x13\x27\x27\x35\x32\x86\xCE' \
           b'\x4D\x7E\xDE\x8B\x9C\x4F\x72\x17\xA0\xE0\x22\x6E\x0F\x0E\xDC\x69'
BLOCK = 1024
E = {}

# ------------------------------------------------------------------ 1 the unpacking
def unpack():
    d = refdat.readDat(open(P, 'rb'))
    payload = d.firmwareData
    fsize = payload.size
    cipher_len = fsize - 0x110
    payload.seek(cipher_len)
    iv = payload.read(0x10)
    payload.seek(0)
    cbc = AES.new(K_057_k8, AES.MODE_CBC, iv)
    ecb = AES.new(KC.key_aes, AES.MODE_ECB)
    sizes, endflags, bad, pads = [], [], [], []
    total = 0
    nread = 0
    with open(STREAM, 'wb') as out:
        while nread < cipher_len:
            blk = payload.read(BLOCK)
            if not blk:
                break
            assert len(blk) == BLOCK, 'short read %d' % len(blk)
            nread += BLOCK
            first = (nread == BLOCK)
            pt = (ecb.decrypt(blk[:512]) + cbc.decrypt(blk[512:])) if first else cbc.decrypt(blk)
            csum = int.from_bytes(pt[0:2], 'little')
            sized = int.from_bytes(pt[2:4], 'little')
            size = sized & 0x7fff
            endflag = bool(sized & 0x8000)
            calc = sum(int.from_bytes(pt[j:j + 2], 'little') for j in range(2, BLOCK, 2)) & 0xffff
            if calc != csum:
                bad.append({'block': len(sizes), 'stored': hex(csum), 'computed': hex(calc)})
            assert 0 <= size <= 1020, 'size out of range %d' % size
            sizes.append(size)
            endflags.append(endflag)
            pad = pt[4 + size:]
            pads.append({'block': len(sizes) - 1, 'pad_len': len(pad),
                         'all_ff': all(b == 0xff for b in pad)})
            out.write(pt[4:4 + size])
            total += size
    return {'blocks': len(sizes), 'cipher_len': cipher_len, 'nread': nread,
            'iv_hex': iv.hex(), 'stream_bytes': total,
            'bad_checksum_blocks': bad, 'checksum_ok_blocks': len(sizes) - len(bad),
            'sizes_1020_except_last': all(s == 1020 for s in sizes[:-1]),
            'last_block_size': sizes[-1], 'last_block_endflag': endflags[-1],
            'endflag_count': sum(1 for x in endflags if x),
            'endflag_on_last_only': all(endflags[:-1]) is False and endflags[-1],
            'framing_bytes': 4 * len(sizes),
            'last_pad_len': pads[-1]['pad_len'], 'last_pad_all_ff': pads[-1]['all_ff'],
            'framing_plus_pad': 4 * len(sizes) + pads[-1]['pad_len'],
            'tail_blocks_endflag': [i for i, x in enumerate(endflags) if x][:5]}


E['unpack'] = unpack()
st = open(STREAM, 'rb').read()
E['stream'] = {'bytes': len(st), 'sha256': hashlib.sha256(st).hexdigest(),
               'crc32': hex(binascii.crc32(st) & 0xffffffff)}
FW_OFF, FW_SIZE, FS_OFF, FS_SIZE = 1253888, 739658240, 512, 1253376
E['stream']['ends_at_firmware_end'] = (len(st) == FW_OFF + FW_SIZE)
E['stream']['declared_components_sum'] = 512 + FS_SIZE + FW_SIZE
E['stream']['unaccounted_bytes_now'] = len(st) - (FW_OFF + FW_SIZE)

# 2 the header crc
E['header_crc'] = {
    'stored': '0x%08x' % int.from_bytes(st[8:12], 'little'),
    'crc12_400': '0x%08x' % (binascii.crc32(st[12:400]) & 0xffffffff),
    'crc12_512': '0x%08x' % (binascii.crc32(st[12:512]) & 0xffffffff),
    'crc12_508': '0x%08x' % (binascii.crc32(st[12:508]) & 0xffffffff),
    'zeros_400_512': all(b == 0 for b in st[400:512]),
    'zeros_92_512': all(b == 0 for b in st[92:512]),
}
E['header_crc']['matches_512'] = E['header_crc']['stored'] == E['header_crc']['crc12_512']
E['header_crc']['matches_400'] = E['header_crc']['stored'] == E['header_crc']['crc12_400']
E['header_crc']['CONTROL_flip'] = '0x%08x' % (binascii.crc32(
    st[12:200] + bytes([st[200] ^ 1]) + st[201:512]) & 0xffffffff)

# ------------------------------------------------------------------ 3 the model names
def ctx(off, n=96):
    return st[max(0, off - 40):off + n].decode('latin1')


E['model_context'] = {}
for pat in (b'ILCE-7SM3', b'ILCE-7M4', b'ILCE-', b'FX3', b'ILME-', b'DSC-'):
    hits = []
    pos = 0
    while True:
        i = st.find(pat, pos)
        if i < 0:
            break
        hits.append({'off': i, 'region': 'firmware' if i >= FW_OFF else 'fs_user',
                     'ctx': ctx(i)})
        pos = i + 1
        if len(hits) >= 12:
            break
    if hits:
        E['model_context'][pat.decode('latin1')] = hits
uniq = sorted({h['ctx'][40:40 + 24] for k in E['model_context'] for h in E['model_context'][k]})
E['model_context']['_unique_24byte_windows'] = uniq[:30]

# ------------------------------------------------------------------ 4 the tar table of contents
def tar_list(buf, base, limit=100000):
    members = []
    off = 0
    n = len(buf)
    while off + 512 <= n and len(members) < limit:
        hdr = buf[off:off + 512]
        if hdr[:100].rstrip(b'\x00') == b'':
            off += 512
            continue
        if hdr[257:262] != b'ustar':
            break
        name = hdr[0:100].rstrip(b'\x00').decode('latin1')
        try:
            size = int(hdr[124:136].rstrip(b'\x00 ').decode() or '0', 8)
        except ValueError:
            break
        mode = hdr[100:108].rstrip(b'\x00 ').decode('latin1')
        mtime = hdr[136:148].rstrip(b'\x00 ').decode('latin1')
        typeflag = hdr[156:157].decode('latin1')
        members.append({'name': name, 'size': size, 'mode': mode, 'mtime_octal': mtime,
                        'typeflag': typeflag, 'abs_off': base + off})
        off += 512 + ((size + 511) // 512) * 512
    return members


fw = st[FW_OFF:FW_OFF + FW_SIZE]
members = tar_list(fw, FW_OFF)
E['tar'] = {'members': len(members), 'first_20': members[:20],
            'last_5': members[-5:] if members else [],
            'total_member_bytes': sum(m['size'] for m in members),
            'keyword_hits': [m for m in members if any(
                k in m['name'].lower() for k in ('sign', 'key', 'cert', 'version', 'model',
                                                 'updater', 'ver', 'v5', 'integrit'))][:40]}
# tar instrument control: assemble a synthetic tar and parse it with the same code
import tarfile, tempfile
with tempfile.NamedTemporaryFile(delete=False) as tf:
    with tarfile.open(fileobj=tf, mode='w') as t:
        for nm, data in (('a/b.txt', b'hello'), ('c.bin', b'\x00' * 3000)):
            ti = tarfile.TarInfo(nm)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    ctrl = open(tf.name, 'rb').read()
os.unlink(tf.name)
E['tar']['CONTROL_synthetic'] = [m['name'] for m in tar_list(ctrl, 0)]

# ------------------------------------------------------------------ 5 crypto material
PATS = {
    'pkcs1_rsa2048_spki': bytes.fromhex('30820122300d06092a864886f70d01010105000382010f00'),
    'pkcs1_rsapublickey': bytes.fromhex('3082010a0282010100'),
    'x509_cert': bytes.fromhex('3082'),
    'pem_public': b'BEGIN PUBLIC KEY',
    'pem_rsa': b'BEGIN RSA PUBLIC KEY',
    'pem_cert': b'BEGIN CERTIFICATE',
    'rsa_exponent_65537': bytes.fromhex('010001'),
    'sony_rsa_modulus_head': bytes.fromhex('c9201f'),
}
hits = {}
for k, v in PATS.items():
    f = []
    pos = 0
    while True:
        i = st.find(v, pos)
        if i < 0:
            break
        if k == 'x509_cert':
            f.append(i)
            if len(f) >= 20:
                break
        else:
            f.append(i)
            if len(f) >= 20:
                break
        pos = i + 1
    hits[k] = f
E['crypto_material'] = {'hits': hits, 'notes': 'DER structures and PEM markers in the stream'}
# control: plant an SPKI and find it
blob = bytearray(st[:1 << 20])
spki = PATS['pkcs1_rsa2048_spki']
blob[12345:12345 + len(spki)] = spki
E['crypto_material']['CONTROL_planted'] = bytes(blob).find(spki)

# ------------------------------------------------------------------ 6 the fs_user image
fsi = st[FS_OFF:FS_OFF + FS_SIZE]
a = np.frombuffer(fsi, dtype=np.uint8)
E['fs_user'] = {
    'size': FS_SIZE,
    'entropy': float(-sum((c / len(fsi)) * np.log2(c / len(fsi))
                          for c in np.bincount(a, minlength=256) if c)),
    'zeros': int((a == 0).sum()), 'ff': int((a == 0xff).sum()),
    'first_64_hex': fsi[:64].hex(),
    'dup_16B_blocks': len(fsi) // 16 - len({fsi[i:i + 16] for i in range(0, len(fsi) - 15, 16)}),
    'sha256': hashlib.sha256(fsi).hexdigest(),
    'is_tar': fsi[257:262] == b'ustar',
    'gzip_try_head': fsi[:2].hex(),
}
for zname, fn in (('zlib', lambda b: __import__('zlib').decompress(b)),
                  ('gzip', lambda b: __import__('gzip').decompress(b))):
    try:
        out = fn(fsi)
        E['fs_user'][zname + '_decompress'] = len(out)
    except Exception as e:
        E['fs_user'][zname + '_decompress'] = 'error: %s' % type(e).__name__
try:
    import lzma
    E['fs_user']['lzma_decompress'] = len(lzma.decompress(fsi))
except Exception as e:
    E['fs_user']['lzma_decompress'] = 'error: %s' % type(e).__name__

# ------------------------------------------------------------------ 7 the tail
d = refdat.readDat(open(P, 'rb'))
payload = d.firmwareData
payload.seek(payload.size - 272)
tail = payload.read(272)
iv, sig = tail[:16], tail[16:]
E['tail'] = {
    'iv_hex': iv.hex(), 'sig_hex_head': sig[:16].hex(), 'sig_hex_tail': sig[-16:].hex(),
    'sig_entropy': float(-sum((c / 256) * np.log2(c / 256)
                              for c in np.bincount(np.frombuffer(sig, dtype=np.uint8),
                                                   minlength=256) if c)),
    'sig_in_stream': sig in st[:1 << 20],
    'iv_in_stream': iv in st,
    'sha256_stream': hashlib.sha256(st).hexdigest(),
    'sha256_firmware': hashlib.sha256(fw).hexdigest(),
    'sha256_matches_sig_head32': hashlib.sha256(st).digest() == sig[:32],
    'stream_sha256_inside_sig': hashlib.sha256(st).digest() in sig,
    'fw_sha256_inside_sig': hashlib.sha256(fw).digest() in sig,
}
# compare with the declared cipher_len and with the last block
E['tail']['cipher_len_mod_1024'] = (FW_OFF + FW_SIZE) % 1024

with open(OUT, 'w') as f:
    json.dump(E, f, indent=1, sort_keys=True, default=str)
print(json.dumps(E, indent=1, ensure_ascii=False))
