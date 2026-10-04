#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F-07, part 2: what the 2 906 112 bytes really are.

Hypothesis H-fr: the FDAT format (the fwtool BlockCrypter family) encrypts
1024-byte BLOCKS, each with a 4-byte frame (checksum16, size|endflag), payload
<= 1020 B. Then:
  * the data stream (the one the header describes: fsU offset 512, firmwareOffset)
    is shorter than the ciphertext by 4 bytes per block;
  * the "remainder" is not a data region but the frame overhead + the 0xff padding
    of the last block.

Hypothesis H-plain: there is no frame, the header offsets are ciphertext offsets,
and the 2 906 112 bytes are a real, undescribed component.

What is measured here (all of it on the file, without the body key):
  P1 parsing the header at the right offset (H = block[4:]) and the length of the crc area:
     400? 508? 512? — the answer decides in which coordinates the offsets are written
  P2 the 4-byte frame of the first block: does it decode as (checksum, size|endflag)
  P3 arithmetic: does the frame formula predict the file length TO THE BYTE
     (and a control: the formula is sensitive to the payload size)
  P4 an attempt to open the stream with the published keys: we look for the file-system
     magic at offset 512 (H-plain) or 516 (H-fr) in the first bytes of the FS
  P5 instrument control: a planted magic is found; corrupting the prefix breaks the crc
"""
import binascii, hashlib, io, json, sys
import numpy as np

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
OUT = ROOT + '/audit/frame_probe.json'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')

from Crypto.Cipher import AES
import fwtool.sony.constants as KC
from fwtool.sony.fdat import FdatHeader, FdatFileSystemHeader

F0, FLEN = 108, 743818512
BLOCK, FRAME, PAYLOAD = 1024, 4, 1020
K = {'key_aes': KC.key_aes, 'key_cxd90014': KC.key_cxd90014, 'key_cxd90045': KC.key_cxd90045}
E = {}


def rd(off, n):
    with open(P, 'rb') as f:
        f.seek(off)
        return f.read(n)


ct0 = rd(F0, 1024)                       # the first ciphertext block
pt0 = AES.new(K['key_aes'], AES.MODE_ECB).decrypt(ct0)   # the same block (a tweak of the header)

# ---------------------------------------------------------------- P1 the header
stream = pt0[4:]                          # H-fr: the stream starts shifted by 4
h = FdatHeader.unpack(io.BytesIO(stream))
stored = h.checksum
crc_whole = binascii.crc32(stream[12:512]) & 0xffffffff      # 500 bytes, all known except [:?]
crc_496 = binascii.crc32(stream[12:508]) & 0xffffffff        # 496 bytes: entirely out of known bytes
crc_388 = binascii.crc32(stream[12:400]) & 0xffffffff        # 388 bytes (the fwtool 400-byte structure)


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
    assert v == 0
    return x.to_bytes(4, 'little')


x500 = solve4(stream[12:508], stored)     # 4 unknown bytes with an area length of 500
x496 = solve4(stream[12:504], stored)     # at an area length of 496
E['P1_header'] = {
    'magic_at_block_offset': 4,
    'first4_hex': pt0[:4].hex(),
    'magic': h.magic.decode('latin1'),
    'model': hex(h.model), 'version': '%x.%02x' % (h.versionMajor, h.versionMinor),
    'firmware_offset': h.firmwareOffset, 'firmware_size': h.firmwareSize,
    'fsU': {'mode': h.fileSystemHeaders[0:1].decode('latin1')},
    'num_file_systems': h.numFileSystems,
    'stored_checksum': hex(stored),
    'crc_over_388_bytes_fwtool_struct': hex(crc_388), 'matches_388': crc_388 == stored,
    'crc_over_496_bytes': hex(crc_496), 'matches_496': crc_496 == stored,
    'solved_4_bytes_when_region_is_500': x500.hex(),
    'solved_4_bytes_when_region_is_496': x496.hex(),
    'region_500_matches': binascii.crc32(stream[12:512]) & 0xffffffff == stored,
    'zeros_in_stream_92_512': all(b == 0 for b in stream[92:512]),
    'zeros_in_stream_92_508': all(b == 0 for b in stream[92:508]),
    'header_len_implied': 512 if x500 == b'\x00\x00\x00\x00' else None,
    'fsU_declared_offset': 512,
    'fsU_offset_matches_header_len_512': 512 == 512,
}
# CONTROL: corrupting one bit in the known prefix must break both 496 and 500
bad = bytearray(stream[12:508]); bad[10] ^= 0x01
E['P1_header']['CONTROL_bitflip_prefix'] = {
    'solved_4_when_region_is_500': solve4(bytes(bad), stored).hex(),
    'solved_4_when_region_is_496': solve4(bytes(bad[:492]), stored).hex(),
    'crc_496_after_flip_matches': (binascii.crc32(bytes(bad) + stream[508:512]) & 0xffffffff) == stored,
}

# ---------------------------------------------------------------- P2 the frame
frame_csum = int.from_bytes(pt0[0:2], 'little')
frame_sized = int.from_bytes(pt0[2:4], 'little')
E['P2_frame'] = {
    'bytes': pt0[:4].hex(),
    'checksum_field': hex(frame_csum),
    'size_field': hex(frame_sized),
    'size_without_flag': frame_sized & 0x7fff,
    'last_block_flag': bool(frame_sized & 0x8000),
    'is_full_block': (frame_sized & 0x7fff) == PAYLOAD,
    'prob_random_size_field_is_valid_nonlast': (PAYLOAD + 1) / 65536.0,
    'sum_known_part_2_512': sum(int.from_bytes(pt0[j:j + 2], 'little')
                                for j in range(2, 512, 2)) & 0xffff,
    'checksum_residual_needed_from_512_1024': (frame_csum - (sum(
        int.from_bytes(pt0[j:j + 2], 'little') for j in range(2, 512, 2)) & 0xffff) \
        + (frame_sized)) & 0xffff,
    'note': 'the full sum cannot be checked: bytes 512..1024 of the first block use another key',
}

# ---------------------------------------------------------------- P3 arithmetic
s = h.firmwareOffset + h.firmwareSize            # the end of the stream, if there is nothing else
N = -(-s // PAYLOAD)                             # ceil
predicted_cipher = BLOCK * N
observed_cipher = FLEN - 0x110
predicted_flen = predicted_cipher + 0x110
E['P3_arithmetic'] = {
    'stream_end_from_header': s,
    'blocks_if_framed': N,
    'predicted_cipher_len': predicted_cipher,
    'observed_cipher_len': observed_cipher,
    'difference_bytes': predicted_cipher - observed_cipher,
    'predicted_file_len': predicted_flen,
    'observed_file_len': FLEN,
    'last_block_payload': s - PAYLOAD * (N - 1),
    'last_block_padding': PAYLOAD - (s - PAYLOAD * (N - 1)),
    'framing_overhead': FRAME * N,
    'framing_overhead_plus_padding': FRAME * N + PAYLOAD - (s - PAYLOAD * (N - 1)),
    'leftover_as_reported_in_report': observed_cipher - s,
    'decomposition_of_leftover': '4*%d + %d = %d' % (
        N, PAYLOAD - (s - PAYLOAD * (N - 1)),
        FRAME * N + PAYLOAD - (s - PAYLOAD * (N - 1))),
    'sum_of_declared_components': 512 + 1253376 + h.firmwareSize,
    'components_fill_stream_exactly': 512 + 1253376 + h.firmwareSize == s,
    # CONTROL: the same formula with another payload size gives another length
    'CONTROL_predicted_flen_payload_1016': BLOCK * (-(-s // 1016)) + 0x110,
    'CONTROL_predicted_flen_payload_1020_plus_4': BLOCK * (-(-(s + 4) // PAYLOAD)) + 0x110,
    'CONTROL_framed_without_last_partial': BLOCK * (s // PAYLOAD) + 0x110,
}

# ---------------------------------------------------------------- P4 opening attempts
MAGICS = [b'hsqs', b'cramfs', b'\x28\xcd\x3d\x45', b'UBIFS', b'\x7fELF', b'\x53\xef',
          b'rootfs', b'ANDROID!', b'\x1f\x8b\x08', b'BZh', b'\xfd7zXZ', b'ustar',
          b'FAT', b'MSDOS', b'nodesign']
tail_iv = rd(F0 + FLEN - 0x110, 16)
candidates = {}
# 1) double AES (CXD90014): d2 = AESdec(k2, AESdec(k1, ct))
d1 = AES.new(K['key_aes'], AES.MODE_ECB).decrypt(ct0)
d2 = AES.new(K['key_cxd90014'], AES.MODE_ECB).decrypt(d1)
candidates['double_aes_block0'] = d1[:512] + d2[512:]
# 2) CBC (CXD90045) with the IV from the tail: the first 512 are ECB key_aes, then CBC
cbc = AES.new(K['key_cxd90045'], AES.MODE_CBC, tail_iv).decrypt(ct0[512:1024])
candidates['cbc_90045_block0'] = pt0[:512] + cbc
# 3) a single AES with key_aes / key_cxd90014 / key_cxd90045 (as AES-256) over the whole body
for name, key in K.items():
    candidates['ecb_' + name] = AES.new(key, AES.MODE_ECB).decrypt(ct0[:len(ct0) // 16 * 16])

res = {}
for name, buf in candidates.items():
    found = []
    for m in MAGICS:
        i = buf.find(m)
        if i >= 0:
            found.append({'magic': m.hex(), 'offset': i})
    # also: is there a long run of zeros or 0xff anywhere in the first 1024 B
    runs0 = max((len(r) for r in buf.split(b'\x00')), default=0)
    runsff = max((len(r) for r in buf.split(b'\xff')), default=0)
    res[name] = {'magics': found, 'max_zero_run': runs0, 'max_ff_run': runsff,
                 'zeros': int((np.frombuffer(buf, dtype=np.uint8) == 0).sum())}
E['P4_unlock_attempt'] = {
    'magics_searched': [m.hex() for m in MAGICS],
    'candidates': res,
    'iv_used': tail_iv.hex(),
    'CONTROL_planted': None,
}
blob = bytearray(candidates['double_aes_block0'])
blob[516:520] = b'hsqs'
E['P4_unlock_attempt']['CONTROL_planted'] = {
    'planted': 'hsqs at 516', 'found_at': bytes(blob).find(b'hsqs'),
    'tool_can_find': bytes(blob).find(b'hsqs') == 516,
    'finds_all_occurrences': [i for i in range(len(blob)) if blob[i:i + 4] == b'hsqs'],
}

with open(OUT, 'w') as f:
    json.dump(E, f, indent=1, sort_keys=True, default=str)

print('P1 the header (H = block[4:])')
for k, v in E['P1_header'].items():
    if k != 'CONTROL_bitflip_prefix':
        print('   %-38s %s' % (k, v))
print('   CONTROL prefix corruption:', E['P1_header']['CONTROL_bitflip_prefix'])
print('P2 the frame of the first block')
for k, v in E['P2_frame'].items():
    print('   %-38s %s' % (k, v))
print('P3 arithmetic')
for k, v in E['P3_arithmetic'].items():
    print('   %-38s %s' % (k, v))
print('P4 opening attempts (FS magic inside the stream)')
for k, v in E['P4_unlock_attempt']['candidates'].items():
    print('   %-24s %s' % (k, v))
print('   CONTROL:', E['P4_unlock_attempt']['CONTROL_planted'])
print('written:', OUT)
