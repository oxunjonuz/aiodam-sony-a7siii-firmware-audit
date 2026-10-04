#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Full unpacking of the file body with the public key CXD90057_k8 (PR #52) —
and direct answers to F-07 and to the question "is there a signature or a second FS in there".

The unpacking here is MY OWN (not a call into fwtool), because the frames of the
1024-byte blocks are what is needed: their sizes and the end flag of the last block
are the measurement that proves what the "2 906 112 unexplained bytes" were.

What comes out:
  out/stream.bin          — the unpacked stream (must be exactly 740 912 128 B)
  audit/unpack_full.json  — every number
"""
import binascii, hashlib, json, os, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
P = ROOT + '/BODYDATA.DAT'
OUTDIR = ROOT + '/out'
STREAM = OUTDIR + '/stream.bin'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
from Crypto.Cipher import AES
from fwtool.sony import constants as KC
from fwtool.sony.fdat import FdatHeader, FdatFileSystemHeader
from fwtool.sony import dat as refdat
import io

K_057_k8 = b'\x43\x45\x89\x43\x2D\x31\x90\x10\xF1\x13\x27\x27\x35\x32\x86\xCE' \
           b'\x4D\x7E\xDE\x8B\x9C\x4F\x72\x17\xA0\xE0\x22\x6E\x0F\x0E\xDC\x69'
BLOCK = 1024
E = {}


def unpack():
    f = open(P, 'rb')
    d = refdat.readDat(f)
    payload = d.firmwareData
    payload.seek(0)
    fsize = payload.size
    cipher_len = fsize - 0x110
    payload.seek(cipher_len)
    iv = payload.read(0x10)
    payload.seek(0)
    cbc = AES.new(K_057_k8, AES.MODE_CBC, iv)
    ecb_aes = AES.new(KC.key_aes, AES.MODE_ECB)
    sizes, frames, bad = [], [], []
    total_stream = 0
    last_endflag = None
    crc_frames = 0
    with open(STREAM, 'wb') as out:
        first = True
        while True:
            blk = payload.read(BLOCK)
            if not blk:
                break
            if first:
                pt = ecb_aes.decrypt(blk[:512]) + cbc.decrypt(blk[512:])
                first = False
            else:
                pt = cbc.decrypt(blk)
            if len(pt) < BLOCK:                      # a trailing incomplete block
                pt = pt + b'\x00' * (BLOCK - len(pt))
            csum = int.from_bytes(pt[0:2], 'little')
            sized = int.from_bytes(pt[2:4], 'little')
            size = sized & 0x7fff
            endflag = bool(sized & 0x8000)
            calc = sum(int.from_bytes(pt[j:j + 2], 'little')
                       for j in range(2, BLOCK, 2)) & 0xffff
            ok = (calc == csum)
            crc_frames += 1 if ok else 0
            if not ok:
                bad.append({'block': len(sizes), 'want': hex(csum), 'got': hex(calc)})
            sizes.append(size)
            frames.append(endflag)
            out.write(pt[4:4 + size])
            total_stream += size
            last_endflag = endflag
    E['unpack'] = {
        'cipher_len': cipher_len, 'iv_hex': iv.hex(),
        'blocks': len(sizes), 'checksum_ok_all': crc_frames == len(sizes),
        'blocks_with_bad_checksum': len(bad), 'first_bad': bad[:3],
        'stream_bytes': total_stream,
        'sizes_all_1020_except_last': all(s == 1020 for s in sizes[:-1]),
        'last_block_size': sizes[-1], 'last_block_endflag': last_endflag,
        'endflags_set_count': sum(1 for x in frames if x),
        'distinct_sizes': sorted(set(sizes)),
    }
    return total_stream


t = unpack()
st = open(STREAM, 'rb').read()
E['stream'] = {
    'bytes': len(st), 'sha256': hashlib.sha256(st).hexdigest(), 'crc32': hex(binascii.crc32(st) & 0xffffffff),
    'magic_at_0': st[:8] == b'UDTRFIRM',
}
# --- the header and the components
h = FdatHeader.unpack(io.BytesIO(st))
slots = []
for i in range(28):
    fs = FdatFileSystemHeader.unpack(h.fileSystemHeaders, i * FdatFileSystemHeader.size)
    slots.append({'i': i, 'mode': fs.modeType.decode('latin1'), 'offset': fs.offset, 'size': fs.size})
E['header'] = {'magic': h.magic.decode('latin1'), 'checksum': hex(h.checksum),
               'version': '%x.%02x' % (h.versionMajor, h.versionMinor), 'model': hex(h.model),
               'region': h.region, 'modeType': h.modeType.decode('latin1'),
               'luwFlag': h.luwFlag.decode('latin1'),
               'firmware_offset': h.firmwareOffset, 'firmware_size': h.firmwareSize,
               'num_file_systems': h.numFileSystems,
               'slots_nonzero': [s for s in slots if s['size'] or s['mode'] != '\x00'],
               'crc_recomputed_ok': (binascii.crc32(st[12:400]) & 0xffffffff) == h.checksum}
fsU = E['header']['slots_nonzero'][0]
fs_img = st[fsU['offset']:fsU['offset'] + fsU['size']]
fw_img = st[h.firmwareOffset:h.firmwareOffset + h.firmwareSize]
end_of_components = h.firmwareOffset + h.firmwareSize
E['stream']['end_of_components'] = end_of_components
E['stream']['extra_after_components'] = len(st) - end_of_components
E['stream']['components_fill_stream'] = len(st) == end_of_components

# --- what these images are
MAG = {'cramfs': b'Compressed ROMFS', 'squashfs(hsqs)': b'hsqs', 'squashfs_le': b'sqsh',
       'ubifs': b'UBIFS', 'elf': b'\x7fELF', 'ustar': b'ustar', 'ext': b'\x53\xef',
       'f2fs': b'\x10\x20\xf5\xf2', 'fat': b'FAT', 'msdos': b'MSDOS', 'jffs2': b'\x85\x19',
       'gzip': b'\x1f\x8b\x08', 'xz': b'\xfd7zXZ', 'bzip2': b'BZh', 'lz4': b'\x04\x22\x4d\x18',
       'andimg': b'ANDROID!', 'sony_fw': b'FirmwareData', 'udtr': b'UDTRFIRM',
       'libupdaterbody': b'libupdaterbody', 'zstd': b'\x28\xb5\x2f\xfd'}
def scan(name, buf):
    out = {}
    for k, m in MAG.items():
        i = buf.find(m)
        if i >= 0:
            out[k] = i
    return out


E['images'] = {'fs_user': {'offset': fsU['offset'], 'size': fsU['size'],
                           'sha256': hashlib.sha256(fs_img).hexdigest(),
                           'magics': scan('fs', fs_img[:1 << 20])},
               'firmware': {'offset': h.firmwareOffset, 'size': h.firmwareSize,
                            'sha256': hashlib.sha256(fw_img).hexdigest(),
                            'magics': scan('fw', fw_img[:1 << 20])}}

# --- the strings that name the model/version
def find_strings(buf, patterns, limit=8):
    res = {}
    for p in patterns:
        hits, pos = [], 0
        while True:
            i = buf.find(p, pos)
            if i < 0:
                break
            hits.append(i)
            pos = i + 1
            if len(hits) >= limit:
                break
        if hits:
            res[p.decode('latin1')] = hits
    return res


PAT = [b'ILCE-', b'ILCA-', b'ILME-', b'DSC-', b'NEX-', b'SLT-', b'FX3', b'FX30', b'7SM3',
       b'7M4', b'91030083', b'910300', b'Sony', b'SONY', b'firmware', b'Firmware',
       b'updater', b'Updater', b'version', b'VERSION']
E['strings'] = {
    'in_stream_first_64MiB': find_strings(st[:64 << 20], PAT),
    'in_fs_image': find_strings(fs_img, PAT),
    'in_firmware_first_64MiB': find_strings(fw_img[:64 << 20], PAT),
    'in_whole_stream': find_strings(st, PAT, limit=5),
}
# examples of readable strings from the file system
def printable_runs(buf, minlen=6, limit=60):
    out, cur = [], bytearray()
    for x in buf:
        if 32 <= x < 127:
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur).decode('latin1'))
            cur = bytearray()
            if len(out) >= limit:
                return out
    return out


E['strings']['fs_examples'] = printable_runs(fs_img, 6, 40)
E['strings']['firmware_examples'] = printable_runs(fw_img[:8 << 20], 6, 40)

# --- control: the instrument "can say ok" and can go red
ctrl = bytearray(open(P, 'rb').read(108 + 2048))
pt = AES.new(KC.key_aes, AES.MODE_ECB).decrypt(bytes(ctrl[108:108 + 1024]))
def frame_ok(p):
    return (sum(int.from_bytes(p[j:j + 2], 'little') for j in range(2, 1024, 2)) & 0xffff) == \
        int.from_bytes(p[0:2], 'little')
E['CONTROL'] = {'real_first_block_frame_ok': frame_ok(pt),
                'flipped_bit_frame_ok': frame_ok(bytearray(pt[:100] + bytes([pt[100] ^ 1]) + pt[101:]))}

with open(ROOT + '/audit/unpack_full.json', 'w') as fh:
    json.dump(E, fh, indent=1, sort_keys=True, default=str)
print(json.dumps(E, indent=1, ensure_ascii=False)[:6000])
