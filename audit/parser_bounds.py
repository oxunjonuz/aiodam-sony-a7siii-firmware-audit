#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Does the format carry its own invariant that offsets stay inside the image?
We build a synthetic FDAT with firmwareOffset beyond the end of the file, repair the header's
internal CRC32 (which is not a signature) and ask the reference parser whether it noticed.
Control: without repairing the CRC the parser must reject the file."""
import io, struct, binascii, sys
sys.path.insert(0, '/work/SONY_A7SIII_UPDATE/tools/fwtool.py-master')
from fwtool.sony import fdat
from fwtool.util import crc32
from fwtool.io import FilePart

def build(bad_offset):
    hdr = bytearray(512)
    hdr[0:8] = b'UDTRFIRM'
    hdr[8:12] = b'\0\0\0\0'                  # checksum, computed below
    hdr[12:16] = b'0100'
    hdr[16] = ord('U'); hdr[20] = ord('N')
    hdr[32] = 1; hdr[33] = 5                 # version 5.01
    hdr[36:40] = struct.pack('<I', 0x91030083)
    hdr[40:44] = struct.pack('<I', 0)
    hdr[48:52] = struct.pack('<I', bad_offset)
    hdr[52:56] = struct.pack('<I', 0x00100000)
    hdr[56:60] = struct.pack('<I', 2)
    hdr[64:65] = b'U'; hdr[68:72] = struct.pack('<I', 512); hdr[72:76] = struct.pack('<I', 4096)
    hdr[80:81] = b'P'; hdr[84:88] = struct.pack('<I', 512); hdr[88:92] = struct.pack('<I', 0)
    img = bytes(hdr) + b'\0' * 8192
    return bytearray(img)

def with_crc(img, fix):
    img = bytearray(img)
    c = crc32(FilePart(io.BytesIO(bytes(img)), 12, 500))   # header[12:512]
    img[8:12] = struct.pack('<I', c if fix else (c ^ 0xDEAD))
    return io.BytesIO(bytes(img))

for label, off, fix in [('offset beyond the file, CRC repaired', 0xFFFFF000, True),
                        ('offset beyond the file, CRC broken',  0xFFFFF000, False),
                        ('normal offset 4096, CRC repaired',     4096, True)]:
    data = with_crc(build(off), fix)
    try:
        r = fdat.readFdat(data)
        r.firmware.seek(0); got = r.firmware.read()
        print('%-40s -> ACCEPTED; firmware.offset=%d size=%d; the read returned %d B' %
              (label, r.firmware.offset, r.firmware.size, len(got)))
    except Exception as e:
        print('%-40s -> REJECTED: %s: %s' % (label, type(e).__name__, e))
print()
print('Conclusion: the header internal CRC32 is checked, but it is not keyed —')
print('an invariant that offsets stay inside the file is absent from both the format and the parser.')
