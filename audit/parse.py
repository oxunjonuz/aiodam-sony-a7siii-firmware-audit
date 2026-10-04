import struct, sys, os, hashlib, zlib, collections, math

P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
d=open(P,'rb').read()
n=len(d)
print("size", n, hex(n))

MAGIC=b'\x89UFU\r\n\x1a\n'
print("magic at 0:", d[:8]==MAGIC)

# TLV parse
off=8
items=[]
while off+8<=n:
    ln=struct.unpack('>I',d[off:off+4])[0]
    tag=d[off+4:off+8]
    if not tag.isascii() or not all(32<=c<127 for c in tag):
        print("stop: tag not ascii at",off,tag); break
    pl=d[off+8:off+8+ln]
    items.append((off,ln,tag,off+8,off+8+ln))
    print(f"off={off:>12} len={ln:>12} tag={tag.decode(errors='replace')!r} payload=[{off+8},{off+8+ln})")
    off=off+8+ln
    if off>=n: break
print("final off",off,"remaining",n-off)
print("tail bytes:", d[off:].hex())
