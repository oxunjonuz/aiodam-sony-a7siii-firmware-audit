import struct, math, collections, hashlib, zlib
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
d=open(P,'rb').read()
n=len(d)
F0,F1=108,743818620
f=d[F0:F1]
print("FDAT len",len(f))

def H(b):
    c=collections.Counter(b); L=len(b)
    return -sum(v/L*math.log2(v/L) for v in c.values())

# entropy in 64KiB blocks
B=65536
hs=[]
for i in range(0,len(f),B):
    hs.append(H(f[i:i+B]))
print("blocks",len(hs))
print("min %.4f max %.4f mean %.4f"%(min(hs),max(hs),sum(hs)/len(hs)))
# histogram of entropies
import statistics
print("stdev %.5f"%statistics.pstdev(hs))
print("first 24:", [round(x,3) for x in hs[:24]])
print("last 24:", [round(x,3) for x in hs[-24:]])
# count blocks below 7.99
low=[(i*B,round(h,4)) for i,h in enumerate(hs) if h<7.98]
print("blocks < 7.98 bits:", len(low), low[:20])

# repeated 16-byte blocks (ECB detection)
seen={}
rep=0
reps=[]
for i in range(0,len(f)-16+1,16):
    blk=f[i:i+16]
    if blk in seen:
        rep+=1
        if len(reps)<20: reps.append((seen[blk],i,blk.hex()))
    else:
        seen[blk]=i
print("16B blocks total",len(seen)+rep,"repeats",rep)
for a,b,h in reps[:20]:
    print("  repeat at",b,"of block first seen at",a,h)

# magic inside
print("magic inside:", [m for m in range(0)] )
idx=[]; p=f.find(b'\x89UFU\r\n\x1a\n')
while p>=0 and len(idx)<20:
    idx.append(p+F0); p=f.find(b'\x89UFU\r\n\x1a\n',p+1)
print("inner UFU magics at:",idx)

# trailer tests
trail=d[743818628:743818632]
print("trailer",trail.hex())
for name,val in [("crc32 whole",zlib.crc32(d)),("crc32 fdat",zlib.crc32(f)),
                 ("crc32 head+fdat",zlib.crc32(d[:F1])),
                 ("adler32 whole",zlib.adler32(d)),("adler32 fdat",zlib.adler32(f))]:
    print(" %s = %08x"%(name,val), "match" if struct.pack('>I',val)==trail or struct.pack('<I',val)==trail else "")
md5=hashlib.md5(d).hexdigest(); sha=hashlib.sha256(d).hexdigest()
print("md5",md5,"sha256",sha)
print("md5 head match?", md5[:8]==trail.hex(), "sha head?", sha[:8]==trail.hex())
