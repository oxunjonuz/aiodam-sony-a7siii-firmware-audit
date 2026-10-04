import binascii, struct
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
size=743818632
crc=0
with open(P,'rb') as f:
    left=size-12
    while left>0:
        b=f.read(min(1<<20,left))
        crc=binascii.crc32(b,crc); left-=len(b)
crc&=0xffffffff
f=open(P,'rb'); f.seek(size-4); stored=f.read(4)
print("computed crc32 over bytes[0:%d] = 0x%08x"%(size-12,crc))
print("stored DEND bytes %s -> BE 0x%08x / LE 0x%08x"%(stored.hex(),struct.unpack('>I',stored)[0],struct.unpack('<I',stored)[0]))
print("RESULT:", "MATCH(BE)" if struct.unpack('>I',stored)[0]==crc else "MISMATCH")
