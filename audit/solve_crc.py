"""Solve for the 4 plaintext bytes the format's own header-CRC demands.
crc32 is affine in a 4-byte suffix, and the map from those 4 bytes to the checksum is a
bijection, so the FDAT header checksum *determines* plaintext[508:512] uniquely.
Then ask what those bytes look like (a file-system magic would confirm the reconstruction)."""
import binascii, struct
from Crypto.Cipher import AES
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
f=open(P,'rb'); f.seek(108); ct=f.read(512)
k_aes=bytes.fromhex('E3B0C44298FC1C149AFBF4C8996FB924')
dec=AES.new(k_aes,AES.MODE_ECB).decrypt(ct)
target=struct.unpack('<I',dec[12:16])[0]
prefix=dec[16:512]          # header[12:508]
def cc(x): return binascii.crc32(prefix+x)&0xffffffff
c0=cc(b'\x00\x00\x00\x00')
# linear map columns: effect of each of the 32 bits of X
cols=[]
for i in range(32):
    x=bytearray(4); x[i//8]|=1<<(i%8)
    cols.append(cc(bytes(x))^c0)
# solve for X: XOR of cols where bit set == target^c0
want=target^c0
sol=0
# gaussian elimination over GF(2) with 32 unknowns, 32 equations (bit positions)
basis={}   # pivot bit -> (mask, value_mask)
rows=[(cols[i],1<<i) for i in range(32)]
for col,bit in rows:
    c=col
    b=bit
    # reduce by existing basis
    for p in list(basis):
        if c>>p & 1:
            c^=basis[p][0]; b^=basis[p][1]
    if c:
        p=c.bit_length()-1
        basis[p]=(c,b)
# build solution vector for "want"
x=0; v=want
for p in sorted(basis,reverse=True):
    if v>>p & 1:
        v^=basis[p][0]; x^=basis[p][1]
assert v==0, "not solvable"
X=x.to_bytes(4,'little')
print("header.checksum (stored)     = 0x%08x"%target)
print("required plaintext[508:512]  = %s  (LE %s)"%(X.hex(), [hex(b) for b in X]))
print("crc32 check with that value  = 0x%08x  -> %s"%(cc(X),"MATCH" if cc(X)==target else "MISMATCH"))
print()
print("interpretation attempts:")
print("  as ascii      :",repr(X))
print("  as BE u32     : 0x%08x"%struct.unpack('>I',X)[0])
print("  as LE u32     : 0x%08x"%struct.unpack('<I',X)[0])
print("  fs magics: cramfs(LE)=453dcd28 squashfs='hsqs' ext2@1080 '53ef' ubi='UBI#' romfs='-rom1fs-'")
print()
print("candidate first-4-bytes of the file system, for comparison:")
print("  the file system starts at stream offset 512 = plaintext[516:520] (different bytes, still unknown)")
