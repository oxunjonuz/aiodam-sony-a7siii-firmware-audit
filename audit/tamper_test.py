"""Is the container's integrity check an authenticity check? (CWE-345 / CWE-353)
Copy the file, flip one byte inside the encrypted body, recompute DEND.crc, and ask the
reference parser to accept the container.  Control: the same flip WITHOUT the CRC fix must be rejected.
NOTE (instrument bug found in run 1): the CRC must be computed after the flip is flushed to disk,
otherwise you measure the file as it was before the flip."""
import binascii, shutil, struct, sys, os
SRC='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
sys.path.insert(0,'/work/SONY_A7SIII_UPDATE/tools/fwtool.py-master')
from fwtool.sony import dat
from fwtool.util import crc32
from fwtool.io import FilePart

def stored_crc(path):
    with open(path,'rb') as f: f.seek(os.path.getsize(path)-4); return struct.unpack('>I',f.read(4))[0]

def flip(src,dst,off,fixcrc):
    shutil.copyfile(src,dst)
    with open(dst,'r+b') as f:
        f.seek(off); b=f.read(1); f.seek(off); f.write(bytes([b[0]^0x01])); f.flush(); os.fsync(f.fileno())
    if fixcrc:
        n=os.path.getsize(dst)
        with open(dst,'r+b') as f:
            c=crc32(FilePart(f,0,n-12))
            f.seek(n-4); f.write(struct.pack('>I',c)); f.flush(); os.fsync(f.fileno())
        return c
    return None

OFF=108+4096
c_new=flip(SRC,'/tmp/tamper_fixed.DAT',OFF,True)
flip(SRC,'/tmp/tamper_raw.DAT',OFF,False)
print("original stored crc : 0x%08x"%stored_crc(SRC))
print("tampered stored crc : 0x%08x (recomputed over the tampered bytes)"%stored_crc('/tmp/tamper_fixed.DAT'))
print()
for name,path in [("tampered + CRC re-fixed",'/tmp/tamper_fixed.DAT'),
                  ("tampered, CRC untouched",'/tmp/tamper_raw.DAT')]:
    f=open(path,'rb')
    try:
        d=dat.readDat(f); r="ACCEPTED by reference parser (readDat returned; firmwareData.size=%d)"%d.firmwareData.size
    except Exception as e:
        r="REJECTED: %s: %s"%(type(e).__name__,e)
    print("%-26s %s"%(name,r))
