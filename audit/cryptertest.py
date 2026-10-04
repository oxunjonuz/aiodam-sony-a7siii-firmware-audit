"""Apply every crypter known to the reference tool fwtool.py to BODYDATA.DAT's FDAT chunk.
Prediction under test: the FDAT block decrypts with AesCbcCrypter (CXD90045)."""
import struct, hashlib, io
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor

P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
F0,FLEN=108,743818512
f=open(P,'rb'); f.seek(F0); ct=f.read(2048)
f.seek(F0+FLEN-0x110); footer=f.read(0x110); iv=footer[:16]
print("payload len %d = 1024*%d + %d  (remainder 0x110=272 -> %s)"%(FLEN,FLEN//1024,FLEN%1024,FLEN%1024==272))
print("footer last 0x110 bytes, IV(16) =",iv.hex()," rest non-zero bytes:",sum(1 for b in footer[16:] if b))

def crc_block(dec):
    ck=struct.unpack('<H',dec[0:2])[0]
    sz=(struct.unpack('<H',dec[2:4])[0])
    end=bool(sz&0x8000); size=sz&0x7fff
    s=sum(struct.unpack('<%dH'%((len(dec)-2)//2),dec[2:2+2*((len(dec)-2)//2)]))&0xffff
    return ck,s,end,size

k_aes=bytes.fromhex('E3B0C44298FC1C149AFBF4C8996FB924')
k_90014=bytes.fromhex('E8B0886D97184F1F65C767F7939965BF')
k_90045=bytes.fromhex('C1AA8F7C46341FFED15589FC8170A6BB5925E85F6282D7F95BA3FDF5D303E06B')
keys={
 'CXD4105_sha':('CXD4105',bytes.fromhex('7E4D09C323F783BFAF65E7E388B2FA9D9057417EBF28D48E51629AF27BD30B6495B184A695A83F01')),
 'CXD4115_sha':('CXD4115',bytes.fromhex('E7CEEAF000DAEB4A00213B28EF5DDEC3FACF3C845EA6783DFFA177889E47F4FAF0D9717A4AC390CF')),
 'MB8AC102_sha':('CXD4105',bytes.fromhex('7E4D09C323F783BFAF65E7E388B2FA9D9057417EBF28D48E51629AF27BD30B6495B184A695A83F01')),
}
def sha_decrypt(ct,block,key):
    out=bytearray(); digest=key[:20]; pos=0
    while pos<len(ct):
        ks=bytearray()
        while len(ks)<block:
            digest=hashlib.sha1(digest+key[20:40]).digest(); ks+=digest
        chunk=ct[pos:pos+block]
        out+=strxor(chunk,bytes(ks[:len(chunk)])); pos+=block
    return bytes(out)

def report(name,raw):
    if raw is None: print("%-22s : no output"%name); return
    ck,s,end,size=crc_block(raw)
    magic=raw[4:12]
    ok_sum = s==ck
    print("%-22s : magic=%r  sum_ok=%s  endFlag=%s  size=%d"%(name,magic,ok_sum,end,size))

# 1) CXD4132: AES-ECB 1024 blocks, key_aes
c=AES.new(k_aes,AES.MODE_ECB); report('CXD4132 (AesECB)',c.decrypt(ct[:1024])+c.decrypt(ct[1024:2048]))
# 2) CXD90014: DoubleAes 1024
c1=AES.new(k_aes,AES.MODE_ECB); c2=AES.new(k_90014,AES.MODE_ECB)
r=c1.decrypt(ct); d=c2.decrypt(r); report('CXD90014 (DoubleAes)',r[:512]+d[512:1024])
# 3) CXD90045: AES-CBC 1024 first block split at 512, IV from -0x110
c1=AES.new(k_aes,AES.MODE_ECB); c2=AES.new(k_90045,AES.MODE_CBC,iv)
b0=c1.decrypt(ct[0:512])+c2.decrypt(ct[512:1024])
b1=c2.decrypt(ct[1024:2048])
report('CXD90045 (AesCbc)',b0+b1)
# 4) SHA crypters, 1000-byte blocks
for name,(kn,key) in keys.items():
    raw=sha_decrypt(ct[:2000],1000,key)
    report(name+' sha',raw[:1000]+raw[1000:2000])
print()
print("raw first 32 bytes of CXD90045 plaintext:",b0[:32].hex())
print("ascii:",repr(b0[:64]))
