"""The first 512 plaintext bytes are certain (ECB(key_aes) gives 'UDTRFIRM', '0100', 'U', 'N').
So the block-integrity convention can be *solved*: search definitions/ranges that yield the stored field."""
import struct, binascii, zlib
from Crypto.Cipher import AES
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
f=open(P,'rb'); f.seek(108); ct0=f.read(512)
k_aes=bytes.fromhex('E3B0C44298FC1C149AFBF4C8996FB924')
dec=AES.new(k_aes,AES.MODE_ECB).decrypt(ct0)
targets={'LE16@0':struct.unpack('<H',dec[0:2])[0],'BE16@0':struct.unpack('>H',dec[0:2])[0],
         'LE16@2':struct.unpack('<H',dec[2:4])[0],'BE16@2':struct.unpack('>H',dec[2:4])[0],
         'LE32@0':struct.unpack('<I',dec[0:4])[0],'BE32@0':struct.unpack('>I',dec[0:4])[0]}
print("stored fields in block header:",{k:hex(v) for k,v in targets.items()})

def defs(b):
    out={}
    out['sumLE16']=sum(struct.unpack('<%dH'%(len(b)//2),b[:len(b)//2*2]))&0xffff
    out['sumBE16']=sum(struct.unpack('>%dH'%(len(b)//2),b[:len(b)//2*2]))&0xffff
    out['sumLE16_neg']=(-out['sumLE16'])&0xffff
    out['sumBE16_neg']=(-out['sumBE16'])&0xffff
    out['sumb']=sum(b)&0xffff
    out['xor16']=0
    for w in struct.unpack('<%dH'%(len(b)//2),b[:len(b)//2*2]): out['xor16']^=w
    x=0
    for c in b: x^=c
    out['xorb']=x
    out['crc32lo']=binascii.crc32(b)&0xffff
    out['crc32hi']=(binascii.crc32(b)>>16)&0xffff
    out['adlerlo']=zlib.adler32(b)&0xffff
    out['adlerhi']=(zlib.adler32(b)>>16)&0xffff
    out['crc16ccitt']=binascii.crc_hqx(b,0xffff)
    out['crc16ibm']=binascii.crc_hqx(b,0x0000)
    return out

ranges={'dec[0:512]':dec[0:512],'dec[2:512]':dec[2:512],'dec[4:512]':dec[4:512],
        'dec[0:508]':dec[0:508],'dec[2:510]':dec[2:510],'dec[4:508]':dec[4:508],
        'dec[2:1024] (needs unknown)':None,'ct[0:512]':ct0,'ct[2:512]':ct0[2:512],
        'ct[0:508]':ct0[0:508],'dec[0:4]':dec[0:4]}
hits=[]
for rn,rb in ranges.items():
    if rb is None: continue
    d=defs(rb)
    for dn,v in d.items():
        for tn,tv in targets.items():
            if v==tv: hits.append((rn,dn,tn,hex(v)))
for h in hits: print("HIT:",h)
if not hits: print("no (range,definition) pair in this set reproduces a stored header field ->")
print()
print("dec[0:16]:",dec[0:16].hex())
print("sumLE16(dec[2:512]) = 0x%04x"%defs(dec[2:512])['sumLE16'])
print("sumLE16(dec[2:1024]) is the format's rule; with only 512 known bytes the missing half must supply 0x%04x"%(targets['LE16@0']-defs(dec[2:512])['sumLE16'])&0xffff if False else "")
needed=(targets['LE16@0']-defs(dec[2:512])['sumLE16'])&0xffff
print("if rule=sumLE16 over dec[2:B], the unknown part must sum to 0x%04x (mod 0x10000)"%needed)
