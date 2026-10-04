"""Which scheme produces the FDAT block that satisfies BOTH checks the format defines?
Oracle A: per-block checksum (sum of LE16 words over dec[2:] & 0xffff == LE16(dec[0:2]))
Oracle B: FDAT header crc32 over header[12:512] == header.checksum  (header = dec[4:])
Only the 4 bytes dec[512:516] are uncertain, so Oracle B is nearly a direct test."""
import struct, binascii
from Crypto.Cipher import AES
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
F0,FLEN=108,743818512
f=open(P,'rb'); f.seek(F0); ct=f.read(4096)
f.seek(F0+FLEN-0x110); foot=f.read(0x110); IV=foot[:16]
k_aes  =bytes.fromhex('E3B0C44298FC1C149AFBF4C8996FB924')
k_90014=bytes.fromhex('E8B0886D97184F1F65C767F7939965BF')
k_90045=bytes.fromhex('C1AA8F7C46341FFED15589FC8170A6BB5925E85F6282D7F95BA3FDF5D303E06B')
Z=bytes(16)
head_plain = ct[0:512]                      # ECB(k_aes) region -- established
dec_first  = AES.new(k_aes,AES.MODE_ECB).decrypt(head_plain)
target_crc = struct.unpack('<I',dec_first[12:16])[0]
print("block hdr: checksum=0x%04x sizeAndFlag=0x%04x"%struct.unpack('<HH',dec_first[0:4]))
print("UDTRFIRM at dec[4:12]:",dec_first[4:12])
print("header.checksum (LE32 @dec[12]) = 0x%08x"%target_crc)

def crc_ok(dec):
    return binascii.crc32(dec[16:516])&0xffffffff==target_crc
def sum_ok(dec):
    ck=struct.unpack('<H',dec[0:2])[0]
    s=sum(struct.unpack('<511H',dec[2:1024]))&0xffff
    return ck,s

def cbc(key,iv,data): return AES.new(key,AES.MODE_CBC,iv).decrypt(data)
def ctr(key,iv,data):
    from Crypto.Util import Counter
    c=AES.new(key,AES.MODE_CTR,counter=Counter.new(128,initial_value=int.from_bytes(iv,'big')))
    return c.decrypt(data)
def ecb(key,data): return AES.new(key,AES.MODE_ECB).decrypt(data)

def cfb(key,iv,data): return AES.new(key,AES.MODE_CFB,iv=iv,segment_size=128).decrypt(data)
def ofb(key,iv,data): return AES.new(key,AES.MODE_OFB,iv=iv).decrypt(data)

cands=[]
cands.append(("ecb_aes(whole blk)",  dec_first+AES.new(k_aes,AES.MODE_ECB).decrypt(ct[512:1024])))
cands.append(("doubleAes",           dec_first+AES.new(k_90014,AES.MODE_ECB).decrypt(AES.new(k_aes,AES.MODE_ECB).decrypt(ct[512:1024]))))
cands.append(("cbc90045(IV)",        dec_first+cbc(k_90045,IV,ct[512:1024])))
cands.append(("cbc90045(zeroIV)",    dec_first+cbc(k_90045,Z,ct[512:1024])))
cands.append(("cbc_aes(IV)",         dec_first+cbc(k_aes,IV,ct[512:1024])))
cands.append(("ecb90045",            dec_first+ecb(k_90045,ct[512:1024])))
cands.append(("ecb90014",            dec_first+ecb(k_90014,ct[512:1024])))
cands.append(("plaintext tail",      dec_first+ct[512:1024]))
cands.append(("ctr90045(IV)",        dec_first+ctr(k_90045,IV,ct[512:1024])))
cands.append(("ctr_aes(IV)",         dec_first+ctr(k_aes,IV,ct[512:1024])))
cands.append(("cfb_aes(IV)",         dec_first+cfb(k_aes,IV,ct[512:1024])))
cands.append(("ofb_aes(IV)",         dec_first+ofb(k_aes,IV,ct[512:1024])))
cands.append(("cfb90045(IV)",        dec_first+cfb(k_90045,IV,ct[512:1024])))
cands.append(("ofb90045(IV)",        dec_first+ofb(k_90045,IV,ct[512:1024])))
for n,d in cands:
    ck,s=sum_ok(d)
    print("%-20s crcA=%s summatch=%s(0x%04x/0x%04x) tail=%s"%(n,crc_ok(d),ck==s,ck,s,d[512:528].hex()))
