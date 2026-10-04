"""Is the first half of EVERY 1024-byte block legacy-ECB-encrypted (i.e. does plaintext appear there)?"""
import math, collections
from Crypto.Cipher import AES
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
F0,FLEN=108,743818512
f=open(P,'rb')
k_aes=bytes.fromhex('E3B0C44298FC1C149AFBF4C8996FB924')
k_90045=bytes.fromhex('C1AA8F7C46341FFED15589FC8170A6BB5925E85F6282D7F95BA3FDF5D303E06B')
ecb=AES.new(k_aes,AES.MODE_ECB); ecb2=AES.new(k_90045,AES.MODE_ECB)
def H(b):
    c=collections.Counter(b); L=len(b)
    return -sum(v/L*math.log2(v/L) for v in c.values())
print("%-12s %-14s %-14s %-14s %s"%("block","ECB(k_aes) H","double H","raw H","first 24B of ECB(k_aes)"))
for bi in [0,1,2,3,10,100,1000,100000,362000,726000]:
    f.seek(F0+bi*1024); w=f.read(512)
    if len(w)<512: continue
    a=ecb.decrypt(w)
    d=ecb2.decrypt(ecb.decrypt(w))
    print("%-12d %-14.3f %-14.3f %-14.3f %s"%(bi,H(a),H(d),H(w),a[:24].hex()))
# structure of the whole first-block first-half plaintext
f.seek(F0); w=f.read(512); a=ecb.decrypt(w)
print()
print("plaintext[0:512] hex:")
print(a.hex())
print("zeros:",a.count(0),"printable:",sum(1 for c in a if 32<=c<127))
# where are zeros?
runs=[]; i=0
while i<512:
    if a[i]==0:
        j=i
        while j<512 and a[j]==0: j+=1
        if j-i>=8: runs.append((i,j-i))
        i=j
    else: i+=1
print("zero runs >=8:",runs)
