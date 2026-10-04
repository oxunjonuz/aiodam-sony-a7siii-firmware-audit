import numpy as np, os
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
F0,F1=108,743818620
plen=F1-F0
N=plen//16
print("payload",plen,"blocks",N)
fp=np.memmap('/tmp/fp.dat',dtype=np.uint64,mode='w+',shape=(N,))
f=open(P,'rb'); f.seek(F0)
M=np.uint64(1099511628211); C=np.uint64(0xcbf29ce484222325)
CH=1<<22  # 4MiB -> 262144 blocks
done=0
while done<N:
    want=min(CH,N-done)
    raw=f.read(want*16)
    b=np.frombuffer(raw,dtype=np.uint8).reshape(want,16)
    acc=np.full(want,C,dtype=np.uint64)
    for j in range(16):
        acc=acc*M+b[:,j].astype(np.uint64)
    fp[done:done+want]=acc
    done+=want
fp.flush()
print("filled",done)
u,c=np.unique(np.asarray(fp),return_counts=True)
print("distinct",len(u),"repeat_extra",int(c.sum()-len(u)))
rep=c[c>1]
print("fs with count>1:",int((c>1).sum()),"max count",int(rep.max()) if len(rep) else 0)
order=np.argsort(c)[::-1][:25]
for o in order:
    if c[o]<2: break
    print("   count=%d fp=%016x"%(int(c[o]),int(u[o])))
eq=(np.asarray(fp[1:])==np.asarray(fp[:-1]))
runs=[];i=0
while i<len(eq):
    if eq[i]:
        j=i
        while j<len(eq) and eq[j]: j+=1
        runs.append((i,j-i+1)); i=j
    else: i+=1
print("consecutive-equal runs:",len(runs))
runs.sort(key=lambda r:-r[1])
for s,l in runs[:25]:
    print("   payload_off=%d file_off=%d blocks=%d bytes=%d"%(s*16,F0+s*16,l+1,(l+1)*16))
