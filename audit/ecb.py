import numpy as np, collections, math, sys
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
F0,F1=108,743818620
f=np.frombuffer(open(P,'rb').read(),dtype=np.uint8)  # whole file in RAM 710MB
pay=f[F0:F1]
N=len(pay)//16
blk=pay[:N*16].reshape(N,16).astype(np.uint64)
fp=np.zeros(N,dtype=np.uint64)
M=np.uint64(1099511628211); C=np.uint64(0xcbf29ce484222325)
for j in range(16):
    fp=fp*M + blk[:,j] + C
del blk
print("blocks",N)
u,c=np.unique(fp,return_counts=True)
print("distinct",len(u),"repeats_total",int(c.sum()-len(u)))
rep=c[c>1]
print("blocks with count>1:",len(rep),"max count",int(rep.max()) if len(rep) else 0)
# top repeated
order=np.argsort(c)[::-1][:20]
print("top repeated fingerprints:")
for o in order:
    if c[o]<2: break
    print("  count=%d fp=%x"%(c[o],u[o]))
# consecutive equal runs
eq=(fp[1:]==fp[:-1])
runs=[]
i=0
while i<len(eq):
    if eq[i]:
        j=i
        while j<len(eq) and eq[j]: j+=1
        runs.append((i, j-i+1))  # start block index, run length in equalities => run of j-i+2 equal blocks
        i=j
    else: i+=1
print("equal-consecutive runs:",len(runs))
tot=sum(r[1] for r in runs)
print("total consecutive-equal pairs:",tot)
runs.sort(key=lambda r:-r[1])
for s,l in runs[:20]:
    print("  payload_off=%d file_off=%d len_blocks=%d (%d bytes)"%(s*16, F0+s*16, l+1, (l+1)*16))
np.save('/tmp/fp.npy',fp)
