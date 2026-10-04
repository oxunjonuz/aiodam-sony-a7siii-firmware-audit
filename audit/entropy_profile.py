"""Entropy of the body, measured in 1 MiB windows, read from disk in chunks (memory bounded)."""
import numpy as np, math
P='/work/SONY_A7SIII_UPDATE/BODYDATA.DAT'
F0,F1=108,743818620
W=1<<20
hs=[]
f=open(P,'rb'); f.seek(F0); rem=F1-F0
while rem>0:
    b=np.frombuffer(f.read(min(W,rem)),dtype=np.uint8); rem-=len(b)
    c=np.bincount(b,minlength=256).astype(np.float64); p=c/c.sum()
    p=p[p>0]
    hs.append(-(p*np.log2(p)).sum())
hs=np.array(hs)
print("windows(1MiB):",len(hs))
print("min %.6f  max %.6f  mean %.6f  stdev %.6f"%(hs.min(),hs.max(),hs.mean(),hs.std()))
print("windows below 7.999: %d  (indices %s)"%((hs<7.999).sum(), np.where(hs<7.999)[0][:20]))
print("windows below 7.99 : %d"%((hs<7.99).sum()))
print("ideal-random 1MiB window entropy ~ 7.99989; observed min is window %d"%int(hs.argmin()))
np.save('/work/SONY_A7SIII_UPDATE/audit/entropy_windows.npy',hs)
