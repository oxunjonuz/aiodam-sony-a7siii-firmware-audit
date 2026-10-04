#!/usr/bin/env python3
"""F158 tool: extract every \\code/\\lc/\\lcf/\\hx/\\hl token from a .tex file,
normalise it (drop \\allowbreak, unescape \\_, collapse whitespace) and compare
two files.  Used to localise the F158 loss: which tokens exist in the Russian
source but not in the English one."""
import re, sys, collections

MACRO = re.compile(r'\\(code|lcf|lc|hx|hl)\{([^{}]*)\}')

def norm(s):
    s = s.replace('\\allowbreak', '')
    s = s.replace('\\_', '_')
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def tokens(path):
    t = open(path, encoding='utf-8').read()
    return [(m.group(1), m.group(2), norm(m.group(2))) for m in MACRO.finditer(t)]

if __name__ == '__main__':
    a, b = sys.argv[1], sys.argv[2]
    A, B = tokens(a), tokens(b)
    ca = collections.Counter(n for _, _, n in A)
    cb = collections.Counter(n for _, _, n in B)
    fa = collections.Counter(m for m, _, _ in A)
    fb = collections.Counter(m for m, _, _ in B)
    print(f'{a}: {len(A)} tokens {dict(fa)}')
    print(f'{b}: {len(B)} tokens {dict(fb)}')
    only_a = {k: v for k, v in ca.items() if k not in cb}
    only_b = {k: v for k, v in cb.items() if k not in ca}
    def flags(k):
        return ('sp' if ' ' in k else '--') + ('/' if '/' in k else '-') + ('_' if '_' in k else '-')
    print(f'\n=== {len(only_a)} tokens present in SOURCE only (lost) ===')
    for k in sorted(only_a, key=lambda x: -len(x)):
        print(f'  len={len(k):3d} n={ca[k]} {flags(k)}  {k!r}')
    print(f'\n=== {len(only_b)} tokens present in DERIVED only (added) ===')
    for k in sorted(only_b, key=lambda x: -len(x)):
        print(f'  len={len(k):3d} n={cb[k]} {flags(k)}  {k!r}')
    common = [k for k in ca if k in cb and len(k) >= 10]
    print(f'\n=== {len(common)} common tokens of length >= 10 (contrast set) ===')
    for k in sorted(common, key=lambda x: -len(x)):
        print(f'  len={len(k):3d} {flags(k)}  {k!r}')
