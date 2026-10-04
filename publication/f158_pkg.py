#!/usr/bin/env python3
"""F158 tool 4: did the round-282 package translation drop tokens the same way?

For every file present both in the pre-translation snapshot (the tgz, Russian)
and in the delivered English tree, pull every ASCII token that looks like an
artifact name (contains _ or / or . and is >= 6 chars) and report those present
in the Russian file but absent from the English one, with their lengths.
"""
import os, re, sys, collections

ROOTS = [('/tmp/tgzfull/work/SONY_A7SIII_UPDATE', '/work/SONY_A7SIII_UPDATE')]
TOK = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_./\\-]{4,}')
# keep only tokens that look like file/artifact names
def interesting(t):
    return ('_' in t or '/' in t or '.' in t) and re.search(r'[A-Za-z]{2}', t) \
           and not t.startswith(('http', 'www'))

def toks(path):
    try:
        t = open(path, encoding='utf-8', errors='replace').read()
    except Exception:
        return collections.Counter()
    c = collections.Counter()
    for m in TOK.finditer(t):
        s = m.group(0).replace('\\_', '_').replace('\\allowbreak', '')
        if interesting(s):
            c[s] += 1
    return c

missing_rows = []
for ru_root, en_root in ROOTS:
    for dp, dn, fn in os.walk(ru_root):
        for f in fn:
            ru = os.path.join(dp, f)
            rel = os.path.relpath(ru, ru_root)
            en = os.path.join(en_root, rel)
            if not os.path.exists(en):
                continue
            if os.path.getsize(ru) > 2_000_000:
                continue
            a, b = toks(ru), toks(en)
            for k, n in a.items():
                if b[k] == 0:
                    missing_rows.append((rel, k, n))

missing_rows.sort(key=lambda r: -len(r[1]))
print(f'{len(missing_rows)} artifact-like tokens present in the Russian file and absent from the English one')
for rel, k, n in missing_rows[:120]:
    print(f'  len={len(k):3d} n={n} {rel:52s} {k!r}')
