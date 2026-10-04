#!/usr/bin/env python3
"""F158 tool 3: classify every code-like token of the Russian manuscript by its
RAW source length (as written, \\allowbreak included) and say whether the English
edition kept it.  This is the tool that tests the "long tokens were dropped" rule."""
import re, sys, collections

MACRO = re.compile(r'\\(code|lcf|lc|hx|hl)\{([^{}]*)\}')

def norm(s):
    s = s.replace('\\allowbreak', '').replace('\\_', '_')
    return re.sub(r'\s+', ' ', s).strip()

ru_path, en_path = sys.argv[1], sys.argv[2]
ru = open(ru_path, encoding='utf-8').read()
en = open(en_path, encoding='utf-8').read()
en_set = collections.Counter(norm(m.group(2)) for m in MACRO.finditer(en))

rows = []
for ln, line in enumerate(ru.split('\n'), 1):
    for m in MACRO.finditer(line):
        raw, macro = m.group(2), m.group(1)
        rows.append((len(raw), macro, raw, norm(raw), ln))

rows.sort(reverse=True)
print(f'{"rawlen":>6} {"macro":>5} {"kept":>5}  rendered')
for rawlen, macro, raw, n, ln in rows:
    kept = 'YES' if en_set[n] > 0 else '**NO**'
    print(f'{rawlen:>6} {macro:>5} {kept:>6}  L{ln:<4} {n!r}')

# the rule test
print('\n--- rule test: every token with raw length >= T lost? ---')
for T in range(20, 80):
    viol = [(r[0], r[1], r[3]) for r in rows if r[0] >= T and en_set[r[3]] > 0]
    miss = [(r[0], r[1], r[3]) for r in rows if r[0] < T and en_set[r[3]] == 0]
    if not viol and not miss:
        print(f'  T={T}: PERFECT separation')
    elif len(viol) <= 3 and len(miss) <= 3:
        print(f'  T={T}: kept-above={len(viol)} lost-below={len(miss)} :: {viol} {miss}')
