#!/usr/bin/env python3
"""F158 tool 2: list every code-like token of a .tex file with its line number,
in order, so two files (source RU, derived EN) can be aligned by eye."""
import re, sys

MACRO = re.compile(r'\\(code|lcf|lc|hx|hl)\{([^{}]*)\}')

def norm(s):
    s = s.replace('\\allowbreak', '')
    s = s.replace('\\_', '_')
    return re.sub(r'\s+', ' ', s).strip()

path = sys.argv[1]
lines = open(path, encoding='utf-8').read().split('\n')
i = 0
for ln, line in enumerate(lines, 1):
    for m in MACRO.finditer(line):
        i += 1
        print(f'{i:4d} L{ln:4d} \\{m.group(1):5s} {norm(m.group(2))!r}')
print(f'TOTAL {i}')
