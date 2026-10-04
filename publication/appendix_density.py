#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""appendix_density.py — is the appendix table still a table, or has it become a wall of digits?

Why this exists (F169). In the first two editions Appendix A was printed as four columns at
\scriptsize: number, artifact, description, artifact sha256. Measured on that printed PDF, the mono
character is 5.038 pt wide, so the number column (0.24\textwidth) held 22 characters per line: a
64-hex sha256 needed three lines, and the sha256 column printed its 16 characters in fragments that
all started at the same x. The owner described the result as "a grid of ones" on pages 14-15.
layout_check.py could not see it: there is no overlap and no overflow — the text simply sits inside
columns too narrow for it. Round 282 regrouped the table by artifact into two wide columns.

What it measures, per page of the printed appendix: the rows (cells of the first column) and, for each
row, how many text lines the row is tall (baselines between this row's top and the next row's top).
A row that is several lines tall is the signature of a column too narrow for its content, and the
worst row is what a reader trips over.

Limits: no row may be taller than 3 lines, and the mean must stay at or below 2.5.

Control: a synthetic document with six rows, one of which holds sixty words in a 0.50\textwidth cell,
is built and measured with the same code. The instrument must report a row over the limit for it; if
it cannot, it proves nothing. (The first version of this control used one 200-character word — it was
blind, because an unbreakable token overflows the column instead of wrapping it. That is a different
defect, and it is layout_check's business.)

Run:  python3 publication/appendix_density.py [path to PDF]
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PDF = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'paper', 'main.pdf')
MAX_ROW_LINES = 3.0
MAX_MEAN_LINES = 2.5


def page_boxes(pdf):
    xml = subprocess.run(['pdftotext', '-bbox-layout', pdf, '-'],
                         capture_output=True, text=True).stdout
    out = []
    for page in xml.split('<page')[1:]:
        words = re.findall(
            r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" yMax="([\d.]+)">(.*?)</word>',
            page)
        out.append([(float(a), float(b), float(c), float(d), w) for a, b, c, d, w in words])
    return out


def header_baseline(words):
    """The y of the appendix table's header row ('number' and 'what' on one baseline), or None.
    Everything above that baseline is prose, and must not be counted as table rows."""
    rows = {}
    for _, y0, _, _, w in words:
        rows.setdefault(round(y0, 1), set()).add(w)
    ys = [y for y, v in rows.items() if 'number' in v and 'what' in v]
    return min(ys) if ys else None


def measure(pages):
    """[(page_no, rows, [(lines per row)], max, mean)] for the appendix pages."""
    out = []
    for pi, words in enumerate(pages, 1):
        if not words:
            continue
        head_y = header_baseline(words)
        if head_y is None:
            continue
        left = min(x0 for x0, _, _, _, _ in words)
        first_col = sorted({round(y0, 1) for x0, y0, _, _, _ in words
                            if x0 < left + 6 and y0 > head_y + 2})
        merged = []
        for y in first_col:
            if merged and y - merged[-1] < 6.5:       # a wrapped cell, not a new row
                continue
            merged.append(y)
        if len(merged) < 3:
            continue
        baselines = sorted({round(y0, 1) for _, y0, _, _, _ in words})
        # The last row has no next row to bound it: bound it by the bottom of ITS OWN first-column
        # cell, so that prose printed below the table is not counted as row height.
        last_bottom = max((y1 for x0, y0, _, y1, _ in words if x0 < left + 6 and y0 >= merged[-1] - 6),
                          default=merged[-1])
        per_row = []
        for i, top in enumerate(merged):
            bottom = merged[i + 1] - 6.5 if i + 1 < len(merged) else last_bottom + 6
            per_row.append(sum(1 for y in baselines if top - 6 <= y < bottom))
        out.append((pi, len(merged), per_row, max(per_row), sum(per_row) / len(per_row)))
    return out


def build_control():
    """Six rows, one of them over-full: the instrument must see it."""
    src = (r'\documentclass[12pt]{article}' '\n'
           r'\usepackage[a4paper,margin=0.92in]{geometry}' '\n'
           r'\usepackage{fontspec}' '\n'
           r'\setmainfont{TeX Gyre Pagella}' '\n'
           r'\setmonofont{DejaVu Sans Mono}' '\n'
           r'\begin{document}' '\n'
           r'\begingroup\scriptsize\begin{tabular}{p{0.46\textwidth}p{0.50\textwidth}}' '\n'
           r'number & what it is \\' '\n'
           r'1 & ' + ('word ' * 60) + r' \\' '\n'
           + ''.join(r'%d & a short cell \\' '\n' % i for i in range(2, 7)) +
           r'\end{tabular}\endgroup' '\n'
           r'\end{document}' '\n')
    tmp = tempfile.mkdtemp(prefix='appendix_density_')
    open(os.path.join(tmp, 'c.tex'), 'w').write(src)
    subprocess.run(['xelatex', '-interaction=nonstopmode', 'c.tex'], cwd=tmp,
                   capture_output=True, text=True, timeout=300)
    pdf = os.path.join(tmp, 'c.pdf')
    return pdf if os.path.exists(pdf) else None


def main():
    if not os.path.exists(PDF):
        print('NO SUCH FILE: %s' % PDF)
        return 2
    rows = measure(page_boxes(PDF))
    if not rows:
        print('the appendix table was not found in %s' % PDF)
        return 2
    print('appendix pages found: %d' % len(rows))
    total_rows = sum(r for _, r, _, _, _ in rows)
    worst = max(mx for _, _, _, mx, _ in rows)
    mean = sum(m for _, _, _, _, m in rows) / len(rows)
    for pi, r, per_row, mx, m in rows:
        print('   page %d: rows=%-4d tallest row=%.0f line(s)  mean=%.2f%s'
              % (pi, r, mx, m, '   <- over the limit' if mx > MAX_ROW_LINES else ''))
    print('tallest row anywhere: %.0f line(s) (limit %.0f); mean of means: %.2f (limit %.1f)'
          % (worst, MAX_ROW_LINES, mean, MAX_MEAN_LINES))

    ctrl_pdf = build_control()
    ctrl = measure(page_boxes(ctrl_pdf)) if ctrl_pdf else []
    ctrl_worst = max([mx for _, _, _, mx, _ in ctrl], default=0.0)
    print('CONTROL (a row of sixty words must measure over the limit): %.0f line(s) -> %s'
          % (ctrl_worst, 'fires' if ctrl_worst > MAX_ROW_LINES else 'BLIND'))
    ok = worst <= MAX_ROW_LINES and mean <= MAX_MEAN_LINES and ctrl_worst > MAX_ROW_LINES
    print('RESULT: %s' % ('THE APPENDIX IS STILL A TABLE' if ok else 'THE APPENDIX IS TOO TIGHT'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
