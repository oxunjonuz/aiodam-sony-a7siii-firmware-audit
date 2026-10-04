#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""layout_check.py — layout check of the printed PDF: letters on top of letters, and overflow
past the margin.

Why a separate instrument: TeX reports overflow only as "Overfull \\hbox", and not in every
case (inside a p{} column it prints a different warning, and microtype protrusion pushes edge
glyphs into the margin in complete silence). As for "letters of one cell on top of the letters
of another", TeX never reports it at all — it is visible only on the page.

Two routes of different nature; both must come out clean:

  A. WORD BOXES from the PDF itself (pdftotext -bbox-layout, poppler). Within a line words
     are sorted by x; if neighbouring boxes overlap by more than TOL_OVERLAP_PT, the letters
     of one cell lie on top of the letters of another. The same route catches overflow past
     the type area.
  B. RASTER INK (pdftoppm -> PIL). The bounding box of all non-empty page pixels.
     The route knows nothing about how the PDF describes glyphs: it looks at what is printed.

The thresholds are calibrated by measurement in selftest_layout.py, not picked by eye.

Run: python3 publication/layout_check.py [path to PDF]
"""
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PDF = os.path.join(HERE, 'paper', 'main.pdf')
TOL_OVERLAP_PT = 1.0     # overlap of two word boxes: this is exactly "letters on letters"
TOL_MARGIN_PT = 4.0      # overflow tolerance: optical protrusion reaches 2.3 pt (measured)
SAFE_PT = 36.0           # safe frame of the sheet (0.5 in): no ink should fall outside it


def words_from_pdf(pdf):
    """Route A: word boxes from the PDF."""
    with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as fh:
        tmp = fh.name
    try:
        subprocess.run(['pdftotext', '-bbox-layout', pdf, tmp], check=True,
                       capture_output=True)
        html = open(tmp, encoding='utf-8', errors='replace').read()
    finally:
        os.unlink(tmp)
    pages = []
    for pm in re.finditer(r'<page width="([\d.]+)" height="([\d.]+)">(.*?)</page>', html,
                          re.S):
        W, H, body = float(pm.group(1)), float(pm.group(2)), pm.group(3)
        lines = []
        for lm in re.finditer(r'<line[^>]*>(.*?)</line>', body, re.S):
            ws = [(float(a), float(b), float(c), float(d), e) for a, b, c, d, e in
                  re.findall(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" '
                             r'yMax="([\d.]+)">([^<]*)</word>', lm.group(1))]
            if ws:
                lines.append(ws)
        widows = [(float(a), float(b), float(c), float(d), e) for a, b, c, d, e in
                  re.findall(r'<word xMin="([\d.]+)" yMin="([\d.]+)" xMax="([\d.]+)" '
                             r'yMax="([\d.]+)">([^<]*)</word>',
                             re.sub(r'<line.*?</line>', '', body, flags=re.S))]
        pages.append({'width': W, 'height': H, 'lines': lines, 'loose': widows})
    return pages


def overlaps(pages, tol=TOL_OVERLAP_PT):
    """Any pair of boxes on a page that overlap in both x and y.

    Not only neighbours within a line are compared: the letters of one table cell may lie on
    top of the letters of the next one, and that is the same defect. The pair sweeps along x
    and the y overlap is tested inside the pair.
    """
    bad = []
    for pno, pg in enumerate(pages, 1):
        allw = [w for line in pg['lines'] for w in line] + pg['loose']
        allw.sort(key=lambda w: w[0])
        for i in range(len(allw)):
            x0, y0, x1, y1, txt = allw[i]
            for j in range(i + 1, len(allw)):
                a0, b0, a1, b1, t2 = allw[j]
                if a0 >= x1 + tol:                 # x0 only grows: no further overlaps are possible
                    break
                ox = min(x1, a1) - max(x0, a0)
                oy = min(y1, b1) - max(y0, b0)
                if ox > tol and oy > tol:
                    bad.append({'page': pno, 'overlap_x_pt': round(ox, 2),
                                'overlap_y_pt': round(oy, 2), 'left': txt[:24],
                                'right': t2[:24], 'x': round(a0, 1), 'y': round(y0, 1)})
    return bad


def margin_violations(pages, margin_pt, tol=TOL_MARGIN_PT):
    bad = []
    for pno, pg in enumerate(pages, 1):
        for ws in pg['lines'] + [pg['loose']]:
            for w in ws:
                x0, y0, x1, y1, txt = w
                if x0 < margin_pt - tol or x1 > pg['width'] - margin_pt + tol:
                    bad.append({'page': pno, 'word': txt[:24], 'x0': round(x0, 1),
                                'x1': round(x1, 1), 'limit': [round(margin_pt, 1),
                                                              round(pg['width'] - margin_pt, 1)]})
    return bad


def ink_boxes(pdf, dpi=150):
    """Route B: where the ink actually lies."""
    from PIL import Image
    d = tempfile.mkdtemp(prefix='layout_')
    subprocess.run(['pdftoppm', '-r', str(dpi), '-png', pdf, os.path.join(d, 'p')],
                   check=True, capture_output=True)
    res = []
    for name in sorted(os.listdir(d)):
        if not name.endswith('.png'):
            continue
        im = Image.open(os.path.join(d, name)).convert('L')
        W, H = im.size
        # everything darker than 250 counts as ink
        bbox = im.point(lambda v: 0 if v > 250 else 255).getbbox()
        scale = 72.0 / dpi
        res.append({'page': name, 'px': im.size,
                    'ink_pt': None if bbox is None else [round(v * scale, 1) for v in bbox],
                    'page_pt': [round(W * scale, 1), round(H * scale, 1)]})
    return res


def main():
    pdf = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PDF
    if not os.path.exists(pdf):
        print('NO PDF: %s' % pdf)
        return 2
    margin = 66.24          # 0.92 in, as in main.tex
    src = os.path.join(HERE, 'paper', os.path.basename(pdf).replace('.pdf', '.tex'))
    if os.path.exists(src):
        m = re.search(r'margin=([\d.]+)in', open(src, encoding='utf-8').read())
        if m:
            margin = float(m.group(1)) * 72.0
    pages = words_from_pdf(pdf)
    ov = overlaps(pages)
    mv = margin_violations(pages, margin)
    ink = ink_boxes(pdf)
    ink_bad = []
    for pg in ink:
        if pg['ink_pt'] is None:
            continue
        x0, y0, x1, y1 = pg['ink_pt']
        W, H = pg['page_pt']
        if x0 < SAFE_PT or y0 < SAFE_PT or x1 > W - SAFE_PT or y1 > H - SAFE_PT:
            ink_bad.append({'page': pg['page'], 'ink': pg['ink_pt']})
    print('pages: %d ; words: %d' % (len(pages), sum(len(l) for p in pages for l in p['lines'])))
    print('route A (word boxes): overlaps %d, overflows past the margin %d' % (len(ov), len(mv)))
    for r in ov[:8]:
        print('   OVERLAP page %d x=%.2f y=%.2f pt: %r | %r'
              % (r['page'], r['overlap_x_pt'], r['overlap_y_pt'], r['left'], r['right']))
    for r in mv[:8]:
        print('   OVERFLOW page %d word %r x0=%.1f x1=%.1f (margin %.1f..%.1f)'
              % (r['page'], r['word'], r['x0'], r['x1'], r['limit'][0], r['limit'][1]))
    print('route B (raster ink): pages with ink outside the %.0f pt safe frame: %d'
          % (SAFE_PT, len(ink_bad)))
    for r in ink_bad[:8]:
        print('   INK page %s %s' % (r['page'], r['ink']))
    ok = not ov and not mv and not ink_bad
    print('RESULT: %s' % ('LAYOUT CLEAN' if ok else 'LAYOUT DIRTY'))
    json.dump({'pdf': pdf, 'pages': len(pages), 'overlaps': ov, 'margin': mv,
               'ink_outside_safe': ink_bad, 'ok': ok},
              open(os.path.join(HERE, 'layout_check.json'), 'w'), ensure_ascii=False, indent=1)
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
