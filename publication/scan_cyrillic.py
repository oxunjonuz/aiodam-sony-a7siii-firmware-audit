#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_cyrillic.py — is there any Russian left in the package?

The round-282 commission was "everything that is in Russian must be translated into English". A claim
like "there is none left" is worth nothing unless it is a check, so this is the check: it walks the
package, decodes every text file and looks for characters in the range U+0400–U+04FF.

What it does NOT cover, and says so: binary files (the firmware, the unpacked stream, .npy arrays, the
PDF itself), the isolated environment (env/), the downloaded reference implementations (tools/) and
their archives (downloads/). A PDF is a binary, so the printed paper is checked by a different route:
paper_check.py requires every number of it to be present in the printed text, and round 282 verified
the paper's own source and its Appendix A separately.

The control line is written from escape sequences (the instrument itself carries no Cyrillic,
otherwise a clean scan could not be read): the instrument plants one Russian line in a temporary file
inside the tree and must find it;
then it removes the file. An instrument that cannot go red proves nothing.

Run:  python3 publication/scan_cyrillic.py
"""
import os
import re
import sys

ROOT = '/work/SONY_A7SIII_UPDATE'
CYR = re.compile(r'[\u0400-\u04FF]')
SKIP_DIRS = {'env', 'out', 'downloads', 'out_fwtool', 'tools', 'tmpwork', '__pycache__'}
SKIP_FILES = {'BODYDATA.DAT'}
TEXT_EXT = {'.md', '.py', '.sh', '.tex', '.json', '.txt', '.cff', '.yml', '.yaml', '.xml', '.conf',
            '.cfg', '.csv', '.log'}
CONTROL_FILE = os.path.join(ROOT, '.cyrillic_control.tmp')


def scan(paths):
    """Return a list of (path, line_no, line) for text files that contain U+0400-U+04FF."""
    hits = []
    for p in paths:
        try:
            with open(p, 'rb') as fh:
                raw = fh.read()
        except OSError:
            continue
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError:
            continue                      # a binary file: not a document, not covered here
        for i, line in enumerate(text.split('\n'), 1):
            if CYR.search(line):
                hits.append((os.path.relpath(p, ROOT), i, line.strip()[:100]))
    return hits


def text_files():
    out = []
    for dp, dn, fn in os.walk(ROOT):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in sorted(fn):
            if f in SKIP_FILES:
                continue
            p = os.path.join(dp, f)
            if os.path.splitext(f)[1].lower() in TEXT_EXT and os.path.isfile(p):
                out.append(p)
    return out


def main():
    files = text_files()
    hits = scan(files)

    # control: plant a Russian line, it must be found, then remove it
    # The planted line is built from escape sequences on purpose: the instrument itself must not
    # contain a single Cyrillic character, or a "clean" scan would be impossible to interpret.
    plant = ('# ' + '\u043a\u043e\u043d\u0442\u0440\u043e\u043b\u044c: '
             '\u0440\u0443\u0441\u0441\u043a\u0430\u044f \u0441\u0442\u0440\u043e\u043a\u0430, '
             '\u043e\u043d\u0430 \u043e\u0431\u044f\u0437\u0430\u043d\u0430 \u0431\u044b\u0442\u044c '
             '\u043d\u0430\u0439\u0434\u0435\u043d\u0430\n')
    with open(CONTROL_FILE, 'w', encoding='utf-8') as fh:
        fh.write(plant)
    try:
        control_hits = scan([CONTROL_FILE])
    finally:
        os.remove(CONTROL_FILE)

    print('text files scanned : %d' % len(files))
    print('files with Cyrillic: %d' % len(hits))
    for rel, ln, line in hits[:40]:
        print('   %s:%d  %s' % (rel, ln, line))
    if len(hits) > 40:
        print('   ... and %d more' % (len(hits) - 40))
    print('CONTROL (a planted Russian line must be found): %s'
          % ('found' if control_hits else 'NOT FOUND - the instrument is blind'))
    ok = not hits and control_hits
    print('RESULT: %s' % ('THE PACKAGE CARRIES NO RUSSIAN TEXT' if ok else 'RUSSIAN TEXT IS PRESENT'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
