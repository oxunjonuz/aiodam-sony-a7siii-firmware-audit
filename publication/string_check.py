#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""string_check.py — the names the paper cites must survive into print.

Why this instrument exists. paper_check.py tests the paper's NUMBERS: every one of them is re-derived
from an artifact and must be present in the source and in the printed PDF. That check is blind to a
missing NAME. On 2026-10-04 the owner read the extracted text of the paper and found holes: five
inline \code{...} fragments had been lost from the source of the paper (a config path, a member name,
the sshd_config path, the HostKey line, the command that creates the key, and one config directive).
Every number was still present, so paper_check.py stayed green, and layout_check.py cannot see missing
text either: it measures the boxes that ARE there. The defect was found by a human reading, not by an
instrument, and that is exactly the gap this file closes.

What it does:
  A. every string in REQUIRED must be present in the paper's source (main.tex), after LaTeX markup is
     stripped;
  B. the same string must be present in the text extracted from the PRINTED PDF, after whitespace is
     removed (a name may be broken across a line, and \\allowbreak in this paper breaks names on
     purpose);
  C. control: a string that is deliberately absent must be reported as absent in both routes. An
     instrument that cannot say "no" proves nothing.

Each required string names where it comes from, so that a failure says which artifact it should agree
with. The list is not a copy of the paper: it is a list of the names the paper's claims rest on, and it
was written from the audit artifacts (ROUND_278.md, audit/*.json, numbers.json), not from main.tex.

Run:  python3 publication/string_check.py
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEX = os.path.join(HERE, 'paper', 'main.tex')
PDF = os.path.join(HERE, 'paper', 'main.pdf')

# (string, why it must be in the printed paper, where it comes from)
REQUIRED = [
    ('BODYDATA.DAT', 'the subject', 'the file'),
    ('ILCE-7SM3', 'the model, by internal evidence', 'audit/round277_checks.json: 61 occurrences'),
    ('ILCE-7SM3 v5.01', 'the ready-made model+version pair', 'ROUND_277.md §3'),
    ('0x91030083', 'the model code in the header', 'audit/evidence.json'),
    ('key_cxd90057_k8', 'the public key that opens the body', 'ROUND_277.md §1'),
    ('UDTRFIRM', 'the body magic', 'audit/evidence.json'),
    ('1fafdcaa', 'the container CRC32', 'audit/evidence.json'),
    ('0700_part_image/dev/nflasha5', 'the member that holds the private key', 'ROUND_278.md §3'),
    ('nflasha15', 'the /usr image member', 'ROUND_278.md §2'),
    ('0800_appli/tmp/ssh/sshd_config', 'the member the sshd config came from', 'ROUND_278.md §4a'),
    ('/tmp_network/ssh/ssh_host_ecdsa_key', 'the host key path of the camera', 'ROUND_278.md §4a'),
    ('HostKeyAlgorithms', 'the config directive that pins the host algorithm', 'ROUND_278.md §4a'),
    ('ecdsa-sha2-nistp256', 'the key and host algorithm type', 'ROUND_278.md §3'),
    ('ecdh-sha2-nistp256', 'the kex the firmware imposes', 'ROUND_279.md §3'),
    ('hmac-sha2-256', 'the MAC the firmware imposes', 'ROUND_279.md §3'),
    ('aes128-ctr', 'the cipher the firmware imposes', 'ROUND_279.md §3'),
    ('/usr/bin/create_host_key.sh', 'the script that creates the camera host key', 'ROUND_278.md §4b'),
    ("ssh-keygen -q -b 256 -t ecdsa -N ''", 'the exact command that creates the key', 'ROUND_278.md §4b'),
    ('PasswordAuthentication no', 'the config forbids password login', 'ROUND_278.md §4d'),
    ('PubkeyAuthentication no', 'the config forbids key login', 'ROUND_278.md §4d'),
    ('PermitRootLogin no', 'root is locked out', 'ROUND_278.md §4d'),
    ('MaxSessions 0', 'no shell is offered', 'ROUND_278.md §4d'),
    ('localhost:15740', 'the only forward permitted (Sony PTP/IP)', 'ROUND_278.md §4d'),
    ('localhost:60152', 'the second permitted forward', 'ROUND_278.md §4d'),
    ('config/config.xml', "the updater's pipeline map", 'ROUND_277.md §9'),
    ('MODE_SERVICE=2', 'the service mode of the updater', 'ROUND_278.md §1'),
    ('CXD90057', 'the class of the device (config/chassis)', 'ROUND_277.md §9'),
    ('700.104.039', 'the internal body version', 'ROUND_277.md §9'),
    ('SHA256:J8L9aBLE', 'the fingerprint of the key shipped in the image', 'ROUND_278.md §3'),
    ('SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U', 'the live camera host key fingerprint',
     'round-279 witness file'),
    ('sshd_config', 'the config file itself', 'ROUND_278.md §4a'),
    ('ILCE-9', 'the only other model name in the file', 'ROUND_277.md §3'),
    ('BEGIN PUBLIC KEY', 'the armour line that was counted instead of keys', 'ROUND_278.md §2'),
    ('OPENSSH PRIVATE KEY', 'the armour line of the single real key', 'ROUND_278.md §2'),
    ('root@(none)', 'the comment inside the key (what ssh-keygen writes on a nameless root box)',
     'ROUND_278.md §3'),
    ('HostKey /tmp_network/ssh/ssh_host_ecdsa_key', 'the single active HostKey line',
     'ROUND_278.md §4a'),
    # Names that the systematic hole search (route C below) found MISSING from the paper and that
    # were restored in round 282. They are listed here so that they cannot go missing again.
    ('CMS_EncryptedData_it', 'the OpenSSL symbol showing image encryption lives in pformat.elf',
     'ROUND_278.md §1'),
    ('paper_check.py', 'the number instrument, named in the paper own "how this was checked"',
     'publication/paper_check.py'),
    ('selftest_paper.py', 'the proof that the number instrument can go red',
     'publication/selftest_paper.py'),
    ('layout_check.py', 'the layout instrument', 'publication/layout_check.py'),
    ('string_check.py', 'this instrument (the name check itself)', 'publication/string_check.py'),
    ('audit/checks.py', 'the main audit instrument, named in the reproduction list',
     'audit/checks.py'),
    ('verify_findings.py', 'the re-verification instrument, named in the reproduction list',
     'audit/verify_findings.py'),
    ('round279_check.py', 'the live-device instrument, named in the reproduction list',
     'audit/round279_check.py'),
    ('MAC_FINGERPRINT.sh', 'the instrument the owner runs on the Mac',
     'audit/make_279_delivery.py'),
    ('run_all.sh', 'the one command that runs the whole chain', 'publication/run_all.sh'),
    # The three fragments that were still absent after the round-282 revision and were put back in
    # round 284 (F158). They are technical strings rather than artifact names, which is exactly why
    # neither the owner's list nor the 46-name list above had caught them. They are listed here so
    # that this instrument — not a reader's eye — is now what notices if they go missing again.
    ('d2i_PKCS8_PRIV_KEY_INFO', 'an OpenSSL symbol: the image writer can parse private keys',
     'ROUND_278.md §1 (pformat.elf symbols)'),
    ('BEGIN ENCRYPTED PRIVATE KEY', 'the one armour line that is a string table, not a key',
     'ROUND_278.md §2 (literals vs objects)'),
    ('kex: host key algorithm: (no match)', 'the debug line whose bad parse produced a false verdict',
     'ROUND_279.md (F156)'),
]

# control strings that must NOT be found in either route
CONTROL = 'ZZ-PLANTED-STRING-THAT-IS-IN-NO-PAPER-ZZ'


def norm_tex(s):
    """Strip the LaTeX markup this paper uses, so names can be compared as plain text."""
    s = re.sub(r'\\allowbreak\s*', '', s)
    s = s.replace(r'\,', '').replace('{,}', ',').replace(r'\ldots', '\u2026')
    for esc, plain in ((r'\_', '_'), (r'\%', '%'), (r'\&', '&'), (r'\#', '#'), (r'\$', '$'),
                       (r'\{', '{'), (r'\}', '}')):
        s = s.replace(esc, plain)
    for cmd in ('code', 'lc', 'lcf', 'hx', 'hl', 'texttt', 'emph', 'textbf', 'text'):
        s = re.sub(r'\\' + cmd + r'\{([^{}]*)\}', r'\1', s)
    s = re.sub(r'\\[a-zA-Z]+\*?(\[[^\]]*\])?', ' ', s)
    return s


def norm_pdf(s):
    return re.sub(r'\s+', '', s)


def occurs(text, needle):
    if needle in text:
        return True, 'plain'
    return (needle.replace('-', '') in text.replace('-', '')), 'hyphens removed'


# A dropped inline token leaves an artefact in the source: two spaces where one was, empty
# parentheses, or a space before punctuation. These patterns found the rest of the holes in round 282
# — names that the required-string list had not thought to ask for. The detector is deliberately
# conservative: it must not fire on ordinary prose, and the negative lookbehind keeps function calls
# such as decrypt() out of the way. The control below shows that it can fire at all.
HOLE_PATTERNS = [
    (r'\S  +\S', 'two spaces between words (a dropped inline token)'),
    (r'(?<![A-Za-z0-9_\\])\(\s*\)', 'empty parentheses'),
    (r',\s*;', 'a comma followed by a semicolon'),
    (r':\s*,', 'a colon followed by a comma'),
    (r',\s*,', 'two commas in a row'),
    (r':\s*\.', 'a colon followed by a full stop'),
    (r'\(,', 'an opening bracket followed by a comma'),
]
HOLE_CONTROL_LINE = '\\item Paper:  --- it runs the instruments'     # the real artefact of F167


def holes(text):
    """Return [(line_no, line, which_pattern)] for the artefacts of a dropped token."""
    out = []
    for i, line in enumerate(text.split('\n'), 1):
        for pat, why in HOLE_PATTERNS:
            if re.search(pat, line):
                out.append((i, line.strip()[:110], why))
                break
    return out


def main():
    for p in (TEX, PDF):
        if not os.path.exists(p):
            print('NO SUCH FILE: %s' % p)
            return 2
    src = norm_tex(open(TEX, encoding='utf-8').read())
    raw = subprocess.run(['pdftotext', '-q', PDF, '-'], capture_output=True, text=True).stdout
    pdf = norm_pdf(raw)
    src_flat = re.sub(r'\s+', '', src)

    rows, missing = [], []
    for needle, why, source in REQUIRED:
        flat = needle.replace(' ', '')
        in_src, route_src = occurs(src_flat, flat)
        in_pdf, route_pdf = occurs(pdf, flat)
        rows.append((needle, in_src, in_pdf))
        if not (in_src and in_pdf):
            missing.append('%-44s source=%-5s pdf=%-5s  (%s; %s)'
                           % (needle, in_src, in_pdf, why, source))

    green = sum(1 for _, a, b in rows if a and b)
    print('required strings checked: %d' % len(REQUIRED))
    print('present in source and in the printed PDF: %d/%d' % (green, len(REQUIRED)))
    for line in missing:
        print('   MISSING %s' % line)

    src_lines = open(TEX, encoding='utf-8').read()
    src_holes = holes(src_lines)
    ctrl_holes = holes(HOLE_CONTROL_LINE)
    print('route C (artefacts of a dropped token in the source): %d' % len(src_holes))
    for ln, line, why in src_holes[:20]:
        print('   line %d: %s   [%s]' % (ln, line, why))
    print('   control (a synthetic line with the same artefact must be flagged): %s'
          % ('flagged' if ctrl_holes else 'NOT FLAGGED - the detector is blind'))

    c_src, _ = occurs(src_flat, CONTROL.replace(' ', ''))
    c_pdf, _ = occurs(pdf, CONTROL.replace(' ', ''))
    print('CONTROL (a planted string must be reported absent in both routes): source=%s pdf=%s'
          % (c_src, c_pdf))
    ok = not missing and not c_src and not c_pdf and not src_holes and bool(ctrl_holes)
    print('RESULT: %s' % ('EVERY CITED NAME SURVIVES INTO PRINT, AND THE SOURCE HAS NO DROPPED TOKEN'
                          if ok else 'A CITED NAME IS MISSING, OR THE SOURCE HAS A DROPPED TOKEN'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
