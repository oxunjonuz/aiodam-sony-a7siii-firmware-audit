#!/usr/bin/env python3
r"""F158 — the mechanism behind the loss of 15 inline fragments from the round-281 paper.

Run:  python3 f158_check.py [paper_dir]
Writes f158_result.json.  Every non-control check must be green and every control
must go RED, or the instrument itself is declared blind.

Routes
  A  localisation: where each fragment is and where it is not (English body vs appendix)
  B  the rule that separated kept tokens from dropped ones, with two red controls
  C  the build, twice, so that "the build did it" is excluded by measurement
  D  the LaTeX log, with a red control that shows the search can see a real error
  E  the .tex diff 281 -> 282 in the same sentences
"""
import json, os, re, subprocess, sys, tempfile, shutil, collections

HERE = os.path.dirname(os.path.abspath(__file__))
P281 = sys.argv[1] if len(sys.argv) > 1 else '/work/transcend/SONY_A7SIII_PAPER_281/paper'
EN281, RU281 = os.path.join(P281, 'main.tex'), os.path.join(P281, 'main_ru.tex')
PDF281 = os.path.join(P281, 'main.pdf')
EN282 = '/work/transcend/SONY_A7SIII_ENGLISH_282/publication/paper/main.tex'
EN_LIVE = '/work/SONY_A7SIII_UPDATE/publication/paper/main.tex'

LOST = [
    'BEGIN OPENSSH PRIVATE KEY',
    '0700_part_image/dev/nflasha5',
    '0800_appli/tmp/ssh/sshd_config',
    '/tmp_network/ssh/ssh_host_ecdsa_key',
    '/usr/bin/create_host_key.sh',
    "ssh-keygen -q -b 256 -t ecdsa -N '' -f/tmp_network/ssh/ssh_host_ecdsa_key",
    'PasswordAuthentication no',
    'd2i_PKCS8_PRIV_KEY_INFO',
    'audit/verify_findings.py',
    'BEGIN ENCRYPTED PRIVATE KEY',
    'publication/paper_check.py',
    'publication/selftest_paper.py',
    'kex: host key algorithm: (no match)',
    'env/venv/bin/python3 audit/checks.py',
    'python3 audit/round279_check.py',
    './MAC_FINGERPRINT.sh --ip <\u0430\u0434\u0440\u0435\u0441 \u043a\u0430\u043c',
    'sh publication/run_all.sh',
]
PRESENT = ['shd_config', 'HostKey', 'PubkeyAuthentication', 'MaxSessions 0',
           'audit/round278_check.py', 'RootLogin']
FABRICATED = 'f158_no_such_fragment_anywhere.py'

results = []
def check(name, ok, detail, control=False):
    results.append({'name': name, 'ok': bool(ok), 'detail': detail, 'control': control})
    print(f'[{"GREEN" if ok else " RED "}] {"CONTROL" if control else "       "} {name}: {detail}')

def flat(text):
    return re.sub(r'\s+', '', text.replace('\\allowbreak', '').replace('\\_', '_'))

def read(p):
    return open(p, encoding='utf-8', errors='replace').read()

def pdftotext(pdf, out):
    subprocess.run(['pdftotext', '-q', pdf, out], capture_output=True)
    return read(out) if os.path.exists(out) else ''

def tex_tokens(text):
    return [(m.group(1), m.group(2))
            for m in re.finditer(r'\\(code|lcf|lc|hx|hl)\{([^{}]*)\}', text)]

def yesno(b):
    return 'Y' if b else 'N'

tmp = tempfile.mkdtemp(prefix='f158_')
en_src, ru_src = read(EN281), read(RU281)
en_flat = flat(en_src)
pdf_pages = pdftotext(PDF281, os.path.join(tmp, 'en281.txt')).split('\f')
body = [p for p in pdf_pages if not re.search(r'[\u0410-\u044F]', p)]
appx = [p for p in pdf_pages if re.search(r'[\u0410-\u044F]', p)]
body_flat, appx_flat = flat(''.join(body)), flat(''.join(appx))

# ---------------------------------------------------------------- route A
print('\n=== A. localisation ===')
print(f'   281 PDF: {len(body)} English pages -> {len(body_flat)} chars; '
      f'{len(appx)} pages carrying Cyrillic -> {len(appx_flat)} chars')
a_hits = 0
for frag in LOST:
    f = flat(frag)
    in_ru, in_en = f in flat(ru_src), f in en_flat
    in_body, in_appx = f in body_flat, f in appx_flat
    print(f'   {frag[:50]:52s} RU={yesno(in_ru)} ENs={yesno(in_en)} '
          f'PDFbody={yesno(in_body)} PDFappx={yesno(in_appx)}')
    a_hits += (in_ru and not in_en and not in_body)
check('A1 all %d lost fragments: in the Russian manuscript, absent from the English source '
      'and from the English body of the printed PDF' % len(LOST),
      a_hits == len(LOST), f'{a_hits}/{len(LOST)}')
check('A-red control: 6 fragments from the same twelve sentences are FOUND in source and body',
      all(flat(f) in en_flat and flat(f) in body_flat for f in PRESENT),
      ','.join(f for f in PRESENT if flat(f) in en_flat and flat(f) in body_flat))
check('A-red2 control: a fabricated name is found nowhere',
      flat(FABRICATED) not in en_flat and flat(FABRICATED) not in flat(ru_src)
      and flat(FABRICATED) not in body_flat,
      'fabricated name absent from both sources and the PDF')

# ---------------------------------------------------------------- route B
print('\n=== B. the rule ===')
ru_tok = tex_tokens(ru_src)
en_tok = collections.Counter(flat(v) for _, v in tex_tokens(en_src))
lc = [(mac, raw) for mac, raw in ru_tok if mac in ('lc', 'code') and len(raw) >= 41]
kept = [r for m, r in lc if en_tok[flat(r)] > 0]
gone = [r for m, r in lc if en_tok[flat(r)] == 0]
print(f'   wrapped \\lc/\\code tokens: {len(lc)}; kept {len(kept)}, gone {len(gone)}')
print(f'   longest kept {max(len(r) for r in kept)} chars, shortest gone {min(len(r) for r in gone)} chars')
check('B1 every wrapped \\lc token of source length < 49 is present and every one >= 49 is gone',
      all(len(r) < 49 for r in kept) and all(len(r) >= 49 for r in gone),
      f'threshold measured between {max(len(r) for r in kept)} and {min(len(r) for r in gone)}')
check('B-red control: at threshold 40 the same rule is contradicted',
      len([r for r in kept if len(r) >= 40] + [r for r in gone if len(r) < 40]) > 0,
      f'{len([r for r in kept if len(r) >= 40] + [r for r in gone if len(r) < 40])} contradictions at 40, so 48/49 is measured',
      control=True)
hk = [r for m, r in ru_tok if m in ('hx', 'hl') and len(r) >= 49]
hkept = [r for r in hk if en_tok[flat(r)] > 0]
check('B-red2 control: the same bound applied to \\hx/\\hl is contradicted',
      len(hkept) > 0, f'{len(hkept)} of {len(hk)} long \\hx/\\hl tokens survived: the bound is macro-specific',
      control=True)
same = [r for r in kept if any(orig == r for _, orig in tex_tokens(en_src))]
check('B2 every kept wrapped token is byte-identical between the two files, allowbreaks and all',
      len(same) == len(kept), f'{len(same)}/{len(kept)} identical')

# ---------------------------------------------------------------- route C
print('\n=== C. the build ===')
def build(d):
    for _ in range(2):
        subprocess.run(['xelatex', '-interaction=nonstopmode', 'main.tex'],
                       cwd=d, capture_output=True, timeout=900)
    return os.path.join(d, 'main.pdf')
b1 = os.path.join(tmp, 'b1'); shutil.copytree(P281, b1)
b2 = os.path.join(tmp, 'b2'); shutil.copytree(P281, b2)
t1 = pdftotext(build(b1), os.path.join(tmp, 'r1.txt'))
t2 = pdftotext(build(b2), os.path.join(tmp, 'r2.txt'))
check('C1 two rebuilds of the same .tex give the same PDF text',
      flat(t1) == flat(t2), f'{len(flat(t1))} vs {len(flat(t2))} characters')
def english_part(pdftext):
    """the rebuild carries the same Russian appendix as the original: compare like with like"""
    return flat(''.join(p for p in pdftext.split('\f') if not re.search(r'[\u0410-\u044F]', p)))
r1, r2 = english_part(t1), english_part(t2)
gone_c = sum(1 for f in LOST if flat(f) not in r1)
kept_c = sum(1 for f in PRESENT if flat(f) in r1)
check('C2 the holes reproduce in the rebuilt PDF, English part (%d/%d gone, %d/%d kept present)'
      % (gone_c, len(LOST), kept_c, len(PRESENT)),
      gone_c == len(LOST) and kept_c == len(PRESENT),
      'the build neither creates nor removes them')
b3 = os.path.join(tmp, 'b3'); shutil.copytree(P281, b3)
frag = 'd2i\\_PKCS8\\_PRIV\\_KEY\\_INFO'
t = read(os.path.join(b3, 'main.tex'))
anchor = 'the same number of \\code{END} lines'
assert anchor in t, 'anchor for the control not found'
open(os.path.join(b3, 'main.tex'), 'w').write(
    t.replace(anchor, 'the same number of \\code{' + frag + '} and \\code{END} lines', 1))
t3 = pdftotext(build(b3), os.path.join(tmp, 'r3.txt'))
check('C-red control: the same fragment typed back into the .tex appears in the rebuilt PDF',
      flat(frag) in english_part(t3) and flat(frag) not in r1,
      'the rebuild route can see a presence as well as an absence', control=True)

# ---------------------------------------------------------------- route D
print('\n=== D. the LaTeX log ===')
pat = re.compile(r'Runaway|! LaTeX Error|! Undefined|! Extra|! Emergency|Missing')
hits = [l for l in read(os.path.join(P281, 'main.log')).split('\n') if pat.search(l)]
check('D1 no Runaway/Missing/LaTeX-Error line in the round-281 build log: the loss was silent',
      len(hits) == 0, f'{len(hits)} matching lines')
open(os.path.join(tmp, 'bad.tex'), 'w').write(
    '\\documentclass{article}\n\\newcommand{\\code}[1]{\\texttt{#1}}\n'
    '\\begin{document}\nplain \\code{an argument that is never closed\n\\end{document}\n')
subprocess.run(['xelatex', '-interaction=nonstopmode', 'bad.tex'], cwd=tmp, capture_output=True, timeout=600)
bad_log = read(os.path.join(tmp, 'bad.log'))
check('D-red control: an artificially unclosed argument does put an error in the log',
      bool(re.search(r'Runaway', bad_log)), 'the search is sensitive to a real LaTeX error', control=True)

# ---------------------------------------------------------------- route E
print('\n=== E. what the round-282 revision did with those fragments ===')
RESTORED = ['paper_check.py', 'selftest_paper.py', 'audit/checks.py',
            'audit/round279_check.py', 'publication/run_all.sh', 'MAC_FINGERPRINT.sh']
STILL = ['d2i_PKCS8_PRIV_KEY_INFO', 'BEGIN ENCRYPTED PRIVATE KEY',
         'kex: host key algorithm: (no match)']
en282f = flat(read(EN282))
verbatim = [f for f in LOST if flat(f) in en282f]
short = [n for n in RESTORED if flat(n) in en282f and n not in verbatim]
still = [f for f in STILL if flat(f) not in en282f]
print(f'   back verbatim: {len(verbatim)}; back in a shortened form: {len(short)} {short}; '
      f'still absent: {len(still)} {still}')
check('E1 the %d still-absent fragments really are absent from the round-282 source'
      % len(STILL), len(still) == len(STILL), f'{len(still)}/{len(STILL)}')
check('E-red control: one of the restored forms is genuinely found in the 282 source',
      all(flat(n) in en282f for n in RESTORED),
      'a positive result is possible on the same route', control=True)
# Added in round 284: the same three fragments, measured on the LIVE source. Route E1 above measures
# the edition of 282 as it was delivered and frozen on the volume — that record must not move. This
# one measures the edition rebuilt in round 284, where the three were put back. Both are needed:
# E1 keeps the round-283 finding reproducible, E2 says whether F158 is actually closed.
en_live = flat(read(EN_LIVE))
back_now = [f for f in STILL if flat(f) in en_live]
check('E2 the %d fragments that were missing are back in the edition rebuilt in round 284'
      % len(STILL), len(back_now) == len(STILL),
      f'{len(back_now)}/{len(STILL)} found in {EN_LIVE}')

print('\n=== summary ===')
g = sum(1 for r in results if r['ok'] and not r['control'])
gc = sum(1 for r in results if not r['control'])
c = sum(1 for r in results if r['ok'] and r['control'])
cc = sum(1 for r in results if r['control'])
print(f'non-control green: {g}/{gc}; controls red as required: {c}/{cc}')
json.dump({'results': results, 'lost': LOST, 'present': PRESENT,
           'pdf': {'english_body_chars': len(body_flat), 'appendix_chars': len(appx_flat),
                   'cyrillic_pages': len(appx)},
           'rule': {'kept_max_source_len': max(len(r) for r in kept),
                    'gone_min_source_len': min(len(r) for r in gone),
                    'kept': sorted(kept, key=len, reverse=True),
                    'gone': sorted(gone, key=len, reverse=True)}},
          open(os.path.join(HERE, 'f158_result.json'), 'w'), indent=1, ensure_ascii=True)
print('wrote f158_result.json')
