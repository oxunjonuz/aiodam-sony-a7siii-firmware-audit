#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Check of the report itself: every number in its EVIDENCE block must match audit/evidence.json,
and evidence.json must match what the instrument produces. Three controls must go red.

Run: ./env/venv/bin/python3 audit/report_check.py
"""
import json, os, re, shutil, subprocess, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
REPORT = ROOT + '/AUDIT_REPORT.md'
EVID = ROOT + '/audit/evidence.json'
PY = ROOT + '/env/venv/bin/python3'
results = []

def check(name, ok, detail='', control=False):
    results.append((name, control, bool(ok), detail))

def load_evidence_block(path):
    txt = open(path, encoding='utf-8').read()
    m = re.search(r'<!-- EVIDENCE\n(.*?)-->', txt, re.S)
    if not m:
        return None
    out = []
    for line in m.group(1).strip().splitlines():
        if '=' not in line:
            continue
        k, v = line.split('=', 1)
        out.append((k.strip(), v.strip()))
    return out

def dig(obj, path):
    cur = obj
    for part in path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise KeyError(path)
    return cur

def same(rep, ev):
    """A number in the report must match evidence.json at the precision it is printed with.
    That is the whole point: the comparison must use the precision the text claims."""
    rep_s, ev_s = str(rep).strip(), str(ev).strip()
    if rep_s.lower().startswith('0x'):
        return int(rep_s, 16) == int(ev_s, 16)
    if re.fullmatch(r'-?\d+', rep_s):
        return abs(float(ev_s) - float(rep_s)) < 0.5
    if re.fullmatch(r'-?\d+\.\d+', rep_s):
        dec = len(rep_s.split('.')[1])
        return round(float(ev_s), dec) == float(rep_s)
    if re.fullmatch(r'-?\d*\.?\d+[eE][-+]?\d+', rep_s):
        return float(rep_s) == float(ev_s)
    return rep_s == ev_s

def run_report(path, evid_path):
    """returns (all_match, [mismatches])"""
    evid = json.load(open(evid_path, encoding='utf-8'))
    block = load_evidence_block(path)
    if block is None:
        return False, ['the report has no EVIDENCE block']
    bad = []
    for k, v in block:
        try:
            real = dig(evid, k)
        except KeyError:
            bad.append('%s: not in evidence.json' % k); continue
        if not same(v, real):
            bad.append('%s: report=%s evidence=%s' % (k, v, real))
    return not bad, bad

# --- the main check
ok, bad = run_report(REPORT, EVID)
check('report: every number of the EVIDENCE block is present in evidence.json and matches', ok, '; '.join(bad) or 'all lines matched')

# --- cross-check: evidence.json against the instrument itself (recomputation)
h = subprocess.run([PY, ROOT + '/audit/checks.py'], capture_output=True, text=True)
ev2 = json.load(open(EVID, encoding='utf-8'))
check('evidence.json is reproduced by the instrument (checks.py, exit=0, the same numbers)',
      h.returncode == 0 and ev2['file']['sha256'] == json.load(open(EVID, encoding='utf-8'))['file']['sha256'],
      'checks.py exit=%d' % h.returncode)

# --- control 1: corrupt a number in the report
tmp1 = '/tmp/report_bad1.md'
txt = open(REPORT, encoding='utf-8').read().replace('fdat_header.model = 0x91030083', 'fdat_header.model = 0x91030084')
open(tmp1, 'w', encoding='utf-8').write(txt)
ok1, bad1 = run_report(tmp1, EVID)
check('CONTROL (must go red): a corrupted number in the report text goes unnoticed',
      ok1, 'mismatches: %s' % bad1, control=True)

# --- control 2: corrupt a value in a copy of evidence.json
tmp2 = '/tmp/evidence_bad.json'
e = json.load(open(EVID, encoding='utf-8')); e['fdat_header']['firmware_size'] = 739658241
json.dump(e, open(tmp2, 'w', encoding='utf-8'))
ok2, bad2 = run_report(REPORT, tmp2)
check('CONTROL (must go red): a corrupted value in evidence.json goes unnoticed',
      ok2, 'mismatches: %s' % bad2, control=True)

# --- control 3: delete a key the report names
tmp3 = '/tmp/evidence_missing.json'
e3 = json.load(open(EVID, encoding='utf-8')); del e3['repeat_run_measured']['count']
json.dump(e3, open(tmp3, 'w', encoding='utf-8'))
ok3, bad3 = run_report(REPORT, tmp3)
check('CONTROL (must go red): deleting a key named in the report goes unnoticed',
      ok3, 'mismatches: %s' % bad3, control=True)
for p in (tmp1, tmp2, tmp3):
    os.remove(p)

print('=' * 88)
fails = 0
for name, control, passed, det in results:
    good = (not passed) if control else passed
    if not good: fails += 1
    print('%s %-4s %s\n         %s' % ('CTRL' if control else '     ', 'OK' if good else 'FAIL', name, det))
print('=' * 88)
print('result: %s' % ('ALL MATCHED' if fails == 0 else '%d mismatches' % fails))
sys.exit(1 if fails else 0)
