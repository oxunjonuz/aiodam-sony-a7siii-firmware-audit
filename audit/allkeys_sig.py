#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Every public key lying INSIDE the file, against the 256 B tail.

If the tail is an RSA-2048 signature, then the matching key will yield, after
exponentiation, a PKCS#1 v1.5 structure (00 01 FF..FF 00 || DigestInfo) — this is
checked without knowing the message. We try every key found in the file itself.
"""
import hashlib, json, re, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
from Crypto.PublicKey import RSA
from fwtool.sony import dat as refdat

st = open(ROOT + '/out/stream.bin', 'rb').read()
P = ROOT + '/BODYDATA.DAT'
E = {}

# --- the tail
d = refdat.readDat(open(P, 'rb'))
pl = d.firmwareData
pl.seek(pl.size - 272)
tail = pl.read(272)
sig = tail[16:]
s_int = int.from_bytes(sig, 'big')

# --- all PEM blocks
blocks = []
for m in re.finditer(rb'-----BEGIN ([A-Z ]+)-----(.*?)-----END \1-----', st, re.S):
    kind = m.group(1).decode()
    body = re.sub(rb'\s', b'', m.group(2))
    blocks.append({'kind': kind, 'offset': m.start(), 'pem': m.group(0)})
E['pem_blocks'] = {'total': len(blocks),
                   'kinds': {k: sum(1 for b in blocks if b['kind'] == k)
                             for k in {b['kind'] for b in blocks}}}

tests = []
for b in blocks:
    if b['kind'] != 'PUBLIC KEY':
        continue
    try:
        k = RSA.import_key(b['pem'])
    except Exception as ex:
        tests.append({'offset': b['offset'], 'error': str(ex)})
        continue
    n, e, bits = k.n, k.e, k.size_in_bits()
    rec = {'offset': b['offset'], 'bits': bits, 'e': e,
           'n_sha256': hashlib.sha256(n.to_bytes((bits + 7) // 8, 'big')).hexdigest(),
           'sig_len_bytes': len(sig), 'sig_len_matches_key': len(sig) == bits // 8,
           'sig_lt_n': s_int < n}
    if bits // 8 == len(sig):
        m = pow(s_int, e, n).to_bytes(len(sig), 'big')
        rec['m_first24_hex'] = m[:24].hex()
        rec['pkcs1_v15_ok'] = (m[0] == 0 and m[1] == 1)
        rec['pss_maybe'] = (m[0] & 0x80) == 0 and m[-1] == 0xbc
        if rec['pkcs1_v15_ok']:
            i = 2
            while i < len(m) and m[i] == 0xff:
                i += 1
            rec['digestinfo_hex'] = m[i + 1:].hex()
    tests.append(rec)
E['tail_vs_keys'] = tests

# --- what is inside the .sum files (the internal integrity of the image)
sums = {}
for name in (b'0101_config_sum/config.sum', b'1051_i2c_sum/i2c.sum'):
    j = st.find(name)
    if j < 0:
        continue
    off = j + 512
    fr = st[off:off + 400].decode('latin1')
    sums[name.decode()] = fr
E['sum_files'] = sums

# --- all small tar members of *.sum / *.txt / *.conf (text)
def tar_members(buf, base):
    off, out = 0, []
    while off + 512 <= len(buf):
        hdr = buf[off:off + 512]
        if hdr[:100].rstrip(b'\x00') == b'':
            off += 512
            continue
        if hdr[257:262] != b'ustar':
            break
        name = hdr[0:100].rstrip(b'\x00').decode('latin1')
        size = int(hdr[124:136].rstrip(b'\x00 ').decode() or '0', 8)
        out.append((name, base + off + 512, size))
        off += 512 + ((size + 511) // 512) * 512
    return out


FW_OFF, FW_SIZE = 1253888, 739658240
members = tar_members(st[FW_OFF:FW_OFF + FW_SIZE], FW_OFF)
E['small_text_members'] = []
for name, off, size in members:
    if size <= 300 and (name.endswith('.sum') or name.endswith('.txt') or name.endswith('.conf')
                        or name.endswith('.pem')):
        blob = st[off:off + size]
        txt = None
        if all(32 <= c < 127 or c in (10, 13, 9) for c in blob):
            txt = blob.decode('latin1')
        E['small_text_members'].append({'name': name, 'size': size, 'text': txt,
                                        'head_hex': None if txt else blob[:32].hex()})
E['member_names'] = [m[0] for m in members]

with open(ROOT + '/audit/allkeys_sig.json', 'w') as f:
    json.dump(E, f, indent=1, default=str)
print(json.dumps({k: E[k] for k in ('pem_blocks', 'tail_vs_keys')}, indent=1, default=str)[:4000])
print('--- sum ---')
for k, v in sums.items():
    print(k, repr(v))
print('--- small text members ---')
for m in E['small_text_members']:
    print(m['name'], m['size'], repr((m['text'] or m['head_hex'])[:300]))
