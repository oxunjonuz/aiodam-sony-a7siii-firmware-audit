#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Keys inside the file + a test of the hypothesis "the 256 B tail is a signature".

The unpacked firmware tar contains two PEM files:
    0800_appli/setting/public_key.pem
    0800_appli/setting/verify_key.pem
These are exactly what the audit lacked: public keys coming from the product itself.
Method: raise the tail to the power e modulo n of each key and see whether a
PKCS#1 v1.5 structure is there (00 01 FF..FF 00 || DigestInfo) — that is how a
signature is verified WITHOUT knowing the message; once a digest is found, we look
for what exactly it hashes.
"""
import binascii, hashlib, io, json, os, sys

ROOT = '/work/SONY_A7SIII_UPDATE'
STREAM = ROOT + '/out/stream.bin'
P = ROOT + '/BODYDATA.DAT'
OUT = ROOT + '/audit/keys_and_sig.json'
sys.path.insert(0, ROOT + '/tools/fwtool.py-master')
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss
from Crypto.Hash import SHA1, SHA256, SHA384, SHA512
from fwtool.sony import dat as refdat

FW_OFF, FW_SIZE, FS_OFF, FS_SIZE = 1253888, 739658240, 512, 1253376
E = {}
st = open(STREAM, 'rb').read()


def tar_list(buf, base):
    members, off = [], 0
    while off + 512 <= len(buf):
        hdr = buf[off:off + 512]
        if hdr[:100].rstrip(b'\x00') == b'':
            off += 512
            continue
        if hdr[257:262] != b'ustar':
            break
        name = hdr[0:100].rstrip(b'\x00').decode('latin1')
        size = int(hdr[124:136].rstrip(b'\x00 ').decode() or '0', 8)
        assert off + 512 + size <= len(buf), 'member beyond region: ' + name
        members.append((name, base + off + 512, size))
        off += 512 + ((size + 511) // 512) * 512
    return members


fw = st[FW_OFF:FW_OFF + FW_SIZE]
members = tar_list(fw, FW_OFF)
E['tar_members'] = [m[0] for m in members]
E['tar_member_count'] = len(members)

# --- pull out the keys and the small text files
def member(name):
    for nm, off, size in members:
        if nm == name:
            return st[off:off + size]
    return None


pem_pub = member('0800_appli/setting/public_key.pem')
pem_ver = member('0800_appli/setting/verify_key.pem')
E['pem_files'] = {
    'public_key.pem_text': pem_pub.decode('latin1') if pem_pub else None,
    'verify_key.pem_text': pem_ver.decode('latin1') if pem_ver else None,
}
keys = {}
for tag, pem in (('public_key', pem_pub), ('verify_key', pem_ver)):
    if pem:
        try:
            k = RSA.import_key(pem)
            keys[tag] = k
            E.setdefault('keys', {})[tag] = {'bits': k.size_in_bits(), 'e': k.e,
                                             'n_head_hex': hex(k.n)[:24],
                                             'n_sha256': hashlib.sha256(
                                                 k.n.to_bytes((k.n.bit_length() + 7) // 8,
                                                              'big')).hexdigest()}
        except Exception as ex:
            E.setdefault('keys', {})[tag] = 'parse error: %s' % ex
# other public keys/certificates in the stream (the first byte of their structure)
E['other_pem_offsets'] = []
pos = 0
while True:
    i = st.find(b'BEGIN PUBLIC KEY', pos)
    if i < 0:
        break
    E['other_pem_offsets'].append(i)
    pos = i + 1
    if len(E['other_pem_offsets']) > 20:
        break

# --- the 256 B tail
d = refdat.readDat(open(P, 'rb'))
pl = d.firmwareData
pl.seek(pl.size - 272)
tail = pl.read(272)
sig = tail[16:]
s_int = int.from_bytes(sig, 'big')
E['tail'] = {'sig_hex': sig.hex(), 'iv_hex': tail[:16].hex(),
             'sig_lt_n': {t: (s_int < k.n) for t, k in keys.items()}}

# --- 1) the structure after exponentiation (without knowing the message)
HASHES = {'sha1': SHA1, 'sha256': SHA256, 'sha384': SHA384, 'sha512': SHA512}
DER_PREFIX = {  # DigestInfo prefixes (RFC 3447)
    'sha1': '3021300906052b0e03021a05000414',
    'sha256': '3031300d060960864801650304020105000420',
    'sha384': '3041300d060960864801650304020205000430',
    'sha512': '3051300d060960864801650304020305000440',
}
structs = {}
for tag, k in keys.items():
    m = pow(s_int, k.e, k.n).to_bytes(k.size_in_bits() // 8, 'big')
    info = {'m_first32_hex': m[:32].hex(), 'm_last32_hex': m[-32:].hex(),
            'pkcs1_v15_ok': m[0] == 0 and m[1] == 1,
            'pss_maybe': (m[0] & 0x80) == 0 and m[-1] == 0xbc}
    if m[0] == 0 and m[1] == 1:
        i = 2
        while i < len(m) and m[i] == 0xff:
            i += 1
        di = m[i + 1:]
        info['ff_run'] = i - 2
        info['digestinfo_hex'] = di.hex()
        for alg, pref in DER_PREFIX.items():
            if di.hex().startswith(pref):
                info['hash_algorithm'] = alg
                info['digest_hex'] = di.hex()[len(pref):]
    structs[tag] = info
E['signature_structure'] = structs

# --- 2) if a digest was found, look for the message
msgs = {
    'whole_stream': st,
    'stream_from_512': st[512:],
    'fs_image': st[FS_OFF:FS_OFF + FS_SIZE],
    'firmware_tar': fw,
    'stream_without_tail_272': st[:-0] if False else st,
    'header_512': st[:512],
    'header_400': st[:400],
    'ciphertext_region': d.firmwareData.read(0) if False else None,
    'payload_minus_tail': None,
}
pl.seek(0)
msgs['payload_minus_tail'] = pl.read(pl.size - 272)
msgs['whole_payload_with_tail'] = pl.read()
cand = {}
for tag, info in structs.items():
    if not info.get('digest_hex'):
        continue
    want = bytes.fromhex(info['digest_hex'])
    algn = info['hash_algorithm']
    for mname, m in msgs.items():
        if m is None:
            continue
        h = hashlib.new(algn, m).digest()
        if h == want:
            cand['%s/%s' % (tag, mname)] = True
        # a variant: a signature over the hash (double hashing)
        h2 = hashlib.new(algn, h).digest()
        if h2 == want:
            cand['%s/%s(dbl)' % (tag, mname)] = True
E['digest_search'] = {'candidates': cand, 'tried_messages': list(msgs)}

# --- 3) a direct signature check (in case the structure was not recognised)
direct = {}
for tag, k in keys.items():
    for mname, m in msgs.items():
        if m is None:
            continue
        for alg, H in HASHES.items():
            for scheme, cls in (('pkcs1v15', pkcs1_15), ('pss', pss)):
                try:
                    h = H.new(m)
                    (cls.new(k).verify(h, sig))
                    direct['%s/%s/%s' % (tag, mname, alg)] = True
                except Exception:
                    pass
E['direct_verification'] = direct
E['CONTROL'] = 'see the planted control below'
# CONTROL: we sign ourselves with a key of our own and verify with the same instrument
try:
    k2 = RSA.generate(2048)
    msg = b'control message'
    s2 = pkcs1_15.new(k2).sign(SHA256.new(msg))
    ok = True
    try:
        pkcs1_15.new(k2.publickey()).verify(SHA256.new(msg), s2)
    except Exception:
        ok = False
    bad = True
    try:
        pkcs1_15.new(k2.publickey()).verify(SHA256.new(b'other'), s2)
        bad = False
    except Exception:
        bad = True
    E['CONTROL'] = {'verify_accepts_true_signature': ok,
                    'verify_rejects_wrong_message': bad}
except Exception as ex:
    E['CONTROL'] = 'error: %s' % ex

# --- the version/model inside the file
ctx = []
for pat in (b'5.01', b'V5.01', b'ver5', b'SM3'):
    f, pos = [], 0
    while True:
        i = st.find(pat, pos)
        if i < 0 or len(f) >= 5:
            break
        f.append({'off': i, 'ctx': st[max(0, i - 24):i + 32].decode('latin1')})
        pos = i + 1
    ctx.append({'pat': pat.decode('latin1'), 'hits': f})
E['version_context'] = ctx

with open(OUT, 'w') as f:
    json.dump(E, f, indent=1, sort_keys=True, default=str)
print(json.dumps({k: E[k] for k in ('pem_files', 'keys', 'signature_structure', 'digest_search',
                                    'direct_verification', 'CONTROL', 'tail')},
                 indent=1, ensure_ascii=False))
