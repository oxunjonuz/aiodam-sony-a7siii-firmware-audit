#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""numrules.py — the dictionary of rules by which a number of the paper is derived from the
artifact bytes.

One rule = one measurement. The list of rules is deliberately short: the fewer kinds of rules,
the fewer places where the check can diverge from the object it checks.

A rule is a dict with a 'kind' field and arguments. Implemented kinds:

  size        {path}                       size of a file in bytes
  hash        {path, algo}                 sha256|md5|sha1 of a file
  hex         {path, off, len}             bytes as a lowercase hex string
  u32         {path, off, endian}          a 4-byte integer
  json        {path, ptr}                  a value from a JSON artifact (dot-separated path)
  count       {path, needle[, enc]}        number of occurrences of a substring in a stream
  tar         {path, off, size, suffix}    [offset of the member data, size] from the tar contents
  expr        {expr, vars}                 arithmetic over already computed numbers
  const       {value}                      a constant (for quantities taken from someone
                                           else's measurement; the source must be named)
  header      {path, field}                a field of the FDAT header (decrypted with the public key)
  udid        {path}                       the list of UDID descriptors
  dend        {path}                       the stored container CRC32 and its recomputation
  ecb         {path}                       runs of identical 16-byte ciphertext blocks
  pems        {path, field}                inventory of armor blocks and RSA moduli
  keyblock    {path, off}                  private key: lengths, fingerprint, blob sha256
  tail        {path, off, ...}             the IV and the signature prefix from the body tail
  squashfs    {root, field}                the unpacked tree: files/ELF/scripts/bytes
  filefield   {path, field}                a field taken out of a text file (matched by pattern)

No key material is stored here: the body key is read from audit/newkeys_probe.py, the
private key from the image itself, and only fingerprints are ever printed out.
"""
import base64
import binascii
import hashlib
import json
import mmap
import os
import re
import struct
import subprocess
import sys
import zlib

ROOT = '/work/SONY_A7SIII_UPDATE'
sys.path.insert(0, os.path.join(ROOT, 'tools', 'fwtool.py-master'))
from Crypto.Cipher import AES                      # noqa: E402
from Crypto.PublicKey import RSA as RSAKey         # noqa: E402
from fwtool.sony import constants as KC            # noqa: E402

_BODY_KEY_SRC = os.path.join(ROOT, 'audit', 'newkeys_probe.py')
_src = open(_BODY_KEY_SRC, encoding='utf-8').read()
_chunk = _src[_src.index('K_057_k8'):][:400]
_KEYS = bytes(int(h, 16) for h in re.findall(r'\\x([0-9A-Fa-f]{2})', _chunk))
assert len(_KEYS) == 32, 'the body key was not read from %s' % _BODY_KEY_SRC


def _resolve(path):
    return path if os.path.isabs(path) else os.path.join(ROOT, path)


def _read(path, off, n):
    with open(_resolve(path), 'rb') as f:
        f.seek(off)
        return f.read(n)


def _stream_scan(path, needles, chunk=1 << 24):
    """A single pass over the file: count all needles at once, carrying the chunk boundary."""
    needles = list(needles)
    counts = {n: 0 for n in needles}
    maxlen = max(len(n) for n in needles)
    tail = b''
    with open(_resolve(path), 'rb') as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            buf = tail + b
            for n in needles:
                counts[n] += buf.count(n)
            tail = buf[-(maxlen - 1):]
    return counts


def _fdat_payload_off(path):
    """The FDAT body starts 8 bytes after the length field (that is, after the tag)."""
    with open(_resolve(path), 'rb') as f:
        off = 8
        while off < 4096:
            ln = struct.unpack('>I', _read(path, off, 4))[0]
            tag = _read(path, off + 4, 4)
            if tag == b'FDAT':
                payload = off + 8
                ct = _read(path, payload, 512)
                pt = AES.new(KC.key_aes, AES.MODE_ECB).decrypt(ct)
                if pt[4:12] != b'UDTRFIRM':      # the magic lives in the DECRYPTED window,
                    raise AssertionError(        # not in the file bytes (error F163)
                        'at offset %d the decrypted header does not start with the magic' % payload)
                return payload
            off += 8 + ln + (-ln % 4)
    raise AssertionError('FDAT not found')


def _solve4(prefix, target):
    """crc32 over a 4-byte tail is a bijection: we solve which 4 bytes the sum demands."""
    def cc(x):
        return binascii.crc32(prefix + x) & 0xffffffff
    c0 = cc(b'\x00\x00\x00\x00')
    basis = {}
    for i in range(32):
        x = bytearray(4)
        x[i // 8] |= 1 << (i % 8)
        col, bit = cc(bytes(x)) ^ c0, 1 << i
        for p in list(basis):
            if col >> p & 1:
                col ^= basis[p][0]
                bit ^= basis[p][1]
        if col:
            basis[col.bit_length() - 1] = (col, bit)
    v, x = target ^ c0, 0
    for p in sorted(basis, reverse=True):
        if v >> p & 1:
            v ^= basis[p][0]
            x ^= basis[p][1]
    return x.to_bytes(4, 'little')


def _fdat_header(path):
    """Decryption of the header with the public key_aes (ECB) + its fields. Returns a dict.

    Note on the window boundary: the crc32 covers 500 bytes starting at the 12th byte of the
    structure, and the last 4 of them already lie outside the window that key_aes opens.
    So they are not read but SOLVED from the sum (the inverse crc32 problem).
    """
    off = _fdat_payload_off(path)
    head = AES.new(KC.key_aes, AES.MODE_ECB).decrypt(_read(path, off, 512))
    H = head[4:]
    checksum = struct.unpack('<I', H[8:12])[0]
    return {
        'payload_off': off,
        'frame_hex': head[:4].hex(),
        'magic': head[4:12].decode('latin1'),
        'fmt_version': head[16:20].decode('latin1'),
        'mode': head[20:21].decode('latin1'),
        'luw': head[24:25].decode('latin1'),
        'checksum': '0x%08x' % checksum,
        'version': '%d.%02d' % (H[33], H[32]),
        'model': '0x%08x' % struct.unpack('<I', H[36:40])[0],
        'region': struct.unpack('<I', H[40:44])[0],
        'fw_off': struct.unpack('<I', H[48:52])[0],
        'fw_size': struct.unpack('<I', H[52:56])[0],
        'num_fs': struct.unpack('<I', H[56:60])[0],
        'fs_u_off': struct.unpack('<I', H[68:72])[0],
        'fs_u_size': struct.unpack('<I', H[72:76])[0],
        'fs_p_size': struct.unpack('<I', H[88:92])[0],
        'known_suffix_hex': _solve4(head[16:512], checksum).hex(),
    }


def _tar_walk(path, off, size):
    with open(_resolve(path), 'rb') as f:
        pos, end, out = off, off + size, {}
        while pos + 512 <= end:
            f.seek(pos)
            hdr = f.read(512)
            if hdr[:1] == b'\x00' or hdr[257:262] != b'ustar':
                break
            name = hdr[0:100].split(b'\x00')[0].decode('latin1')
            try:
                sz = int((hdr[124:136].split(b'\x00')[0].strip() or b'0'), 8)
            except ValueError:
                sz = 0
            out[name] = (pos + 512, sz)
            pos += 512 + ((sz + 511) // 512) * 512
    return out


def _openssh_key(block_text):
    raw = base64.b64decode(b''.join(l for l in block_text.splitlines()
                                    if not l.startswith(b'-----')))
    o = 15
    out = {}
    for f in ('cipher', 'kdf', 'kdfopts'):
        ln = struct.unpack('>I', raw[o:o + 4])[0]
        o += 4
        out[f] = raw[o:o + ln]
        o += ln
    out['nkeys'] = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    ln = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    out['pub'] = raw[o:o + ln]
    o += ln
    ln = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    priv = raw[o:o + ln]
    po = 0
    out['checkint'] = struct.unpack('>II', priv[po:po + 8])
    po += 8
    for nm in ('keytype', 'curve', 'Q', 'd', 'comment'):
        ln = struct.unpack('>I', priv[po:po + 4])[0]
        po += 4
        out[nm] = priv[po:po + ln]
        po += ln
    return out


def _p256_mul(d):
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
    G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
         0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

    def add(Pa, Pb):
        if Pa is None:
            return Pb
        if Pb is None:
            return Pa
        x1, y1 = Pa
        x2, y2 = Pb
        if x1 == x2 and (y1 + y2) % p == 0:
            return None
        lam = ((3 * x1 * x1 + a) * pow(2 * y1 % p, p - 2, p) if Pa == Pb
               else (y2 - y1) * pow((x2 - x1) % p, p - 2, p)) % p
        x3 = (lam * lam - x1 - x2) % p
        return (x3, (lam * (x1 - x3) - y1) % p)

    R, Q = None, G
    while d:
        if d & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        d >>= 1
    return R


def _pems(path):
    """Inventory of armor blocks and distinct RSA moduli over the whole file."""
    with open(_resolve(path), 'rb') as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        literals, rsa, keys = {}, {}, {}
        for m in re.finditer(rb'-----BEGIN ([A-Z ]+)-----', mm):
            kind = m.group(1).decode()
            literals[kind] = literals.get(kind, 0) + 1
            if kind == 'PUBLIC KEY':
                body = mm[m.end():mm.find(b'-----END', m.end())]
                try:
                    k = RSAKey.import_key(base64.b64decode(b''.join(body.split())))
                    rsa[m.start()] = k
                    keys[hashlib.sha256(k.n.to_bytes((k.n.bit_length() + 7) // 8, 'big')
                                        ).hexdigest()[:16]] = (m.start(), k.size_in_bits())
                except Exception:                      # noqa: BLE001
                    rsa[m.start()] = None
        mm.close()
    bits = sorted(b for _, b in keys.values())
    return {'literals': literals, 'spki_blocks': len(rsa), 'distinct': len(keys),
            'bits_list': ','.join(str(b) for b in bits),
            'bits_2048_count': bits.count(2048),
            'offset_2048': next((o for o, b in keys.values() if b == 2048), None),
            'objects': rsa,
            'keys': {k: (o, b) for k, (o, b) in keys.items()}}


def derive(rule, values):
    """Compute one number. values — numbers already computed (used by expr)."""
    k = rule['kind']
    if k == 'const':
        return rule['value']
    if k == 'size':
        return os.path.getsize(_resolve(rule['path']))
    if k == 'hash':
        h = {'sha256': hashlib.sha256, 'md5': hashlib.md5, 'sha1': hashlib.sha1}[rule['algo']]()
        with open(_resolve(rule['path']), 'rb') as f:
            for b in iter(lambda: f.read(1 << 22), b''):
                h.update(b)
        return h.hexdigest()
    if k == 'hex':
        return _read(rule['path'], rule['off'], rule['len']).hex()
    if k == 'u32':
        return struct.unpack(('>' if rule.get('endian', 'big') == 'big' else '<') + 'I',
                             _read(rule['path'], rule['off'], 4))[0]
    if k == 'find':
        needle = rule['needle'].encode(rule.get('enc', 'utf-8'))
        with open(_resolve(rule['path']), 'rb') as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            off = mm.find(needle, rule.get('start', 0))
            mm.close()
        if off < 0:
            raise AssertionError('not found: %r' % needle)
        return off + rule.get('delta', 0)
    if k == 'json':
        cur = json.load(open(_resolve(rule['path'])))
        for part in rule['ptr'].split('.'):
            cur = cur[int(part)] if isinstance(cur, list) else cur[part]
        return cur
    if k == 'count':
        return _stream_scan(rule['path'], [rule['needle'].encode(rule.get('enc', 'utf-8'))]
                            )[rule['needle'].encode(rule.get('enc', 'utf-8'))]
    if k == 'counts':
        enc = rule.get('enc', 'utf-8')
        needles = [n.encode(enc) for n in rule['needles']]
        got = _stream_scan(rule['path'], needles)
        return [got[n] for n in needles]
    if k == 'tar':
        members = _tar_walk(rule['path'], rule['off'], rule['size'])
        cand = sorted((n for n in members if n.endswith(rule['suffix'])), key=len)
        if not cand:
            raise AssertionError('there is no member with suffix %r' % rule['suffix'])
        want = rule.get('field', 'off')
        return members[cand[0]][0 if want == 'off' else 1]
    if k == 'expr':
        env = {kk: values[vv] for kk, vv in rule.get('vars', {}).items()}
        return eval(rule['expr'], {'__builtins__': {'round': round, 'int': int,
                                                    'abs': abs, 'len': len}}, env)   # noqa: S307
    if k == 'header':
        return _fdat_header(rule['path'])[rule['field']]
    if k == 'udid':
        off = _fdat_payload_off(rule['path'])
        udid = _read(rule['path'], off - 68, 60)      # payload of the UDID block
        cnt = struct.unpack('>I', udid[0:4])[0]
        ent = [(struct.unpack('>H', udid[4 + 8 * i:6 + 8 * i])[0],
                struct.unpack('>H', udid[6 + 8 * i:8 + 8 * i])[0],
                struct.unpack('<I', udid[8 + 8 * i:12 + 8 * i])[0])
               for i in range((len(udid) - 4) // 8)]
        return {'count': cnt, 'entries': ent,
                'list': ','.join('%04x:%04x' % (v, p) for p, v, _ in ent),
                'flags': ','.join(str(f) for _, _, f in ent),
                'updater_pid': '0x%04x' % ent[-1][0]}[rule['field']]
    if k == 'dend':
        size = os.path.getsize(_resolve(rule['path']))
        c = binascii.crc32(_read(rule['path'], 0, size - 12)) & 0xffffffff
        stored = struct.unpack('>I', _read(rule['path'], size - 4, 4))[0]
        return {'computed': '0x%08x' % c, 'stored': '0x%08x' % stored,
                'equal': c == stored, 'offset': size - 12}[rule['field']]
    if k == 'ecb':
        import numpy as np
        off = _fdat_payload_off(rule['path'])
        cipher_len = 743818240
        step = 1 << 24
        runs, prev_last, done = [], None, 0
        with open(_resolve(rule['path']), 'rb') as fh:
            fh.seek(off)
            while done < cipher_len:
                buf = fh.read(min(step, cipher_len - done))
                if not buf:
                    break
                n = len(buf) // 16
                a = np.frombuffer(buf[:n * 16], dtype=np.uint8).reshape(n, 16)
                if prev_last is not None and np.array_equal(a[0], prev_last):
                    runs.append((done // 16 - 1, 2))
                eq = np.all(a[1:] == a[:-1], axis=1)
                idx = np.nonzero(eq)[0]
                if len(idx):
                    br = np.nonzero(np.diff(idx) != 1)[0]
                    starts = np.concatenate(([0], br + 1))
                    ends = np.concatenate((br, [len(idx) - 1]))
                    for s, e in zip(starts, ends):
                        runs.append((done // 16 + int(idx[s]), int(e - s + 2)))
                prev_last = a[-1].copy()
                done += n * 16
        return {'runs': len(runs), 'start': runs[0][0] if runs else None,
                'length': runs[0][1] if runs else None,
                'start_byte': (runs[0][0] * 16) if runs else None,
                'length_bytes': (runs[0][1] * 16) if runs else None,
                'cipher_bytes': cipher_len}[rule['field']]
    if k == 'pems':
        p = _pems(rule['path'])
        if rule['field'] == 'certificate_literals':
            return p['literals'].get('CERTIFICATE', 0)
        if rule['field'] == 'openssh_begin_literals':
            return p['literals'].get('OPENSSH PRIVATE KEY', 0)
        if rule['field'] == 'openssh_total_literals':
            return 2 * p['literals'].get('OPENSSH PRIVATE KEY', 0)
        if rule['field'] == 'encrypted_pk_literals':
            return p['literals'].get('ENCRYPTED PRIVATE KEY', 0)
        if rule['field'] == 'public_key_literals':
            return p['literals'].get('PUBLIC KEY', 0)
        if rule['field'] == 'spki_blocks':
            return p['spki_blocks']
        if rule['field'] == 'rsa_distinct':
            return p['distinct']
        if rule['field'] == 'rsa_bits':
            return p['bits_list']
        if rule['field'] == 'rsa_2048_offset':
            return p['offset_2048']
        raise KeyError(rule['field'])
    if k == 'keyblock':
        off = rule['off']
        win = _read(rule['path'], off, 700)
        end = win.find(b'-----END OPENSSH PRIVATE KEY-----') + len(b'-----END OPENSSH PRIVATE KEY-----')
        block = win[:end]
        kb = _openssh_key(block)
        blob = kb['pub']
        if rule['field'] == 'offset':
            return off
        if rule['field'] == 'block_bytes':
            return len(block)
        if rule['field'] == 'b64_chars':
            return len(block) - 35 - 1 - 33
        if rule['field'] == 'type':
            return kb['keytype'].decode()
        if rule['field'] == 'blob_sha256':
            return hashlib.sha256(blob).hexdigest()
        if rule['field'] == 'fingerprint':
            import tempfile
            d = tempfile.mkdtemp(prefix='numpem_')
            p = os.path.join(d, 'k.pub')
            with open(p, 'wb') as fh:
                fh.write(b'ecdsa-sha2-nistp256 ' + base64.b64encode(blob) + b'\n')
            out = subprocess.run(['ssh-keygen', '-lf', p], capture_output=True, text=True,
                                 timeout=30).stdout.strip()
            return re.search(r'SHA256:\S+', out).group(0)
        if rule['field'] == 'dG_equals_Q':
            Q = kb['Q'][1:]
            G = _p256_mul(int.from_bytes(kb['d'], 'big'))
            return bool(G and G[0] == int.from_bytes(Q[:32], 'big')
                        and G[1] == int.from_bytes(Q[32:], 'big'))
        if rule['field'] == 'comment':
            return kb['comment'].decode()
        if rule['field'] == 'cipher_kdf':
            return '%s/%s' % (kb['cipher'].decode(), kb['kdf'].decode())
        raise KeyError(rule['field'])
    if k == 'tail':
        off = _fdat_payload_off(rule['path'])
        base = off + 743818240
        tb = _read(rule['path'], base, 272)
        if rule['field'] == 'bytes':
            return len(tb)
        if rule['field'] == 'iv':
            return tb[:16].hex()
        if rule['field'] == 'sig_bytes':
            return len(tb[16:])
        if rule['field'] == 'read_at':
            return base
        raise KeyError(rule['field'])
    if k == 'sig_prefix':
        p = _pems(rule.get('keys_path', rule['path']))
        off2048 = p['offset_2048']
        key = p['objects'].get(off2048)
        if key is None:
            raise AssertionError('the 2048-bit key did not parse')
        tailoff = _fdat_payload_off(rule['path']) + 743818240 + 16
        sig = _read(rule['path'], tailoff, 256)
        mb = pow(int.from_bytes(sig, 'big'), key.e, key.n).to_bytes(256, 'big')
        return {'prefix_hex': mb[:2].hex(), 'pkcs1_v15': bool(mb[0] == 0 and mb[1] == 1)}[
            rule['field']]
    if k == 'squashfs':
        root = _resolve(rule['root'])
        files = [(os.path.relpath(os.path.join(dp, x), root), os.path.getsize(os.path.join(dp, x)))
                 for dp, dn, fn in os.walk(root) for x in fn]
        elfs = scripts = 0
        for rel, sz in files:
            head = open(os.path.join(root, rel), 'rb').read(20)
            if head[:4] == b'\x7fELF':
                elfs += 1
            elif head[:2] == b'#!':
                scripts += 1
        return {'files': len(files), 'elf': elfs, 'scripts': scripts,
                'bytes': sum(s for _, s in files)}[rule['field']]
    if k == 'filefield':
        txt = open(_resolve(rule['path']), encoding='utf-8', errors='replace').read()
        if rule.get('mode') == 'count_lines':
            return sum(1 for l in txt.splitlines() if rule['needle'] in l)
        m = re.search(rule['pattern'], txt)
        return m.group(int(rule.get('group', 1)))
    raise KeyError('unknown rule: %r' % k)
