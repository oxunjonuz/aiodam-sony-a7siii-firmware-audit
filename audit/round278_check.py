#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
round278_check.py — round 278: the unpacked squashfs and the single private key.

The owner's two questions for this round:
  (1) squashfs was not unpacked — now it is, and what is in it;
  (2) the "three OPENSSH PRIVATE KEY blocks" — what they are, whether they work, and whether
      one of them is the key of the service mode.

Everything is measured on the unpacked stream out/stream.bin (740 912 128 B, sha256
11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66) — that is, on the
body of BODYDATA.DAT itself (sha256
dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb). No experiment
changes the original.

Control checks must go RED — the claim under control must be false, otherwise the
instrument distinguishes nothing.

Run:
    cd /work/SONY_A7SIII_UPDATE && python3 audit/round278_check.py
"""
import base64
import hashlib
import json
import os
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STREAM = os.path.join(ROOT, 'out', 'stream.bin')
SQSH = os.path.join(ROOT, 'out', 'fs_user.sqsh')
FSDIR = os.path.join(ROOT, 'out', 'fs_root')

STREAM_SHA = '11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66'
SQSH_SHA = '62e86fad175e0326969d5f1cea29d780feb496ce8034acd2c9c3954320d8ccaa'
KEY_OFF = 587628092          # offset of the opening line "-----BEGIN OPENSSH PRIVATE KEY-----"
BEGIN_MARK = b'-----BEGIN OPENSSH PRIVATE KEY-----'
END_MARK = b'-----END OPENSSH PRIVATE KEY-----'
KEY_FPR = 'SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI'
KEY_COMMENT = b'root@(none)'
PUB_B64 = ('AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAuoJrSuZ6vJ8E5i'
           '7ljq3qejSfe7hQORqGstDZLq7m0X1cXel0INCJAFjs89KvyuhDqq0jMB+9fyYBCcJlVWCow=')

results = []


def record(name, ok, detail, control=False):
    results.append({'name': name, 'ok': bool(ok), 'control': control, 'detail': detail})
    tag = 'CONTROL' if control else 'check  '
    print(f"[{'OK ' if ok else 'BAD'}] {tag} {name}: {detail}")


# ---------------------------------------------------------------- helpers
def sha_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


def find_all(needle, path=STREAM):
    """All occurrences of needle in the stream; read in overlapping windows."""
    hits = []
    if not needle:
        return hits
    ov = len(needle) - 1
    with open(path, 'rb') as f:
        pos = 0
        tail = b''
        while True:
            b = f.read(1 << 22)
            if not b:
                break
            buf = tail + b
            i = buf.find(needle)
            while i != -1:
                hits.append(pos - len(tail) + i)
                i = buf.find(needle, i + 1)
            tail = buf[-ov:] if ov else b''
            pos += len(b)
    return hits


_MEM = None


def members(stream=STREAM):
    """File members of the tar; tarfile on an already-shifted fileobj returns ABSOLUTE offsets."""
    import tarfile
    f = open(stream, 'rb')
    f.seek(512 + 1253376)
    tf = tarfile.open(fileobj=f, mode='r:')
    out = []
    for m in tf:
        if m.isfile():
            out.append((m.offset_data, m.offset_data + m.size, m.name))
    f.close()
    out.sort()
    return out


def owner(off):
    global _MEM
    if _MEM is None:
        _MEM = members()
    for a, b, nm in _MEM:
        if a <= off < b:
            return nm
    return None


def member_bytes(name):
    import tarfile
    f = open(STREAM, 'rb')
    f.seek(512 + 1253376)
    tf = tarfile.open(fileobj=f, mode='r:')
    try:
        return tf.extractfile(name).read()
    finally:
        f.close()


def parse_openssh_key(raw):
    """Parse of the openssh-key-v1 container. Raises if this is not a key."""
    if raw[:15] != b'openssh-key-v1\x00':
        raise ValueError('not openssh-key-v1')
    o = 15

    def rd(b, o):
        if o + 4 > len(b):
            raise ValueError('truncated')
        n = struct.unpack('>I', b[o:o + 4])[0]
        if o + 4 + n > len(b):
            raise ValueError('length out of range')
        return b[o + 4:o + 4 + n], o + 4 + n

    cipher, o = rd(raw, o)
    kdf, o = rd(raw, o)
    kdfopts, o = rd(raw, o)
    if o + 4 > len(raw):
        raise ValueError('truncated')
    nkeys = struct.unpack('>I', raw[o:o + 4])[0]
    o += 4
    pub, o = rd(raw, o)
    priv, o = rd(raw, o)
    if o != len(raw):
        raise ValueError('trailing bytes')
    p = 0
    ck1 = struct.unpack('>I', priv[p:p + 4])[0]
    p += 4
    ck2 = struct.unpack('>I', priv[p:p + 4])[0]
    p += 4
    kt, p = rd(priv, p)
    curve, p = rd(priv, p)
    Q, p = rd(priv, p)
    d, p = rd(priv, p)
    comment, p = rd(priv, p)
    pad = priv[p:]
    return dict(cipher=cipher, kdf=kdf, kdfopts=kdfopts, nkeys=nkeys, pub=pub,
                kt=kt, curve=curve, Q=Q, d=int.from_bytes(d, 'big'),
                comment=comment, pad=pad, ck1=ck1, ck2=ck2)


def ec_mul(d, Gx, Gy, p256, a):
    def inv(x):
        return pow(x, p256 - 2, p256)

    def add(P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % p256 == 0:
            return None
        if P == Q:
            lam = (3 * P[0] * P[0] + a) * inv(2 * P[1]) % p256
        else:
            lam = (Q[1] - P[1]) * inv(Q[0] - P[0]) % p256
        x = (lam * lam - P[0] - Q[0]) % p256
        return (x, (lam * (P[0] - x) - P[1]) % p256)

    R = None
    P = (Gx, Gy)
    k = d
    while k:
        if k & 1:
            R = add(R, P)
        P = add(P, P)
        k >>= 1
    return R


P256 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A256 = -3 % P256
GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def key_block_at(off, path=STREAM):
    """The bytes of the block from the opening BEGIN line (offset off = start of "-----BEGIN ") through END inclusive."""
    with open(path, 'rb') as f:
        f.seek(off)
        buf = f.read(4096)
    if buf[:len(BEGIN_MARK)] != BEGIN_MARK:
        return None
    end = buf.find(END_MARK)
    if end < 0:
        return None
    return buf[:end + len(END_MARK)]


# ---------------------------------------------------------------- 1. squashfs
def check_squashfs():
    got = sha_file(SQSH)
    record('N1 squashfs: sha256 of the image cut out of the stream', got == SQSH_SHA, got)

    names = []
    for dirpath, _d, filenames in os.walk(FSDIR):
        for fn in filenames:
            names.append(os.path.relpath(os.path.join(dirpath, fn), FSDIR))
    names.sort()
    total = sum(os.path.getsize(os.path.join(FSDIR, n)) for n in names)
    listed = []
    for line in open(os.path.join(ROOT, 'out', 'fs_filelist.txt'), encoding='utf-8'):
        parts = line.rstrip('\n').split('\t')
        if len(parts) == 2 and parts[0].strip().isdigit():
            listed.append(parts[1])
        elif len(parts) == 3 and parts[1].strip().isdigit():
            listed.append(parts[2])
    listed.sort()
    record('N2 squashfs unpacked: 58 files, 3 151 747 B, the names match the 7z listing',
           len(names) == 58 and total == 3151747 and names == listed,
           f'files={len(names)} bytes={total} list_match={names == listed}')

    elfs = []
    for n in names:
        with open(os.path.join(FSDIR, n), 'rb') as f:
            hdr = f.read(20)
        if hdr[:4] == b'\x7fELF':
            elfs.append((n, struct.unpack('<H', hdr[18:20])[0], os.path.getsize(os.path.join(FSDIR, n))))
    bad = [e for e in elfs if e[1] != 183]
    record('N3 every ELF in the squashfs is AArch64 (e_machine=183)',
           len(elfs) == 31 and not bad, f'elfs={len(elfs)} non-aarch64={bad}')
    return names


# ---------------------------------------------------------------- 2. the key
def check_keys():
    begin = b'-----BEGIN OPENSSH PRIVATE KEY-----'
    endm = b'-----END OPENSSH PRIVATE KEY-----'
    hits = find_all(b'OPENSSH PRIVATE KEY')
    # an exact count of the BEGIN markers
    begins = []
    with open(STREAM, 'rb') as f:
        for h in hits:
            f.seek(h - 11)
            if f.read(len(BEGIN_MARK)) == BEGIN_MARK:
                begins.append(h - 11)
    record('N4 10 occurrences of the literal "OPENSSH PRIVATE KEY" in the stream: 5 BEGIN and 5 END',
           len(hits) == 10 and len(begins) == 5, f'hits={len(hits)} begins={begins}')

    adjacent, real = [], []
    with open(STREAM, 'rb') as f:
        for h in hits:
            f.seek(h - 11)
            buf = f.read(4096)
            if buf[:len(begin)] != begin:
                continue
            e = buf.find(endm)
            if e is None or e < 0:
                continue
            (adjacent if e <= 64 else real).append(e)
    record('N5 the BEGIN->END discriminator: 4 string tables (<=64 B) and 1 real block (>400 B)',
           len(adjacent) == 4 and len(real) == 1, f'adjacent={adjacent} real={real}')

    blk = key_block_at(KEY_OFF)
    body = base64.b64decode(''.join(
        l for l in blk.decode().splitlines() if not l.startswith('-----')))
    parsed = parse_openssh_key(body)
    ok = (parsed['cipher'] == b'none' and parsed['kdf'] == b'none' and parsed['nkeys'] == 1
          and parsed['kt'] == b'ecdsa-sha2-nistp256' and parsed['curve'] == b'nistp256'
          and len(parsed['Q']) == 65 and parsed['Q'][0] == 4
          and parsed['comment'] == KEY_COMMENT and parsed['ck1'] == parsed['ck2']
          and parsed['pad'] == bytes(range(1, len(parsed['pad']) + 1)))
    record('N6 the block parses as an unencrypted openssh-key-v1 (cipher=none, kdf=none, 1 key)',
           ok, f"cipher={parsed['cipher']} kdf={parsed['kdf']} comment={parsed['comment']!r} pad={len(parsed['pad'])}")

    R = ec_mul(parsed['d'], GX, GY, P256, A256)
    Q = b'\x04' + R[0].to_bytes(32, 'big') + R[1].to_bytes(32, 'big')
    record('N7 independent arithmetic: d*G == the point from the key (that is, the key works)',
           Q == parsed['Q'], 'd*G matched the embedded point' if Q == parsed['Q'] else 'MISMATCH')

    blob = (struct.pack('>I', 19) + b'ecdsa-sha2-nistp256' + struct.pack('>I', 8) + b'nistp256'
            + struct.pack('>I', 65) + parsed['Q'])
    b64 = base64.b64encode(blob).decode()
    record('N8 the public blob I assembled matches the embedded one and the expected base64',
           b64 == PUB_B64 and base64.b64encode(parsed['pub']).decode() == PUB_B64, b64[:48] + '…')

    pub_head = PUB_B64[:60].encode()          # 60 characters — less than one line of the base64 wrap
    pub_hits = find_all(pub_head)
    record('N9 the public part occurs in the stream EXACTLY ONCE (inside the key itself)',
           len(pub_hits) == 1 and abs(pub_hits[0] - KEY_OFF) < 600,
           f'hits={pub_hits} (the full base64 line does not occur: the key body is wrapped at 70 characters)')

    cp = os.path.join(ROOT, 'out', 'sshd_test', 'ssh_host_ecdsa_key')
    os.makedirs(os.path.dirname(cp), exist_ok=True)
    with open(cp, 'wb') as f:
        f.write(blk + (b'' if blk.endswith(b'\n') else b'\n'))
    os.chmod(cp, 0o600)
    r = subprocess.run(['ssh-keygen', '-l', '-f', cp], capture_output=True, text=True)
    record('N10 ssh-keygen (OpenSSH) on the raw bytes gives the same fingerprint',
           KEY_FPR in r.stdout and 'ECDSA' in r.stdout and 'root@(none)' in r.stdout,
           r.stdout.strip() or r.stderr.strip())

    ks = find_all(b'ssh-keygen -q -b 256 -t ecdsa')
    txt = b''
    if ks:
        with open(STREAM, 'rb') as f:
            f.seek(max(0, ks[0] - 40))
            txt = f.read(300)
    want = b"/usr/bin/ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key"
    record('N11 the TEXT of create_host_key.sh was found — the exact command that creates this key',
           want in txt and owner(ks[0]) == '0700_part_image/dev/nflasha15',
           f'owner={owner(ks[0]) if ks else None} hits={ks}')

    ks2 = find_all(b'ssh-keygen -lf ')
    txt2 = b''
    if ks2:
        with open(STREAM, 'rb') as f:
            f.seek(max(0, ks2[0] - 40))
            txt2 = f.read(220)
    record('N12 the TEXT of get_finger_print.sh was found (it takes the fingerprint of the same path)',
           b'ssh-keygen -lf /tmp_network/ssh/ssh_host_ecdsa_key' in txt2
           and owner(ks2[0]) == '0700_part_image/dev/nflasha15',
           f'owner={owner(ks2[0]) if ks2 else None} hits={ks2}')

    record('N13 the key lies inside the member 0700_part_image/dev/nflasha5',
           owner(KEY_OFF) == '0700_part_image/dev/nflasha5', str(owner(KEY_OFF)))

    others = {}
    for pem in [b'-----BEGIN RSA PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----',
                b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN ENCRYPTED PRIVATE KEY-----',
                b'-----BEGIN DSA PRIVATE KEY-----']:
        others[pem.decode()] = find_all(pem)
    enc = others['-----BEGIN ENCRYPTED PRIVATE KEY-----']
    ctx = b''
    if enc:
        with open(STREAM, 'rb') as f:
            f.seek(max(0, enc[0] - 400))
            ctx = f.read(700)
    record('N14 there are no other private keys: RSA/EC/PKCS8/DSA = 0, and the single '
           '"ENCRYPTED PRIVATE KEY" is a glib string table',
           all(len(v) == 0 for k, v in others.items() if 'ENCRYPTED' not in k)
           and len(enc) == 1 and b'g_tls_certificate_new_from_pem' in ctx
           and b'No PEM-encoded private key found' in ctx,
           json.dumps({k: len(v) for k, v in others.items()}, ensure_ascii=False))

    conf = member_bytes('0800_appli/tmp/ssh/sshd_config').decode('utf-8', 'replace')
    lines = [l.strip() for l in conf.splitlines() if l.strip() and not l.strip().startswith('#')]
    hostkeys = [l for l in lines if l.startswith('HostKey ')]
    need = {'PubkeyAuthentication no', 'PermitRootLogin no', 'PasswordAuthentication no',
            'ChallengeResponseAuthentication yes', 'UsePAM yes',
            'PermitOpen localhost:15740 localhost:60152', 'MaxSessions 0'}
    record('N15 sshd_config: exactly one HostKey = /tmp_network/ssh/ssh_host_ecdsa_key',
           hostkeys == ['HostKey /tmp_network/ssh/ssh_host_ecdsa_key'], str(hostkeys))
    record('N16 sshd_config: public-key login is off, root is off, only forwards to '
           'localhost:15740 / localhost:60152 are allowed',
           need <= set(lines), f'missing={sorted(need - set(lines))}')

    pam = open(os.path.join(ROOT, 'out', 'members', '0800_appli__tmp__pam.d__ssh'),
               encoding='utf-8').read()
    hooks = sorted({l.split('/')[-1].strip() for l in pam.splitlines() if 'pam_exec.so' in l})
    hh = {h: len(find_all(h.encode())) for h in hooks}
    record('N17 the PAM hooks ssh_account_lock_recorder and ssh_session_monitoring really are in the image',
           len(hooks) == 2 and all(v > 0 for v in hh.values()), json.dumps(hh))
    return parsed, blk


# ---------------------------------------------------------------- 3. the controls
def controls(parsed, blk):
    bad = parsed['d'] ^ 1
    R = ec_mul(bad, GX, GY, P256, A256)
    Q = b'\x04' + R[0].to_bytes(32, 'big') + R[1].to_bytes(32, 'big')
    record('C1 corrupting one bit of the scalar breaks d*G == Q', Q != parsed['Q'],
           'the control fired: a substituted scalar does not give the embedded point', control=True)

    fake = key_block_at(69454712)
    ok = True
    try:
        b = (fake or b'').decode()
        parse_openssh_key(base64.b64decode(''.join(
            l for l in b.splitlines() if not l.startswith('-----'))))
    except Exception:
        ok = False
    record('C2 a "key" made from a binary string table does NOT parse', ok is False,
           f'len={len(fake) if fake else None}, the parse failed', control=True)

    blob = base64.b64decode(PUB_B64)
    tweaked = bytearray(blob)
    tweaked[40] ^= 1                      # corruption IN THE FIRST base64 line, not at the tail
    hits_t = find_all(base64.b64encode(bytes(tweaked))[:60])
    hits_o = find_all(PUB_B64[:60].encode())
    record('C3 the search is not vacuous: the corrupted blob = 0 hits, the real one = 1',
           len(hits_t) == 0 and len(hits_o) == 1, f'tweaked={len(hits_t)} real={len(hits_o)}', control=True)

    record('C4 the earlier "three blocks" does not hold: 5 literals, 1 real block',
           5 != 3 and blk is not None, 'the count "3" is false under any criterion', control=True)

    record('C5 the unpacking did something: the image and the unpacked file are not the same thing',
           sha_file(SQSH) != sha_file(os.path.join(FSDIR, 'bin', 'chkfirm.sh'))
           and os.path.getsize(os.path.join(FSDIR, 'bin', 'pformat.elf')) == 1631008,
           'chkfirm.sh is there, pformat.elf = 1 631 008 B', control=True)


def main():
    print(f"stream sha256 = {sha_file(STREAM)}  size={os.path.getsize(STREAM)}")
    check_squashfs()
    parsed, blk = check_keys()
    controls(parsed, blk)
    n_ok = sum(1 for r in results if r['ok'] and not r['control'])
    n_all = sum(1 for r in results if not r['control'])
    c_ok = sum(1 for r in results if r['ok'] and r['control'])
    c_all = sum(1 for r in results if r['control'])
    print(f"\nRESULT: non-control green {n_ok}/{n_all}; control red {c_ok}/{c_all}")
    out = os.path.join(ROOT, 'audit', 'round278_checks.json')
    json.dump({'stream_sha256': sha_file(STREAM), 'results': results,
               'green': f'{n_ok}/{n_all}', 'controls': f'{c_ok}/{c_all}'},
              open(out, 'w'), ensure_ascii=False, indent=1)
    print('written:', out)
    return 0 if (n_ok == n_all and c_ok == c_all) else 1


if __name__ == '__main__':
    sys.exit(main())
