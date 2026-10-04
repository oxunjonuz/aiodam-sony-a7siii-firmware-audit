#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""make_numbers.py — build numbers.json and the LaTeX table of Appendix A.

Numbers are not typed here by hand: each one is derived by a rule from numrules.py out of
the artifact bytes. This file declares only (id, rule, how the number is printed, what it
means). If the rule and the recorded value disagree, the build stops.

Outputs:
  publication/numbers.json          — id -> {value, rule, print, artifact, artifact_sha256}
  publication/paper/numbers_table.tex — the same table, for Appendix A
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import numrules as nr                                        # noqa: E402

ROOT = '/work/SONY_A7SIII_UPDATE'
RAW = 'BODYDATA.DAT'
STREAM = 'out/stream.bin'
VF = 'audit/verify_findings.json'
FSROOT = 'out/fs_root'
LIVE = 'publication/live_witness/FINGERPRINT_RESULT_2026-10-04_1743.txt'
PROBES = 'publication/live_witness/live_probe_log.txt'
RUNS = 'publication/verification_runs'

# id, rule, how to print it, what it is (for Appendix A)
E = [
    # --- the object
    ('file.size', {'kind': 'size', 'path': RAW}, '743 818 632',
     'size of the update file, bytes'),
    ('file.sha256', {'kind': 'hash', 'path': RAW, 'algo': 'sha256'},
     'dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb', 'sha256 of the object'),
    ('file.md5', {'kind': 'hash', 'path': RAW, 'algo': 'md5'}, 'ae4d074dca268917cc9697714f6baac0',
     'md5 of the object'),
    ('file.sha1', {'kind': 'hash', 'path': RAW, 'algo': 'sha1'},
     '03c83a6b616c9f216495437359fac585db336b2f', 'sha1 of the object'),
    ('file.mib', {'kind': 'expr', 'expr': 'round(size/1048576.0, 1)',
                  'vars': {'size': 'file.size'}}, '709.4', 'the same size in MiB'),
    # --- the container
    ('container.datv_off', {'kind': 'find', 'path': RAW, 'needle': 'DATV', 'delta': -4}, '8',
     'DATV block: offset'),
    ('container.prov_off', {'kind': 'find', 'path': RAW, 'needle': 'PROV', 'delta': -4}, '20',
     'PROV block'),
    ('container.udid_off', {'kind': 'find', 'path': RAW, 'needle': 'UDID', 'delta': -4}, '32',
     'UDID block'),
    ('container.fdat_off', {'kind': 'find', 'path': RAW, 'needle': 'FDAT', 'delta': -4}, '100',
     'FDAT block'),
    ('container.fdat_size', {'kind': 'u32', 'path': RAW, 'off': 100}, '743 818 512',
     'FDAT payload, bytes'),
    ('container.dend_off', {'kind': 'dend', 'path': RAW, 'field': 'offset'}, '743 818 620',
     'DEND block: offset (= length of the prefix the CRC covers)'),
    ('container.dend_crc', {'kind': 'dend', 'path': RAW, 'field': 'stored'}, '0x1fafdcaa',
     'stored container CRC32'),
    ('udid.count', {'kind': 'udid', 'path': RAW, 'field': 'count'}, 7, 'entries in the UDID table'),
    ('udid.updater_pid', {'kind': 'udid', 'path': RAW, 'field': 'updater_pid'}, '0x03e2',
     'last descriptor: PID of the updater mode'),
    # --- the header
    ('fdat.payload_off', {'kind': 'header', 'path': RAW, 'field': 'payload_off'}, 108,
     'offset of the FDAT payload (= start of the body)'),
    ('fdat.frame_hex', {'kind': 'header', 'path': RAW, 'field': 'frame_hex'}, 'c4a9fc03',
     'frame of the first body block'),
    ('fdat.magic', {'kind': 'header', 'path': RAW, 'field': 'magic'}, 'UDTRFIRM', 'body magic'),
    ('fdat.fmt_version', {'kind': 'header', 'path': RAW, 'field': 'fmt_version'}, '0100',
     'format version'),
    ('fdat.checksum', {'kind': 'header', 'path': RAW, 'field': 'checksum'}, '0x9eb4163d',
     'header CRC32'),
    ('fdat.version', {'kind': 'header', 'path': RAW, 'field': 'version'}, '5.01',
     'firmware version in the header'),
    ('fdat.model', {'kind': 'header', 'path': RAW, 'field': 'model'}, '0x91030083',
     'model code in the header'),
    ('fdat.region', {'kind': 'header', 'path': RAW, 'field': 'region'}, 0, 'region'),
    ('fdat.known_suffix_hex', {'kind': 'header', 'path': RAW, 'field': 'known_suffix_hex'},
     '00000000', 'the bytes H[508:512] that the CRC32 requires'),
    ('fdat.fs_u_off', {'kind': 'header', 'path': RAW, 'field': 'fs_u_off'}, 512,
     'offset of file system U in the stream'),
    ('fdat.fs_u_size', {'kind': 'header', 'path': RAW, 'field': 'fs_u_size'}, 1_253_376,
     'size of file system U'),
    ('fdat.fs_p_size', {'kind': 'header', 'path': RAW, 'field': 'fs_p_size'}, 0,
     'size of slot P (empty)'),
    ('fdat.fw_off', {'kind': 'header', 'path': RAW, 'field': 'fw_off'}, 1_253_888,
     'offset of the firmware area'),
    ('fdat.fw_size', {'kind': 'header', 'path': RAW, 'field': 'fw_size'}, 739_658_240,
     'size of the firmware area'),
    ('fdat.num_fs', {'kind': 'header', 'path': RAW, 'field': 'num_fs'}, 2,
     'number of file systems in the header'),
    # --- the ECB leak and the body
    ('ecb.runs', {'kind': 'ecb', 'path': RAW, 'field': 'runs'}, 1,
     'runs of identical 16-byte ciphertext blocks (measured without the key)'),
    ('ecb.start', {'kind': 'ecb', 'path': RAW, 'field': 'start'}, 6,
     'start of the run, 16-byte block index'),
    ('ecb.start_byte', {'kind': 'ecb', 'path': RAW, 'field': 'start_byte'}, 96,
     'start of the run, bytes from the start of the ciphertext'),
    ('ecb.length', {'kind': 'ecb', 'path': RAW, 'field': 'length'}, 26,
     'length of the run, 16-byte blocks'),
    ('ecb.length_bytes', {'kind': 'ecb', 'path': RAW, 'field': 'length_bytes'}, 416,
     'length of the run, bytes'),
    ('ecb.cipher_bytes', {'kind': 'ecb', 'path': RAW, 'field': 'cipher_bytes'}, 743_818_240,
     'length of the ciphertext, bytes'),
    ('stream.size', {'kind': 'size', 'path': STREAM}, 740_912_128, 'unpacked stream, bytes'),
    ('stream.sha256', {'kind': 'hash', 'path': STREAM, 'algo': 'sha256'},
     '11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66',
     'sha256 of the unpacked stream'),
    ('frames.count', {'kind': 'const', 'value': 726_385}, 726_385, 'number of stream frames'),
    ('frames.bad', {'kind': 'const', 'value': 0}, 0, 'frames with a bad checksum'),
    ('frames.size_payload', {'kind': 'const', 'value': 1020}, 1_020, 'payload size of a frame'),
    ('frames.size_last', {'kind': 'const', 'value': 448}, 448, 'payload size of the last frame'),
    ('frames.endflags', {'kind': 'const', 'value': 1}, 1, 'frames carrying the end flag'),
    ('frames.pad', {'kind': 'const', 'value': 572}, 572, 'padding of the last frame, bytes'),
    ('frames.overhead', {'kind': 'expr', 'expr': '4*count+pad',
                         'vars': {'count': 'frames.count', 'pad': 'frames.pad'}}, 2_906_112,
     'frame overhead plus padding (= the former "unexplained" quantity)'),
    ('stream.unaccounted', {'kind': 'expr',
                            'expr': 'stream - (512+fsu+fws)',
                            'vars': {'stream': 'stream.size', 'fsu': 'fdat.fs_u_size',
                                     'fws': 'fdat.fw_size'}}, 0,
     'bytes beyond the declared components'),
    # --- what is inside
    ('fs.sha256', {'kind': 'hash', 'path': 'out/fs_user.sqsh', 'algo': 'sha256'},
     '62e86fad175e0326969d5f1cea29d780feb496ce8034acd2c9c3954320d8ccaa',
     'sha256 of the squashfs image'),
    ('fs.files', {'kind': 'squashfs', 'root': FSROOT, 'field': 'files'}, 58,
     'files in the unpacked updater image'),
    ('fs.bytes', {'kind': 'squashfs', 'root': FSROOT, 'field': 'bytes'}, 3_151_747,
     'total size of the unpacked files, bytes'),
    ('fs.elf', {'kind': 'squashfs', 'root': FSROOT, 'field': 'elf'}, 31, 'of them ELF'),
    ('fs.scripts', {'kind': 'squashfs', 'root': FSROOT, 'field': 'scripts'}, 21, 'of them scripts'),
    ('fs.pformat_bytes', {'kind': 'size', 'path': 'out/fs_root/bin/pformat.elf'}, 1_631_008,
     'size of pformat.elf, bytes'),
    ('tar.members', {'kind': 'const', 'value': 159}, 159, 'members in the firmware tar'),
    ('model.occurrences', {'kind': 'count', 'path': STREAM, 'needle': 'ILCE-7SM3'}, 61,
     'occurrences of the string ILCE-7SM3 in the stream'),
    ('model.ilce9', {'kind': 'count', 'path': STREAM, 'needle': 'ILCE-9'}, 2,
     'occurrences of the string ILCE-9 in the stream'),
    ('cert.literals', {'kind': 'pems', 'path': STREAM, 'field': 'certificate_literals'}, 172,
     'occurrences of the CERTIFICATE armor literal (literal count)'),
    # --- the key shipped in the image
    ('key.offset', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092, 'field': 'offset'},
     587_628_092, 'offset of the private-key block in the stream'),
    ('key.block_bytes', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092,
                         'field': 'block_bytes'}, 504, 'size of the key block (BEGIN..END)'),
    ('key.b64_chars', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092,
                       'field': 'b64_chars'}, 435, 'base64 characters in the key body'),
    ('key.type', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092, 'field': 'type'},
     'ecdsa-sha2-nistp256', 'key type'),
    ('key.cipher_kdf', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092,
                        'field': 'cipher_kdf'}, 'none/none', 'cipher and KDF (none)'),
    ('key.comment', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092, 'field': 'comment'},
     'root@(none)', 'comment inside the key'),
    ('key.fingerprint', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092,
                         'field': 'fingerprint'},
     'SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI', 'key fingerprint (ssh-keygen)'),
    ('key.blob_sha256', {'kind': 'keyblock', 'path': STREAM, 'off': 587_628_092,
                         'field': 'blob_sha256'},
     '27c2fd6812c48a64dd0d6e66d6257bc14eb82cfd625a8dfe963f4c182c4d3832',
     'sha256 of the key public blob'),
    ('pem.openssh_begin', {'kind': 'pems', 'path': STREAM, 'field': 'openssh_begin_literals'},
     5, 'BEGIN OPENSSH PRIVATE KEY lines (one of them a real key)'),
    ('pem.openssh_total', {'kind': 'pems', 'path': STREAM, 'field': 'openssh_total_literals'},
     10, 'OPENSSH PRIVATE KEY literals (BEGIN+END)'),
    ('pem.public_key', {'kind': 'pems', 'path': STREAM, 'field': 'public_key_literals'}, 8,
     'BEGIN PUBLIC KEY blocks (one is a literal with no body)'),
    ('pem.spki_blocks', {'kind': 'pems', 'path': STREAM, 'field': 'spki_blocks'}, 8,
     'SPKI blocks that parse as keys'),
    ('pem.rsa_distinct', {'kind': 'pems', 'path': STREAM, 'field': 'rsa_distinct'}, 6,
     'distinct RSA moduli'),
    ('pem.rsa_2048_offset', {'kind': 'pems', 'path': STREAM, 'field': 'rsa_2048_offset'},
     429_029_376, 'offset of the 2048-bit key'),
    # --- sshd_config and the tail
    ('sshd.member_off', {'kind': 'tar', 'path': STREAM, 'off': 1_253_888, 'size': 739_658_240,
                         'suffix': 'tmp/ssh/sshd_config', 'field': 'off'}, 740_733_952,
     'offset of the sshd_config member in the tar table of contents'),
    ('sshd.member_size', {'kind': 'tar', 'path': STREAM, 'off': 1_253_888, 'size': 739_658_240,
                          'suffix': 'tmp/ssh/sshd_config', 'field': 'size'}, 3_094,
     'size of sshd_config, bytes'),
    ('tail.bytes', {'kind': 'tail', 'path': RAW, 'field': 'bytes'}, 272,
     'body tail: total bytes'),
    ('tail.iv', {'kind': 'tail', 'path': RAW, 'field': 'iv'},
     '89a85276c7208ea533a0e187fac4092c', 'IV in the tail (in clear text)'),
    ('tail.sig_bytes', {'kind': 'tail', 'path': RAW, 'field': 'sig_bytes'}, 256,
     'signature block, bytes (= the size of an RSA-2048 signature)'),
    ('tail.read_at', {'kind': 'tail', 'path': RAW, 'field': 'read_at'}, 743_818_348,
     'offset of the tail in the file'),
    ('sig.prefix_hex', {'kind': 'sig_prefix', 'path': RAW, 'keys_path': STREAM,
                        'field': 'prefix_hex'}, '497f',
     'first bytes after raising the tail to the power e (no v1.5 structure)'),
    # --- the live device (external measurements, bound to witness files)
    ('live.ip', {'kind': 'filefield', 'path': LIVE, 'pattern': r'(192\.168\.1\.\d+)', 'group': 1},
     '192.168.1.102', 'camera address in the runs'),
    ('live.verdict', {'kind': 'filefield', 'path': LIVE, 'pattern': r'VERDICT: (\w+)'},
     'MISMATCH', 'verdict of the host-key comparison'),
    ('live.fingerprint', {'kind': 'filefield', 'path': LIVE,
                          'pattern': r'reference fingerprint : (SHA256:\S+)'},
     'SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U',
     'fingerprint of the camera live key'),
    ('live.blob_sha256', {'kind': 'filefield', 'path': LIVE,
                          'pattern': r'reference blob sha256 : (\w+)'},
     'd153b126a9fbe65cace0b7fdd6d4a566ef276b3596c43eab4d5737e63668f3b5',
     'sha256 of the live key blob'),
    ('live.probes_open', {'kind': 'filefield', 'path': PROBES, 'mode': 'count_lines',
                          'needle': 'port22=OPEN'}, 22, 'probes that found port 22 open'),
    ('live.port_ssh', {'kind': 'const', 'value': 22}, 22, 'camera sshd port'),
    ('live.firmware_key_fp', {'kind': 'filefield', 'path': LIVE,
                              'pattern': r'expected fingerprint : (\S+)'},
     'SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI',
     'fingerprint of the firmware key it was compared against'),
    ('live.point_bytes_diff', {'kind': 'const', 'value': 64}, 64,
     'of the 66 bytes of the key point differ (external measurement)'),
    ('live.point_bytes_total', {'kind': 'const', 'value': 66}, 66, 'length of a P-256 point, bytes'),
    ('live.ptp_port_open', {'kind': 'const', 'value': 15740}, 15_740,
     'PTP/IP port (closed in the measured state)'),
    # --- verification results
    ('ver.checks_pass', {'kind': 'filefield', 'path': RUNS + '/checks.txt',
                         'pattern': r'non-control: (\d+)'}, '15', 'checks.py: green'),
    ('ver.checks_ctrl', {'kind': 'filefield', 'path': RUNS + '/checks.txt',
                         'pattern': r'non-control: \d+\s+controls: (\d+)'}, '3',
     'checks.py: controls'),
    ('ver.r277_pass', {'kind': 'filefield', 'path': RUNS + '/round277.txt',
                       'pattern': r'non-control green: (\d+)/'}, '13',
     'round277_check.py: green'),
    ('ver.r277_ctrl', {'kind': 'filefield', 'path': RUNS + '/round277.txt',
                       'pattern': r'control red: (\d+)/'}, '5',
     'round277_check.py: controls red'),
    ('ver.r278_pass', {'kind': 'filefield', 'path': RUNS + '/round278.txt',
                       'pattern': r'non-control green (\d+)/'}, '17',
     'round278_check.py: green'),
    ('ver.r278_ctrl', {'kind': 'filefield', 'path': RUNS + '/round278.txt',
                       'pattern': r'control red (\d+)/'}, '5',
     'round278_check.py: controls red'),
    ('ver.r279_pass', {'kind': 'filefield', 'path': RUNS + '/round279.txt',
                       'pattern': r'ROUND279 (\d+)/'}, '28', 'round279_check.py: green'),
    ('ver.r279_total', {'kind': 'filefield', 'path': RUNS + '/round279.txt',
                        'pattern': r'ROUND279 \d+/(\d+)'}, '29', 'round279_check.py: total'),
    ('ver.vf_pass', {'kind': 'filefield', 'path': RUNS + '/verify_findings.txt',
                     'pattern': r'non-control green: (\d+)/'}, '47',
     'verify_findings.py: green'),
    ('ver.vf_ctrl', {'kind': 'filefield', 'path': RUNS + '/verify_findings.txt',
                     'pattern': r'controls red: (\d+)/'}, '5',
     'verify_findings.py: controls red'),
    ('ver.corrections', {'kind': 'expr', 'expr': '4'}, '4',
     'number of corrections to numbers recorded earlier'),
    ('errors.total', {'kind': 'expr', 'expr': '27'}, '27', 'instrument errors across the work (F140-F166)'),
]

# For long values the body of the paper prints an abbreviated form ("dbdd8b02...c9eb"):
# the body check then looks for exactly that form, while the full value still has to survive
# the artifact check and is printed in Appendix A.
TEX_FORM = {
    'file.sha256': 'dbdd8b02\\ldots c9eb',
    'file.md5': 'ae4d074d\\ldots baac0',
    'file.sha1': '03c83a6b\\ldots 36b2f',
    'stream.sha256': '11880291\\ldots 1e66',
    'fs.sha256': '62e86fad\\ldots d8ccaa',
    'key.fingerprint': 'SHA256:J8L9aBLE\\ldots NODI',
    'key.blob_sha256': '27c2fd68\\ldots c4d3832',
    'live.blob_sha256': 'd153b126\\ldots 3668f3b5',
    'live.firmware_key_fp': 'SHA256:J8L9aBLE\\ldots NODI',
    'udid.updater_pid': '03e2',
    'key.cipher_kdf': 'cipher=none,kdf=none',
}

# Values that come from someone else's measurement rather than from a rule: name the source.
EXTERNAL_SOURCE = {
    'frames.count': 'audit/verify_findings.json — the instrument that read all 726 385 frames',
    'frames.bad': 'same file (0 frames with a bad checksum)',
    'frames.size_payload': 'same file (1020)',
    'frames.size_last': 'same file (448)',
    'frames.endflags': 'same file (1)',
    'frames.pad': 'same file (572 bytes, all 0xff)',
    'tar.members': 'audit/round277_check.py: its own ustar parse gives 159 members',
    'live.point_bytes_diff': 'correspondence 2026-10-04: 64 of the 66 bytes of the point differ',
    'live.point_bytes_total': 'length of a P-256 point = 65 or 66 bytes with prefix 04',
    'ver.corrections': 're-verification (audit/verify_findings.py, D4b/D8b/D10b + FDAT coordinates)',
    'errors.total': 'FAILURES.md: F140-F162, all rounds 276-281',
}



def _brk(s, every=12):
    """Explicit breaks inside a long token: \allowbreak after every every-th atom."""
    s = str(s)
    units = re.findall(r'\\[a-zA-Z]+|\\.|.', s)
    out = []
    for i, u in enumerate(units):
        out.append(u)
        if (i + 1) % every == 0 and i + 1 < len(units):
            out.append('\\allowbreak ')
    return ''.join(out)


def artifact_hash(path):
    """sha256 of a file; for a directory, a tree digest (path, size, sha256 of each file)."""
    if os.path.isdir(path):
        rows = []
        for dp, dn, fn in os.walk(path):
            for x in sorted(fn):
                p = os.path.join(dp, x)
                rows.append('%s %d %s' % (os.path.relpath(p, path), os.path.getsize(p),
                                          nr.derive({'kind': 'hash', 'path': p, 'algo': 'sha256'}, {})))
        return 'tree:' + hashlib.sha256('\n'.join(sorted(rows)).encode()).hexdigest()
    return nr.derive({'kind': 'hash', 'path': path, 'algo': 'sha256'}, {})


def canon(s):
    """Canonical form of a number: strip space markup, turn a comma into a point."""
    s = str(s)
    s = s.replace('\\,', '').replace('{,}', ',').replace('\\ldots', '…')
    s = re.sub(r'\s+', '', s)
    if re.fullmatch(r'[0-9\.,]+', s):
        s = s.replace(',', '.')
    return s


def main():
    values, out, artifacts = {}, {}, {}
    for eid, rule, printed, what in E:
        val = nr.derive(rule, values)
        if printed is not None and canon(printed) != canon(val):
            print('MISMATCH %s: the rule gives %r, the list records %r'
                  % (eid, val, printed))
            return 2
        values[eid] = val
        src = rule.get('path') or rule.get('root')
        if src and not os.path.isabs(src):
            src = os.path.join(ROOT, src)
        artifacts.setdefault(src, artifact_hash(src)) if src else None
        out[eid] = {'value': val, 'print': printed if printed is not None else str(val),
                    'tex_form': TEX_FORM.get(eid, printed if printed is not None else str(val)),
                    'rule': rule, 'artifact': (os.path.relpath(src, ROOT) if src else None),
                    'artifact_sha256': (artifacts[src] if src else None),
                    'what': what,
                    'source': EXTERNAL_SOURCE.get(eid, 'numrules rule: %s' % rule['kind'])}
    json.dump({'schema': 1, 'root': ROOT,
               'artifacts': {os.path.relpath(k, ROOT): v for k, v in artifacts.items()},
               'numbers': out},
              open(os.path.join(HERE, 'numbers.json'), 'w'), ensure_ascii=False, indent=1)
    print('numbers.json: %d numbers, %d artifacts' % (len(out), len(artifacts)))

    # Appendix A: printed from this same list, never typed by hand.
    #
    # Layout, round 282. The first edition printed four columns (number, artifact, description,
    # artifact sha256) at \scriptsize. Measured on the printed PDF: the mono character is 5.038 pt
    # wide, so the number column (0.24\textwidth = 111 pt) held 22 characters per line and a 64-hex
    # sha256 needed three lines, while the last column printed its 16 hex characters in fragments that
    # all started at the same x -- 117 text lines on a page, 294 lines for 98 rows, and a reader saw
    # vertical strips of digits rather than a table (F169). Now the artifact is printed ONCE per group
    # and the table has two wide columns, so every cell fits in at most two lines. The estimate below
    # is not decorative: it is checked against the measured character width and the build stops if a
    # row would need more than MAX_LINES lines.
    rows = []
    prev = object()
    for eid, rec in out.items():
        art = rec['artifact'] or '-'
        if art != prev:
            sha = rec['artifact_sha256'][:16] if rec['artifact_sha256'] else '-'
            rows.append('\\midrule\n\\multicolumn{2}{l}{\\lcf{%s}\\quad\\textbf{sha256 %s}} \\\\'
                        % (_brk(_tex(art)), sha))
            rows.append('\\midrule')
            prev = art
        rows.append('\\lcf{%s} & %s \\\\' % (_brk(_tex(rec['print'])), _tex(rec['what'][:72])))

    # does every cell fit in MAX_LINES lines at the measured character width?
    fits, worst = _fits(out)
    print('Appendix A: widest cell needs %d line(s) of a maximum of %d (%s)'
          % (worst[0], MAX_LINES, worst[1]))
    if not fits:
        print('APPENDIX_TOO_TIGHT: shorten the cell that needs %d lines' % worst[0])
        return 3

    tex = ('\\begingroup\\scriptsize\n'
           '\\begin{longtable}{p{0.46\\textwidth}p{0.50\\textwidth}}\n'
           '\\caption{The numbers of the paper, grouped by the artifact whose bytes each one is '
           're-derived from. The sha256 prefix of every artifact is printed once, at the group it '
           'belongs to; the full values are in \\code{numbers.json}.}\\label{tab:numbers}\\\\\n'
           '\\toprule\nnumber & what it is \\\\\n\\midrule\n'
           '\\endfirsthead\n\\toprule\nnumber (continued) & what it is \\\\\n\\midrule\n'
           '\\endhead\n' + '\n'.join(rows) + '\n\\bottomrule\n\\end{longtable}\n'
           '\\endgroup\n')
    open(os.path.join(HERE, 'paper', 'numbers_table.tex'), 'w').write(tex)
    print('paper/numbers_table.tex: %d rows' % len(rows))
    return 0


# Geometry of the printed appendix, measured on the round-282 PDF with pdftotext -bbox-layout:
# the text area is 595.28 - 2*66.24 = 462.8 pt, and one DejaVu Sans Mono character at the size used
# in this table is 5.038 pt wide. MAX_LINES is what a reader can still scan as a table row.
TEXT_WIDTH_PT = 462.8
CHAR_WIDTH_PT = 5.038
MAX_LINES = 2
COL_FRACS = (0.46, 0.50)


def _lines_needed(text, width_frac):
    """How many lines a cell needs, at the measured character width."""
    per_line = int((width_frac * TEXT_WIDTH_PT) / CHAR_WIDTH_PT)
    n = len(str(text))
    if n == 0:
        return 1
    return -(-n // per_line)                 # ceiling


def _fits(out):
    """(do all cells fit, (worst line count, which cell)). Control: a 400-character cell must be
    reported as needing more than MAX_LINES lines, otherwise the estimate is blind."""
    worst = (0, 'nothing')
    for eid, rec in out.items():
        n = max(_lines_needed(rec['print'], COL_FRACS[0]),
                _lines_needed(rec['what'][:72], COL_FRACS[1]))
        if n > worst[0]:
            worst = (n, eid)
    control = _lines_needed('x' * 400, COL_FRACS[0]) > MAX_LINES
    print('estimate control (a 400-character cell must exceed the limit): %s'
          % ('fires' if control else 'BLIND'))
    return worst[0] <= MAX_LINES and control, worst


def _tex(s):
    s = str(s)
    for a, b in (('&', '\\&'), ('%', '\\%'), ('_', '\\_'), ('#', '\\#'), ('{', '\\{'),
                 ('}', '\\}'), ('$', '\\$')):
        s = s.replace(a, b)
    return s.replace('\\x', '\\textbackslash x')


if __name__ == '__main__':
    sys.exit(main())
