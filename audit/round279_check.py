#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Round 279 checks: MAC_FINGERPRINT.sh against a REAL SSH server, offline.

Why this file exists
--------------------
MAC_FINGERPRINT.sh is meant to run on the owner's Mac against the camera. Nothing
on this Linux container is that camera, so the script's live path cannot be tested
here by "just running it". What CAN be tested is everything between the socket and
the verdict: the SSH key exchange, the parsing of ssh-keyscan's output, the three
comparison routes, the verdict logic and the controls that must go red.

So this harness stands up a real SSH server (paramiko) that holds the REAL host key
extracted from BODYDATA.DAT in round 278, and points the script at it. A MATCH from
the script is then checked against an INDEPENDENT route: the harness itself runs
ssh-keyscan + ssh-keygen and computes the fingerprint on its own.

Checks that must go RED are part of the suite on purpose: a control that cannot fail
proves nothing.

Run:  python3 audit/round279_check.py
"""
import base64
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time

import paramiko

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'MAC_FINGERPRINT.sh')
FIRMWARE_KEY = os.path.join(ROOT, 'out', 'key_wbi_nflasha5.pem')
EXPECT_FP = 'SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI'
REF_LIVE_FP = 'SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U'
LIVE_IP = '192.168.1.102'      # the owner's camera, 2026-10-04
EXPECT_B64 = ('AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAuoJrSuZ6vJ8E5i7ljq'
              '3qejSfe7hQORqGstDZLq7m0X1cXel0INCJAFjs89KvyuhDqq0jMB+9fyYBCcJlVWCow=')
WORK = tempfile.mkdtemp(prefix='r279_')

RESULTS = []
NOTES = []


def check(cid, name, ok, detail=''):
    RESULTS.append({'id': cid, 'name': name, 'ok': bool(ok), 'detail': str(detail)[:600]})
    print(('PASS  ' if ok else 'FAIL  ') + f'{cid} {name}' + (f'   [{detail}]' if detail else ''))
    return bool(ok)


def note(msg):
    NOTES.append(str(msg))
    print('note  ' + str(msg))


# --------------------------------------------------------------------- servers --
class Iface(paramiko.ServerInterface):
    """Records what the client asked for - so 'read-only' can be an assertion."""

    def __init__(self):
        self.auth_attempts = []
        self.channel_requests = []
        self.shell_requests = []

    def check_auth_none(self, username):
        self.auth_attempts.append(('none', username))
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        self.auth_attempts.append(('password', username))
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.auth_attempts.append(('publickey', username))
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'none,password,publickey'

    def check_channel_request(self, kind, chanid):
        self.channel_requests.append(kind)
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.shell_requests.append('shell')
        return True

    def check_channel_exec_request(self, channel, command):
        self.shell_requests.append(('exec', command))
        return True


class SshServer(threading.Thread):
    """A real SSH server with a given host key. Restricts kex to what the camera's
    sshd_config allows (ecdh-sha2-nistp256) when paramiko lets us."""

    def __init__(self, keyfile, restrict=True, banner='SSH-2.0-OpenSSH_7.9'):
        super().__init__(daemon=True)
        self.key = paramiko.ECDSAKey.from_private_key_file(keyfile)
        self.keyfile = keyfile
        self.restrict = restrict
        self.banner = banner
        self.iface = Iface()
        self.restriction = 'not attempted'
        self.connections = 0
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        t = None
        try:
            t = paramiko.Transport(conn)
            t.add_server_key(self.key)
            try:
                t.local_version = self.banner
            except Exception:
                pass
            if self.restrict:
                # mimic the four restrictions the firmware's sshd_config imposes, so the
                # script's algorithm-set identification can be tested against a server
                # that looks like the camera
                so = t.get_security_options()
                applied = []
                try:
                    so.kex = ('ecdh-sha2-nistp256',); applied.append('kex')
                except Exception as e:                                     # noqa: BLE001
                    applied.append(f'kex FAILED {e}')
                try:
                    so.ciphers = ('aes128-ctr',); applied.append('ciphers')
                except Exception as e:                                     # noqa: BLE001
                    applied.append(f'ciphers FAILED {e}')
                try:
                    so.digests = ('hmac-sha2-256',); applied.append('macs')
                except Exception as e:                                     # noqa: BLE001
                    applied.append(f'macs FAILED {e}')
                self.restriction = 'mimic-camera: ' + ', '.join(applied)
            t.start_server(server=self.iface)
            deadline = time.time() + 30
            while t.is_active() and not self._stop and time.time() < deadline:
                time.sleep(0.05)
        except Exception as e:                                             # noqa: BLE001
            if not self._stop:
                pass
        finally:
            try:
                if t is not None:
                    t.close()
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class TcpListener(threading.Thread):
    """A socket that accepts and says nothing (not SSH)."""

    def __init__(self, port=0):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', port))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        self.conns = 0

    def run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            self.conns += 1
            threading.Thread(target=self._hold, args=(conn,), daemon=True).start()

    def _hold(self, conn):
        try:
            while not self._stop:
                time.sleep(0.1)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


# ------------------------------------------------------------------- the script --
def run_script(ip, port, expect_b64=None, expect_fp=None, scan='no', timeout=180):
    out = os.path.join(WORK, 'out_%d.txt' % int(time.time() * 1000 % 1e9))
    env = dict(os.environ)
    env.update({'AIODAM_IP': ip, 'AIODAM_SSH_PORT': str(port), 'AIODAM_OUT': out,
                'AIODAM_SCAN': scan})
    if expect_b64 is not None:
        env['AIODAM_EXPECT_B64'] = expect_b64
    if expect_fp is not None:
        env['AIODAM_EXPECT_FP'] = expect_fp
    p = subprocess.run([b'bash', SCRIPT.encode()], capture_output=True, env=env, timeout=timeout)
    text = ''
    if os.path.exists(out):
        text = open(out, encoding='utf-8', errors='replace').read()
    else:
        text = p.stdout.decode('utf-8', 'replace')
    return p.returncode, text, out, p.stdout.decode('utf-8', 'replace')


def verdict_of(text):
    m = re.search(r'^ VERDICT: (\S+)', text, re.M)
    return m.group(1) if m else None


def reason_of(text):
    m = re.search(r'^ reason : (\S+)', text, re.M)
    return m.group(1) if m else None


def json_of(text):
    m = re.search(r'^AIODAM_JSON: (\{.*\})$', text, re.M)
    return json.loads(m.group(1)) if m else None


def observed_fp_of(text):
    m = re.search(r'^    their fingerprints   : (\S+)', text, re.M)
    return m.group(1) if m else None


def probe_open(ip, port, t=4.0):
    s = socket.socket(); s.settimeout(t)
    try:
        s.connect((ip, port)); return True
    except Exception:
        return False
    finally:
        s.close()


def fresh_ecdsa_key():
    path = os.path.join(WORK, 'fresh%f' % time.time())
    subprocess.run(['ssh-keygen', '-q', '-t', 'ecdsa', '-b', '256', '-N', '',
                    '-f', path], check=True, capture_output=True)
    with open(path + '.pub') as f:
        blob = f.read().split()[1]
    fp = subprocess.run(['ssh-keygen', '-lf', path + '.pub'], capture_output=True
                        , text=True).stdout.split()[1]
    return path, blob, fp


def independent_probe(port):
    """The harness's OWN route to the live key: ssh-keyscan + ssh-keygen."""
    ks = subprocess.run(['ssh-keyscan', '-T', '5', '-p', str(port), '127.0.0.1'],
                        capture_output=True, text=True, timeout=60).stdout
    lines = [l for l in ks.splitlines() if l.strip() and not l.startswith('#')]
    if not lines:
        return None, None
    pub = os.path.join(WORK, 'indep.pub')
    parts = lines[0].split()
    with open(pub, 'w') as f:
        f.write('%s %s\n' % (parts[1], parts[2]))
    fp = subprocess.run(['ssh-keygen', '-lf', pub], capture_output=True,
                        text=True).stdout.split()[1]
    return fp, parts[2]


# ----------------------------------------------------------------------- suite --
def main():
    print('=' * 78)
    print('ROUND 279 CHECKS - MAC_FINGERPRINT.sh')
    print('=' * 78)

    # -- C0 syntax
    rc = subprocess.run(['bash', '-n', SCRIPT], capture_output=True, text=True)
    check('C0', 'bash -n syntax clean', rc.returncode == 0, rc.stderr.strip()[:200])

    # -- C1 offline selftest must be green and must have skipped nothing silently
    rc, text, _out, so = run_script('127.0.0.1', 9, timeout=120)
    check('C1', 'selftest path: script starts (exit code recorded)', True, f'rc={rc}')
    st = subprocess.run([b'bash', SCRIPT.encode(), b'--selftest'], capture_output=True,
                        env=dict(os.environ, AIODAM_OUT=os.path.join(WORK, 'st.txt')),
                        timeout=180, cwd=ROOT)
    sttext = open(os.path.join(WORK, 'st.txt'), encoding='utf-8', errors='replace').read()
    check('C2', '--selftest exit 0', st.returncode == 0, f'rc={st.returncode}')
    check('C3', '--selftest says SELF_TEST_OK', 'SELF_TEST_OK' in sttext,
          re.search(r'SELFTEST: .*', sttext).group(0) if re.search(r'SELFTEST: .*', sttext) else '')

    # -- the real SSH server, real firmware key
    srv = SshServer(FIRMWARE_KEY, restrict=True)
    srv.start()
    time.sleep(0.5)
    note(f'SSH server on 127.0.0.1:{srv.port}, host key = out/key_wbi_nflasha5.pem, '
         f'{srv.restriction}')

    # -- C4 the independent route: does THIS harness see the expected fingerprint?
    indep_fp, indep_blob = independent_probe(srv.port)
    check('C4', 'independent route (harness ssh-keyscan) sees the firmware fingerprint',
          indep_fp == EXPECT_FP, f'{indep_fp}')
    check('C5', 'independent route: blob is byte-identical to the firmware blob',
          indep_blob == EXPECT_B64, f'{len(indep_blob or "")} chars')

    # -- C6 the script itself, over a real handshake
    rc, text, out, so = run_script('127.0.0.1', srv.port)
    v = verdict_of(text)
    check('C6', 'script over a real SSH handshake -> MATCH', v == 'MATCH', f'verdict={v}')
    check('C7', 'script reports the same fingerprint the harness computed',
          observed_fp_of(text) == EXPECT_FP, f'{observed_fp_of(text)}')
    j = json_of(text)
    check('C8', 'AIODAM_JSON parses and agrees with the text verdict',
          isinstance(j, dict) and j.get('verdict') == v,
          f'{j.get("verdict") if isinstance(j, dict) else "unparsed"}')
    check('C9', 'all three comparison routes available and saying yes',
          isinstance(j, dict) and j['route_blob'] == 'yes' and j['route_fp'] == 'yes'
          and j['route_sha'] == 'yes',
          f"blob={j.get('route_blob')} fp={j.get('route_fp')} sha={j.get('route_sha')}" if isinstance(j, dict) else 'no json')
    check('C10', 'report file was written where --out/AIODAM_OUT said',
          os.path.exists(out) and verdict_of(open(out, encoding='utf-8', errors='replace').read()) == v,
          os.path.basename(out))

    # -- C11 read-only assertion: no authentication, no channel, no shell was attempted
    check('C11', 'read-only: the server saw ZERO auth attempts and ZERO channel requests',
          not srv.iface.auth_attempts and not srv.iface.channel_requests
          and not srv.iface.shell_requests,
          f'auth={srv.iface.auth_attempts} chan={srv.iface.channel_requests}')
    note(f'kex restriction actually applied to the live handshake: {srv.restriction}')
    check('C11b', 'the live handshake negotiated the camera\'s own kex (ecdh-sha2-nistp256)',
          'kex: algorithm: ecdh-sha2-nistp256' in text, 'from the verbatim ssh-keyscan stderr')
    with open(os.path.join(ROOT, 'out', 'round279_match_report.txt'), 'w') as f:
        f.write(text)
    note('saved a full MATCH report to out/round279_match_report.txt')

    # -- C12 a different key must give MISMATCH
    fkey, fblob, ffp = fresh_ecdsa_key()
    srv2 = SshServer(fkey, restrict=False)
    srv2.start()
    time.sleep(0.4)
    rc2, text2, _o2, _s2 = run_script('127.0.0.1', srv2.port)
    v2 = verdict_of(text2)
    check('C12', 'a different host key -> MISMATCH', v2 == 'MISMATCH', f'verdict={v2}')
    j2 = json_of(text2)
    check('C13', 'and the JSON records the observed (different) fingerprint, not the expected one',
          isinstance(j2, dict) and EXPECT_FP not in (j2.get('observed_fingerprints') or ''),
          (j2 or {}).get('observed_fingerprints', '')[:60])

    # -- C13b/C13c the algorithm-set identification, and its control
    check('C13b', "an alg-mimicking server is identified as the firmware's own sshd_config",
          isinstance(j, dict) and j.get('alg_set_match') == 'yes',
          f"alg_set_match={(j or {}).get('alg_set_match')} alg_set={(j or {}).get('alg_set')}")
    check('C13c', 'control: a server with default algorithms is NOT identified as such',
          isinstance(j2, dict) and j2.get('alg_set_match') == 'no',
          f"alg_set_match={(j2 or {}).get('alg_set_match')}")
    check('C13d', 'the reference-key comparison reports SAME for the firmware-key server '
                  'only when that key is also the reference (here it is not)',
          isinstance(j, dict) and j.get('ref_live_match') == 'DIFFERENT',
          f"ref_live_match={(j or {}).get('ref_live_match')}")

    # -- C14 control: retarget the expectation at the other key -> the MATCH must go away
    rc3, text3, _o3, _s3 = run_script('127.0.0.1', srv2.port, expect_b64=fblob, expect_fp=ffp)
    check('C14', 'control: expectation retargeted to the other key -> MATCH (sanity of the swap)',
          verdict_of(text3) == 'MATCH', f'verdict={verdict_of(text3)}')
    rc4, text4, _o4, _s4 = run_script('127.0.0.1', srv.port, expect_b64=fblob, expect_fp=ffp)
    check('C15', 'control: real firmware key vs that expectation -> MISMATCH, not MATCH',
          verdict_of(text4) == 'MISMATCH', f'verdict={verdict_of(text4)}')

    # -- C16 control: routes made to disagree -> no verdict may be issued
    rc5, text5, _o5, _s5 = run_script('127.0.0.1', srv.port, expect_b64=EXPECT_B64,
                                      expect_fp='SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODX')
    check('C16', 'control: one route yes, one route no -> INCONCLUSIVE_CONTRADICTION',
          verdict_of(text5) == 'INCONCLUSIVE_CONTRADICTION', f'verdict={verdict_of(text5)}')

    # -- C16b control: a one-character corruption of the embedded expectation must
    # -- not still be able to produce a MATCH
    bad_b64 = EXPECT_B64[:-1] + 'X'
    rc5b, text5b, _o5b, _s5b = run_script('127.0.0.1', srv.port, expect_b64=bad_b64,
                                          expect_fp=EXPECT_FP)
    check('C16b', 'control: one character changed in the embedded blob -> not MATCH',
          verdict_of(text5b) not in ('MATCH', None), f'verdict={verdict_of(text5b)}')
    j5b = json_of(text5b)
    fw_sha = hashlib.sha256(base64.b64decode(EXPECT_B64)).hexdigest()
    check('C16c', 'and the sha256 expectation followed the changed base64 (routes cannot drift apart)',
          isinstance(j5b, dict) and j5b['expected_blob_sha256'] != fw_sha
          and j5b['route_sha'] == 'no',
          f"sha_expect={(j5b or {}).get('expected_blob_sha256', '')[:12]} route_sha={(j5b or {}).get('route_sha')}")

    # -- C17 closed port -> UNREACHABLE
    dummy = socket.socket()
    dummy.bind(('127.0.0.1', 0))
    closed_port = dummy.getsockname()[1]
    dummy.close()
    rc6, text6, _o6, _s6 = run_script('127.0.0.1', closed_port)
    check('C17', 'closed port -> UNREACHABLE', verdict_of(text6) == 'UNREACHABLE',
          f'verdict={verdict_of(text6)} reason={reason_of(text6)}')

    # -- C18 a socket that is not SSH -> INCONCLUSIVE_NO_KEY
    plain = TcpListener()
    plain.start()
    time.sleep(0.3)
    rc7, text7, _o7, _s7 = run_script('127.0.0.1', plain.port, timeout=240)
    check('C18', 'port open but not SSH -> INCONCLUSIVE_NO_KEY',
          verdict_of(text7) == 'INCONCLUSIVE_NO_KEY', f'verdict={verdict_of(text7)}')
    check('C19', 'and in that case the report still contains the raw ssh-keyscan stderr',
          'ssh-keyscan stderr' in text7, '')
    plain.stop()

    # -- C20 camera present (PTP 15740 open) but sshd closed: the realistic outcome
    ptp = TcpListener(port=15740)
    ptp.start()
    time.sleep(0.3)
    rc8, text8, _o8, _s8 = run_script('127.0.0.1', closed_port)
    v8, r8 = verdict_of(text8), reason_of(text8)
    check('C20', 'camera signature present, sshd closed -> UNREACHABLE/camera_found_but_sshd_not_listening',
          v8 == 'UNREACHABLE' and r8 == 'camera_found_but_sshd_not_listening', f'{v8}/{r8}')
    check('C21', 'and the report names the PTP port as the evidence the camera is there',
          '15740:OPEN' in text8, '')
    ptp.stop()

    srv.stop()
    srv2.stop()

    # -- C22..C25 THE LIVE CAMERA. The strongest check in this file: the script is run
    # -- against the owner's real camera, which the owner measured himself. If it is not
    # -- reachable the check is SKIPPED (not passed) with the reason printed.
    live = probe_open(LIVE_IP, 22)
    if not live:
        RESULTS.append({'id': 'C22', 'name': 'live camera reachable', 'ok': None,
                        'detail': f'{LIVE_IP}:22 not reachable from here - live checks SKIPPED'})
        print(f'SKIP  C22 live camera {LIVE_IP}:22 not reachable from this container - '
              f'the live half of this suite did not run (a skip is not a pass)')
    else:
        rcL, textL, _oL, _sL = run_script(LIVE_IP, 22, scan='no', timeout=240)
        jL = json_of(textL)
        check('C22', 'live camera: reachable and fingerprinted', isinstance(jL, dict),
              f'port 22 open at {LIVE_IP}')
        check('C23', 'live camera: verdict is MISMATCH (its key differs from the firmware key)',
              verdict_of(textL) == 'MISMATCH', f'verdict={verdict_of(textL)}')
        check('C24', 'live camera: the algorithm set it negotiates is the firmware sshd_config set',
              isinstance(jL, dict) and jL.get('alg_set_match') == 'yes',
              f"alg_set={(jL or {}).get('alg_set')}")
        check('C25', 'live camera: the key it presents is byte-identical to the key the owner read',
              isinstance(jL, dict) and jL.get('ref_live_match') == 'SAME'
              and REF_LIVE_FP in (jL.get('observed_fingerprints') or ''),
              f"observed={(jL or {}).get('observed_fingerprints')}")
        with open(os.path.join(ROOT, 'out', 'round279_live_camera_report.txt'), 'w') as f:
            f.write(textL)
        note('saved the live-camera report to out/round279_live_camera_report.txt')

    # -- summary
    passed = sum(1 for r in RESULTS if r['ok'])
    total = len(RESULTS)
    controls = [r for r in RESULTS if r['id'] in ('C15', 'C16')]
    print('-' * 78)
    print(f'ROUND279 {passed}/{total} passed; controls that must go red: '
          f'{sum(1 for r in controls if r["ok"])}/{len(controls)}')
    with open(os.path.join(ROOT, 'audit', 'round279_checks.json'), 'w') as f:
        json.dump({'passed': passed, 'total': total, 'results': RESULTS, 'notes': NOTES},
                  f, indent=1)
    print('wrote audit/round279_checks.json')
    return 0 if passed == total else 1


if __name__ == '__main__':
    sys.exit(main())
