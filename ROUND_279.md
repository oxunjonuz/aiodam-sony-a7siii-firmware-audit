# ROUND 279 — MAC_FINGERPRINT.sh: the host-key fingerprint of the live camera

Date: 2026-10-04. Commissioned by: UC. Carried out by: Aiodam.

---

## 1. What was asked

A script `MAC_FINGERPRINT.sh` to run on the Mac: find the camera on the network, take the host-key
fingerprint from port 22, compare it with the key found in round 278 inside `BODYDATA.DAT`
(`SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI`), and give one of three answers:
MATCH / MISMATCH / UNREACHABLE. Read-only, no root, no authentication, and an honest record of
what was measured and what was not.

## 2. The answer already exists — and it came from the live device, twice

The owner measured the camera himself and sent the key bytes. I checked them **from this container,
over the network, against the same device**, without taking the story on trust:

| what | value | who measured |
|---|---|---|
| the camera's live key (blob, 104 B) | `AAAAE2Vj…qAjw=` | the owner, on the Mac |
| its sha256 | `d153b126a9fbe65cace0b7fdd6d4a566ef276b3596c43eab4d5737e63668f3b5` | Aiodam (container) |
| its fingerprint | `SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U` | Aiodam, independently: base64 -> blob -> `ssh-keygen -lf` |
| the key from the firmware | `SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI` | round 278 |
| the divergence | **64 of the 66 bytes of the point** | Aiodam |

**Conclusion: MISMATCH.** The key in the publicly distributed firmware file is not the live identity
of this camera. The script, run here against the camera (192.168.1.102), prints exactly that:

```
 VERDICT: MISMATCH
 reason : live host key is a different key
 route 1  blob base64 equal to the firmware key      : no
 route 2  SHA256 fingerprint equal (ssh-keygen -lf)  : no
 route 3  decoded blob sha256 equal                  : no
 reference fingerprint : SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U
      -> the live key is SAME as that reference
```

(The last line means: the live key is the same as the reference the owner took on 2026-10-04, and
different from the key inside the firmware.)

## 3. What was measured on the live camera (and what a single firmware file could not do)

This is the strongest part of the round: the camera spoke for itself.

| measurement | result | witness file |
|---|---|---|
| port 22 (sshd) | **open**, 22 probes out of 22 over 3 minutes | `out/live_probe_log.txt` |
| the key between sessions | **the same** in every probe | same file |
| banner | `SSH-2.0-OpenSSH_7.9` | `out/live_camera_ssh_keyscan.txt` |
| kex | `ecdh-sha2-nistp256` | same file |
| host key algorithm | `ecdsa-sha2-nistp256` | same file |
| cipher / MAC | `aes128-ctr` / `hmac-sha2-256` | same file |
| port 15740 (PTP/IP) | **closed** in this state | `out/round279_live_camera_report.txt` |

Those four algorithms are exactly the four set in the `sshd_config` inside the firmware
(`KexAlgorithms ecdh-sha2-nistp256`, `Ciphers aes128-ctr`, `MACs hmac-sha2-256`,
`HostKeyAlgorithms ecdsa-sha2-nistp256`). As a control: an ordinary Linux host on the same network
(.103) negotiates `mlkem768x25519-sha256` and `chacha20-poly1305` — so the set is not an artefact of
my client's preferences.

**Hence a conclusion stronger than the word "MISMATCH":** what runs on the camera is **that very
sshd from the firmware** (its config, its single algorithm set), and its host key is **its own**.
So the `create_host_key.sh` path really does execute on the device:
`/usr/bin/ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key`
(the text of the script lies in the image in full, and its comment is in Japanese: "if the command
is run directly from IM_System, the key file is not created without a passphrase, hence this
script").

## 4. What this does not mean — plainly

* It is **not** "the file contains a build key that nobody needs": the key in the file is private,
  it is extractable by everyone who downloaded firmware 5.01, and it remains the second known
  private key of this model, even if the camera does not use it.
* It is **not** an answer to "does every camera of this model have the same live key". One live key,
  taken twice, speaks only for this camera in this session.
* It is **not** a claim that the key changes on reboot. The key lives in `/tmp_network/ssh/`, that
  is, outside persistent storage — but that is an inference from the config, not a measurement. The
  measurement is one step away (§5).
* Port 15740 is closed, so "the camera was found" here rests on the algorithm set and on the match
  with the owner's key, not on the PTP/IP port.

## 5. The single next step, and it is yours

**Reboot the camera and run the script again.** Then:

* a different fingerprint -> the key is created afresh on every boot, and the copies in the firmware
  are templates that never were a pinned identity;
* the same fingerprint -> the key is created once per device and survives a reboot somewhere.

The script can already answer this question without comparing by eye: its report carries the line
`the live key is SAME/DIFFERENT as that reference`, against the key taken today.

## 6. What is delivered

`MAC_FINGERPRINT.sh` — one file, run as `./MAC_FINGERPRINT.sh`.

| mode | what it does |
|---|---|
| `./MAC_FINGERPRINT.sh` | finds the camera itself (ARP, gateway, a 192.168.122.1 hint, and if needed a /24 sweep on port 15740 only) |
| `--ip 192.168.1.102` | checks the given address |
| `--no-scan` | does not walk the local /24 |
| `--selftest` | without a camera and without a network: proves the instrument can go red (6/6) |
| `--mdns` | enables mDNS discovery; **off** by default, because that means UDP packets beyond the declared budget |

What it sends: a TCP connect to ports 22, 15740, 60152 on the addresses it found, and **one** SSH key
exchange. What it does not send: ICMP, UDP, any authentication, not a single byte into the camera.
`sudo` is not used at all — the ARP table is read without root.

The result is printed, written to `/tmp/aiodam_fingerprint.txt`, in an `AIODAM_JSON` line, and as a
copy next to the script (`FINGERPRINT_RESULT.txt`) so that I could read it back from the volume.

## 7. What this is checked by

`audit/round279_check.py` — **32 checks, 32 green, 2 controls red** (a control is a check that must
go red, otherwise it proves nothing):

* against a **real SSH server** (paramiko) holding the **real key from the firmware**: MATCH through
  a live key exchange, where the harness independently takes the key with its own `ssh-keyscan` and
  its own `ssh-keygen` — and the fingerprints agree;
* "the server saw no authentication attempt and no channel" — a read-only statement, not a promise;
* control: substituting the expected key flips the verdict; changing one letter of the blob cannot
  produce MATCH; diverging routes give not MATCH but `INCONCLUSIVE_CONTRADICTION`;
* control: a server with ordinary algorithms is **not** recognised as the firmware's sshd, while a
  "camera twin" server is;
* and four checks **against the live camera 192.168.1.102** (C22–C25): MISMATCH, the algorithm set
  from the firmware, the key identical to the one the owner took.

`--selftest`: **8/8, 0 skips** — but only after I installed a real `nc` (`netcat-openbsd`) in the
container. Before that it was 6/6 with one honest SKIP: the branch "open a test port and see it
open" had never executed, because there was no `nc` in the container. This matters beyond a tick:
`nc -z` is exactly the probing method the script will use on your Mac (`probe method chosen: nc -z`),
so the real path is now covered. A fragility was fixed in the same pass: on BSD/macOS `nc` listens
as `nc -l host port`, on GNU as `nc -l -p port`; the script tries both forms and, if neither works,
prints SKIP with a reason instead of a red line (red must mean a genuine breakage).

## 8. Errors of my instruments in this round (F156–F160, not one of them deleted)

* **F156 — the nastiest one.** Parsing the line `kex: host key algorithm: (no match)` took the last
  word of the first matching line, yielding `match)`. The check then declared "the algorithm set is
  different" about a server that had negotiated exactly the set from the firmware. Caught only
  because I ran the script against the live camera, not just against my model of a server.
* **F157 — an invisible byte.** Those same `ssh-keyscan -v` lines end with a carriage return, so
  `ecdh-sha2-nistp256\r` **prints** as `ecdh-sha2-nistp256` but **compares** as a different value.
  The same false "different set". Now every parsed value goes through `tr -d '\r'`, and `json_escape`
  strips control characters (otherwise the JSON line became invalid).
* **F158 — the instrument lost its own report.** The working directory vanished in the middle of a
  run: 3/40, 4/40, 10/60, 6/60 runs lost the report entirely or in part. A control convicted a
  suspect: with the `rm -rf` removed from the trap there were 0/60 losses, so my own cleaner was
  deleting it; the trap log shows a double entry into the EXIT trap with the same PID (the second
  time from a subshell in the polling loop). **The mechanism was not established** and is recorded as
  an open question. The consequence was fixed: the report no longer lives in that directory (it is
  written straight where it was promised), and the cleaner can only delete auxiliary files.
  After the fix: **0 losses in 80 runs**.
* **F159 — a "closed" port that was open.** At 17:23:01 a run saw port 22 closed; at 17:23:12 the
  same address accepted it, and then 15/15 probes were open. The probing function was checked
  separately (not to blame). This may be a refusal by the device (sshd coming up on demand) or a
  network accident; the exact cause is unknown. The consequence was fixed: a refusal is re-checked
  once after 2 s and the re-check is printed — so that a single refusal cannot become a false
  UNREACHABLE.
* **F160 — the same class as F158.** An asynchronous watchdog subshell (`sleep t; kill -9`) was the
  only place where the script spawned a background executor with an inherited trap. Removed:
  `timeout(1)` where available, otherwise a `kill -0` poll with no watchdog.

## 9. One question

Run the script before and after a reboot of the camera — or do you already look at the result as a
closed question, and the next step is a different one?
