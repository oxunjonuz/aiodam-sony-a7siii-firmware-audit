# Audit of a Sony firmware update file (ILCE-7SM3) — SONY_A7SIII_UPDATE

**Read:** `AUDIT_REPORT.md` — that is the report.
**Check:** `./env/venv/bin/python3 audit/checks.py` (15 checks + 3 controls)
and `./env/venv/bin/python3 audit/report_check.py` (checks the report's numbers, 2 + 3 controls).

Subject: `BODYDATA.DAT`, 743 818 632 bytes,
sha256 `dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb`.
No experiment changed the original (copies live in `/tmp`).

**Status of this file.** The three sections below were written at round 276. Later rounds
changed two of their statements, and both corrections are measured, not asserted:

* the body **has since been opened** with a public key (`key_cxd90057_k8`, PR #52): the stream
  is 740 912 128 B, sha256 `11880291…1e66`, and it contains the updater file system (squashfs,
  58 files), the firmware tar (159 members) and one unencrypted OpenSSH private key;
* the "2 906 112 unexplained bytes" **do not exist**: they are the 4-byte frame overhead of the
  726 385 blocks (4 × 726 385 = 2 905 540) plus the 572-byte 0xff padding of the last block.

`AUDIT_REPORT.md` §0 carries both corrections; `ROUND_277.md` … `ROUND_279.md` and the paper in
`publication/` carry the measurements.

## In short (as measured at round 276)

* The `.DAT` container is parsed to the byte and agrees with an **independent** public
  implementation (`fwtool.py`, by ma1co). The container's internal CRC32 matches → the file is intact.
* **The firmware header (the first 512 bytes of the body) is readable with a published key**
  (`key_aes`, ECB, one key across three camera generations): model `0x91030083`, version **5.01**,
  region 0, the file-system layout and the sizes.
* ECB leaks structure: in all 710 MiB of ciphertext there is exactly **one** run of identical
  blocks (26 blocks starting at the 96th), and it was predicted from the decrypted header
  **before** it was measured.
* Container integrity is **not** authentication: a modified file whose keyless CRC32 has been
  recomputed is **accepted** by the reference parser; the same file without the recomputation is
  rejected (control).
* The header's internal CRC32 is not keyed either: a synthetic header with an offset **beyond the
  end of the file** is accepted in silence (control: with a broken CRC it is rejected).
* The body (99.99993 % of the file) was **not opened** by any of the 6 published decrypters at that
  time; the entropy of every window ≥ 7.9995 bits/byte; the reference tool answers
  `No decrypter found`. That was "not opened", **not** "impossible".
* Unexplained: 2 906 112 bytes (2838 × 1024) between the end of the firmware and the tail.
* Tail of the body: 272 bytes = 16 bytes of IV in clear text + 256 bytes (the size of an RSA-2048
  signature; nothing can verify it — no Sony public key is available).

## What is not here, and why

Signature verification on the camera, the root of trust, anti-rollback, the robustness of the
camera's parser, interrupt and power-loss handling, debug interfaces — none of these can be
checked from a single file. The full list of 11 rows is §6 of the report. Closing them needs a
dump of the loader/parser or the camera itself in service mode.

## Contents

```
AUDIT_REPORT.md              the report (with a machine-readable EVIDENCE block for report_check)
TZ_SONY_ADUDIT.md            the terms of reference as commissioned (translated into English)
BODYDATA.DAT                 the subject (unchanged)
audit/checks.py              instrument: 15 checks + 3 controls -> evidence.json
audit/checks_out.txt         the instrument's full output
audit/evidence.json          every number of the report, machine-readable
audit/report_check.py        check: every number of the report against evidence.json
audit/report_check_out.txt   its output
audit/parser_bounds.py       bounds of the format (synthetic image)
audit/header_plain.txt       the decrypted header, 512 bytes, with the fields marked
audit/ecb2.py                search for runs of identical blocks without the key
audit/entropy_profile.py     entropy of the body, per 1 MiB
audit/solve_crc.py           inverting CRC32: what the header demands of 4 unknown bytes
audit/crypter_matrix.py      14 schemes for the second half-block: none of them matches
out_fwtool/                  what the reference tool wrote (the body was rejected)
tools/                       downloaded implementations of the format (fwtool.py, Sony-PMCA-RE)
downloads/                   their archives with sha256
env/venv/                    isolated environment (pycryptodome, pyyaml, numpy)
```
