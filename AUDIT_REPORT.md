# Security audit of a Sony firmware update file (ILCE-7SM3)
## BODYDATA.DAT — static analysis, isolated environment

**Subject:** `/work/SONY_A7SIII_UPDATE/BODYDATA.DAT`
**Size:** 743 818 632 bytes (709.4 MiB)
**SHA-256:** `dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb`
**Terms of reference:** `TZ_SONY_ADUDIT.md` (met in substance; the deviations from the letter of the terms are listed in §1.3)
**Date of the analysis:** 2026-10-04
**Where it lives:** `/work/SONY_A7SIII_UPDATE/` (working folder);
a copy for reading from the Mac — `/Volumes/Transcend234/SONY_A7SIII_AUDIT_276/`
(the report, the README, the instruments and their output; the copies were compared by sha256).
**Was the subject modified:** no. The original was not changed; every experiment ran on copies in `/tmp` and on synthetic images.

---

## §0 UPDATE (round 277): the body is opened; the "2 906 112 uncovered bytes" were an accounting error

Three corrections to the text below, all measured in round 277 (in full: `ROUND_277.md`):

1. **The body is opened.** The public key `key_cxd90057_k8` from the open PR `ma1co/fwtool.py#52`
   ("Support CXD90057", opened 2026-09-10, unmerged) decrypts the whole file:
   a stream of 740 912 128 B, sha256 `11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66`,
   and the reference `readFdat` passes. Round 276 said "six public decrypters" — there are seven; the
   seventh was absent from the master branch, so a search of the repository did not show it.
   The estimate "512 bytes out of 743 818 512 are publicly readable" (0.000069 %) is wrong: everything is readable.
2. **§F-07 does not exist.** 2 906 112 = 4 × 726 385 (the overhead of the 4-byte frames of the
   1024-byte blocks) + 572 (the 0xff padding of the last block). The offsets in the header are in
   stream coordinates, while the remainder was computed as the difference between the ciphertext
   length and the sum of the components. Measured: 726 385 frames, every checksum matches, the sizes
   are 1020 in all but the last (448), the "last" flag is on that one only, the padding is 572 × 0xff,
   the stream = 512 + 1 253 376 + 739 658 240, and the number of extra bytes is zero. The passages of
   §5/§6/§8 below that treat that difference as an uncovered area should be read with this correction.
3. **The model is confirmed by the file itself:** `ILCE-7SM3` occurs 61 times, including the string
   `ILCE-7SM3 v5.01` (α7S III, version 5.01). Inside the file there are also two 3072-bit public keys
   (`0800_appli/setting/public_key.pem`, `verify_key.pem`) and one 2048-bit key; **not one of them
   confirms the 256-byte tail** — the verification key stays outside the file. The internal integrity
   of the image is a CRC32 in `*.sum` (12 of 12 match, and they are forged without a key). The
   container CRC32 is unkeyed as well (C8).

---

## §0b UPDATE (round 278): the squashfs is unpacked; "three OPENSSH PRIVATE KEY blocks" is one key

Two corrections, both measured in round 278 (in full, with controls: `ROUND_278.md`,
`audit/round278_check.py` — 17/17 non-control green, 5/5 controls red):

1. **The squashfs is unpacked.** The statement "there is no `unsquashfs` in the container, that is the
   next cheap step" was wrong: the container has `7z`, and it reads SquashFS 4.0 (ZLIB). Extracted:
   **58 files, 3 151 747 B** (the image is 1 253 376 B, sha256 `62e86fad…`): 31 ELF (all AArch64) and
   21 scripts. `config/config.xml` is the map of the update pipeline, and its order is **check the
   CRC32 of the group → run the module**; no signature takes part in the pipeline. `common.src`
   contains `MODE_SERVICE=2`. In `loader_writer.sh` the loader md5 check is **commented out**, and in
   `nor_loader_writer.sh` `loader_nor.md5` is declared but never called.
2. **There is one private key in the file, not three.** In round 277 I counted literals: the whole
   stream has 10 of them (5 BEGIN + 5 END), of which 4 pairs are **string tables of binaries**
   (libcrypto/libssh2 in `/usr`, with the BEGIN and the END 40 bytes apart). The real block is one —
   587 628 092, the member `0700_part_image/dev/nflasha5` (/wbi): `ecdsa-sha2-nistp256`,
   `cipher=none`, `kdf=none`, comment `root@(none)`, fingerprint
   **`SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI`**. The key works: `d*G` matched the embedded
   point (my own arithmetic), and `ssh-keygen` and OpenSSL confirm it independently. It is the camera's
   **host key**: `sshd_config` names a single `HostKey /tmp_network/ssh/ssh_host_ecdsa_key` with
   `HostKeyAlgorithms ecdsa-sha2-nistp256`, and the recovered text of `/usr/bin/create_host_key.sh` —
   `ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key` — has the same
   parameters and the same path. It gives no entry: the same config says `PubkeyAuthentication no`,
   `PermitRootLogin no`, `PasswordAuthentication no`, `MaxSessions 0`, and only forwards to
   `localhost:15740`/`:60152` are allowed. One fact remains unestablished: whether the camera uses
   this very key (the script creates a key "if absent"); the decisive check is a fingerprint on the
   live camera.

---

## §0c UPDATE (round 279): the check on the live camera was made — the key from the file is NOT used

The unestablished fact from §0b is closed, and the answer is negative. Measured on 2026-10-04 on the
live device (`192.168.1.102`), independently by two machines (the owner's Mac and this container), in
full and with controls: `ROUND_279.md`, `audit/round279_check.py` — 32/32, 2 controls red.

1. **The camera presents its own key, not the key from the firmware.** The live host key:
   `SHA256:0VOxJqn75lys4Lf91tSlZu8nazWWxD6rTVc35jZo87U`
   (blob sha256 `d153b126a9fbe65cace0b7fdd6d4a566ef276b3596c43eab4d5737e63668f3b5`),
   the key from the file — `SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI`
   (blob sha256 `27c2fd6812c48a64dd0d6e66d6257bc14eb82cfd625a8dfe963f4c182c4d3832`).
   The divergence is 64 of the 66 bytes of the point, so this is a different key, not a typo.
2. **At the same time, the sshd running on the camera is the one whose config is in the firmware.**
   The live server negotiated exactly four isolations from `sshd_config`: kex `ecdh-sha2-nistp256`,
   host key `ecdsa-sha2-nistp256`, cipher `aes128-ctr`, MAC `hmac-sha2-256`; an ordinary host on the
   same network (.103) negotiates `mlkem768x25519-sha256` and `chacha20-poly1305`. So the
   `/usr/bin/create_host_key.sh` found in the image really does create a key on the device, and the
   private key from the public file is **not** the camera's live identity.
3. **What remains open:** whether the live key changes on reboot (it lives in `/tmp_network/ssh/`,
   that is, outside persistent storage — but that is an inference from the config, not a measurement)
   and whether every camera of the model has the same one. A single live key does not settle that.
   The instrument for the check is `MAC_FINGERPRINT.sh` (see §0d).

---

## §0d WHAT SITS NEXT TO IT: MAC_FINGERPRINT.sh

A script for the Mac that takes the host-key fingerprint of the live camera and compares it with the
key from the firmware: `MAC_FINGERPRINT.sh` (`./MAC_FINGERPRINT.sh`, `--ip 192.168.1.102`,
`--no-scan`, `--selftest`). It sends only TCP connects to ports 22/15740/60152 and one SSH key
exchange; it does not authenticate, writes nothing into the camera, does not use `sudo`, and puts its
result in `/tmp/aiodam_fingerprint.txt` and next to the script.

---

## §0e UPDATE (round 281): re-verification of every number in this report

The round-281 re-verification (`audit/verify_findings.py`, 47/47 green, 5/5 controls red) derived every
number of this report again from the raw bytes with its own code, and found four corrections to numbers
recorded earlier (F161–F163 and the FDAT body offset). They change numbers, not conclusions, and the
text below is left as it was written:

* the private-key block is **504 B**, not 501, and its base64 body is **435** characters, not 471 (471
  is the offset of the closing line — an offset that entered the reports as a length, F161);
* the `sshd_config` member starts at **740 733 952**, not 740 736 525 (F162);
* the file holds **8** `BEGIN PUBLIC KEY` literals (one with no body) and **6** distinct RSA moduli,
  not 4 and 5 (F163);
* the `FDAT` body starts at byte **108**, not 100 (100 is the length field).

---

## §1 Method and boundaries

### 1.1 What is here
One update file. No camera, no dump of its firmware, no parser, no service mode.

### 1.2 What follows from that, honestly
The terms of reference (§3–§5) require checking the **signature mechanism on the device**, the
**robustness of the parser** and the **update logic** (anti-rollback, interrupt handling). From a
single file these are **not checkable**: signature verification is done by code in the camera, and
error handling by its loader. Everything below marked **[MEASURED]** is a measurement on the file and
on published implementations of the format. Everything about the camera's behaviour is marked
**[DEVICE NOT TESTED]** or **[HYPOTHESIS]** and is never presented as a fact.

### 1.3 Deviations from the letter of the terms of reference (with the owner's permission: "the terms are not a law")
| Item of the terms | What was done instead |
|---|---|
| §4.1 "obtain the official file from the Sony website" | The file was supplied by the owner; verifying its provenance is **impossible** — see §6, the "authenticity" row |
| §4.1 `binwalk` | There is no `binwalk` in the container; its task (finding signatures) was solved by a direct signature probe with a frequency control (C10/C10b) |
| §4.4 "fuzzing in QEMU/Unicorn" | There is no image to emulate. Instead the **invariants of the format itself** were measured (§4, F-07) on the reference parser |
| §4.3 "where the root of trust lives" | There is no answer in the file. What **can** be a signature was established: 256 bytes in the tail (§3.4) |
| §5 "debug interfaces of a release firmware" | Requires a camera. **Not done** |

### 1.4 Instruments and their provenance
Everything was downloaded from public repositories and pinned by SHA-256:

| Source | What was taken | SHA-256 |
|---|---|---|
| `github.com/ma1co/fwtool.py` → `fwtool/sony/dat.py` | the container parse, CRC | `5f5c1324649ee6c1719b14d5fc3b829741daf904c5f79da2ddcab10ef17f8d8e` |
| same → `fwtool/sony/constants.py` | the **public keys** of the decrypters | `318ecfb52735696c0f824d41a9694ebc203ae4839b23f55bdc3d2a5eb38f1297` |
| same → `fwtool/sony/fdat.py` | the FDAT format, modes, decrypters | `9f22c7a66b0d33f3accba26b417446b974d1251234462f1ca5c13ea6ee5b9910` |
| same → `README.md` | which camera generations are covered | `5cb33cc0eb8c8191159c33555c6ecb6a02a712614430e9d092b991371466ef8d` |
| `github.com/ma1co/Sony-PMCA-RE` → `pmca/usb/sony.py` | Sony USB IDs (VID and updater mode) | `53ffb4d9d49cb5146623fda2b66ecb137681a6fc9ab0c98d23a51e75128af97e` |
| same → `README.md` | what is known about the signed generations | `779f36d8cf20c878ff8245d2d69fab1fcf0f77c2c5a58f00dddbb99c44379fa3` |
| `usb-ids.gowdy.us/usb.ids` | the USB identifier table | `f5a48b0cc8dae1607c2f0bae6b8dc13f2ecef69dbeaeaf34b4be8e280d34dba4` |

The reference tool `fwtool.py` was **run on the file itself** (not merely read):
`python3 fwtool.py unpack -f BODYDATA.DAT -o out_fwtool` → the container is accepted, the body is
rejected, `Exception: No decrypter found`. This is an independent implementation of the same format,
written by another person — that is, my container parse is checked by someone other than me.

---
## §2 What this file is

### 2.1 The container (parsed to the last byte)
```
offset 0        89 55 46 55 0d 0a 1a 0a          magic   \x89 "UFU" CRLF SUB LF
offset 8        <len=4>   "DATV"  payload: 01 00 00 00   (dataVersion 0x0100, isLens=0)
offset 20       <len=4>   "PROV"  payload: 01 00 00 00   (protocolVersion 0x0100)
offset 32       <len=60>  "UDID"  payload: count=7 + 7 descriptors of 8 bytes
offset 100      <len=743818512> "FDAT"   <- the firmware body
offset 743818620 <len=4>  "DEND"  payload: 1f af dc aa
```
The lengths are big-endian, and the length is always followed by a 4-byte tag. The parse agrees **to
the byte** with the independent implementation (checks C1 and C3).

### 2.2 Container integrity
`DEND.crc = 0x1fafdcaa` equals the `crc32` of the first 743 818 620 bytes of the file (**C2, computed
separately, matched**). This is not a signature — see F-04.

### 2.3 The device table (UDID)
| # | VID:PID | mode |
|---|---|---|
| 1 | `054c:0448` | 1 — normal |
| 2 | `054c:047d` | 1 — normal |
| 3 | `054c:0d15` | 1 — normal |
| 4 | `054c:0d16` | 1 — normal |
| 5 | `054c:0d19` | 1 — normal |
| 6 | `054c:0d1a` | 1 — normal |
| 7 | `054c:03e2` | **2 — updater** |

`0x054c` is Sony Corp. (the `usb.ids` table, **confirmed**). `0x03e2` is **confirmed as the PID of the
updater mode** by an independent project: `pmca/usb/sony.py` has
`SONY_ID_PRODUCT_UPDATER = [0x033a, 0x03e2]`.
I could not tie the six "ordinary" PIDs to model names: they are in neither `usb.ids`, `libmtp` nor
`libgphoto2` (checked). **This is an honest "I do not know", not a "there is nothing".**

---
## §3 The FDAT header is openly readable (with a public key)

### 3.1 How this was established
The first 512 bytes of the body were decrypted with the **published** key `key_aes`
(`E3B0C44298FC1C149AFBF4C8996FB924`; it lies in clear text in `fwtool/sony/constants.py`) in ECB
mode, in 16-byte blocks. The result is a coherent FDAT structure: the magic `UDTRFIRM`, format version
`0100`, mode `U`, flag `N`. A coincidence of that kind is excluded (check C4).

### 3.2 The firmware metadata this yields (**[MEASURED]**)
| Field | Value | How it was checked |
|---|---|---|
| model | `0x91030083` | the header's `model` field |
| version | **5.01** | `versionMajor=5`, `versionMinor=1` by fwtool's own rule (`'%x.%02x'`) |
| region | 0 | |
| file system (U) | offset 512, size **1 253 376** | |
| file system (P) | offset 512, size 0 | |
| firmware | offset **1 253 888**, size **739 658 240** | 512 + 1 253 376 = 1 253 888 — **matches exactly** |
| number of file systems | 2 | |
| header CRC | `0x9eb4163d` | see §3.3 |

The model name for the code `0x91030083` is not confirmed: it is not in fwtool's `devices.yml` (which
has `0x91030019` = ILCE-7C, `0x91030010` = 7RM4, `0x91030014` = 9M2). The form `0x91 03 00 xx` is the
CXD90045 generation, the Alpha family. **The candidate is the ILCE-7SM3, but that is a guess, not a
result.** — _Closed in §0: the file itself carries the string `ILCE-7SM3 v5.01` 61 times._

### 3.3 Three independent checks that the header was decrypted correctly
1. **The internal CRC32 matches.** The header stores the `crc32` of its bytes [12:512]. 496 of the
   500 bytes are known from the decryption; the mapping "last 4 bytes → CRC" is a bijection, so the CRC
   **determines them uniquely**. The required value is `00000000`, that is, the very zeros the structure
   predicts (28 FS slots, 2 occupied). (C6)
2. **The arithmetic of the offsets.** `fsOffset + fsSize == firmwareOffset` to the byte. (C5)
3. **A prediction made blind.** From the zero region of the header it follows that 26 sixteen-byte
   plaintext blocks coincide — so under ECB their ciphertext must coincide. Measured on the ciphertext
   **with no key at all**: in all 710 MiB there is exactly **one** run of identical blocks — 26 blocks,
   starting at block 6 (byte 96). Predicted: 26 blocks, 6..31. It matched exactly, including the
   absence of any other run. (C7)

### 3.4 The tail of the body (**[MEASURED]**)
The body length is 743 818 512 B = 1024 × 726 385 **+ 272**. The last 272 bytes are: 16 bytes of IV
(`89a85276c7208ea533a0e187fac4092c`, in clear text) + 256 bytes that **should** be an RSA-2048
signature (256 B is exactly the size of an RSA-2048 signature); checked: the tail after the IV holds
256 non-zero bytes. The geometry "the IV at offset −0x110" is **exactly what the published decrypter
`AesCbcCrypter` expects** for the CXD90045 generation (C14). The signature cannot be checked: I do not
have Sony's public key.

---
## §4 Findings

### F-01 — Format and container integrity: no violations **[INFO]**
The container is parsed to the byte, the parse is confirmed by an independent implementation, the CRC
matches, the field structure is consistent. That means: **the file is not damaged and was made to
Sony's specification**. There is no vulnerability here. No `CWE`.

### F-02 — The firmware header is encrypted with a shared public key in ECB mode **[MEASURED]**
`key_aes` is a constant in an open source and is **the same across three generations** (CXD4132,
CXD90014, CXD90045). Anyone who knows the format (it is public) can read the model, the version, the
region, the file-system layout and the sizes out of the file — and, more importantly, **can craft a
format-valid header** with any of those values.
`CWE-321` (use of a hard-coded key), `CWE-327`, `CWE-1188`.
CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` = **5.3** as metadata disclosure.
The real weight depends on **what the camera does with this header before verifying the signature** —
**[DEVICE NOT TESTED]**; if the decision to roll the version back is taken from the header, that is a
downgrade path and the score would be higher.

### F-03 — ECB mode leaks structure **[MEASURED, WITHOUT A KEY]**
That run of 26 identical blocks is visible in the ciphertext **without a key** — that is, the fact
"here stand 416 bytes of identical plaintext" is available to an observer. This is the textbook
property of ECB, and here it is measured on a real file rather than quoted.
`CWE-327`. CVSS 3.1: `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N` = **3.1**
(the leak itself is small, because this same region is readable with the key from F-02 anyway).

### F-04 — Container integrity is a CRC32, not an authentication code **[MEASURED, PROVEN]**
I changed one byte inside the body and recomputed `DEND.crc` **in a single pass with no key** — the
reference parser **accepted** the modified file. Control: the same file without the CRC recomputation
was **rejected** (`Wrong checksum`). CRC32 is linear: forgery costs one pass and needs no secret.
`CWE-345`, `CWE-353`.
CVSS 3.1: `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N` = **5.9**. A caveat: this scores the container as a
trust boundary; if nobody relies on the container CRC, the weight is lower.

### F-05 — The header's internal CRC32 is not keyed either **[MEASURED, PROVEN]**
The `crc32` over the 500 header bytes is not a MAC either. A synthetic header with a `firmwareOffset`
pointing **beyond the end of the file** (4 294 963 200) was **accepted** as soon as the CRC matched;
the read returned 0 bytes in silence. Control: with a broken CRC — rejected. Conclusion:
**the format has no invariant that offsets and sizes lie inside the image.**
`CWE-20` (missing input validation), `CWE-1284` (improper validation of a length/offset).
**[MEASURED ON THE REFERENCE IMPLEMENTATION; the camera's parser was not tested]**
CVSS 3.1 (conditional): `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H` = **7.4** — if the camera's parser is
built the same way. This is a hypothesis with a named way to test it, not a conclusion.

### F-06 — The body is not readable with any published decrypter **[MEASURED]**
All three publicly known AES decrypters were tried (`CXD4132` ECB, `CXD90014` double AES, `CXD90045`
ECB+CBC with the IV from the tail): **not one** yields a valid block (the block checksum does not
match — that is, what diverges is not even the cryptography but its control marker).
The entropy of all 710 windows of 1 MiB: min 7.999532, mean 7.999824, max 7.999871 bits/byte. Not one
plain-text signature of length ≥5 bytes. The reference tool answers `No decrypter found`.
**The right wording: the protection of the body has not been broken — which is not the same as
"unbreakable".** It is publicly known that the CXD90045 and CXD90057 generations use signed firmware
(the Sony-PMCA-RE README, §1.4). What we have not read, we cannot audit.

### F-07 — 2.9 MB in the body are not described by the header **[MEASURED, UNEXPLAINED]**
Between the end of the firmware (`1253888 + 739658240 = 740912128`) and the start of the tail
(743 818 240) there remain **2 906 112 bytes** = exactly 2838 × 1024. The header describes only two
file systems (the second one empty) and the firmware. What this is — a second component, an image
signature, or slack — is **not established**. This is the only place where the file's layout does not
agree with its own header, and I leave it open rather than invent an explanation.
_(Corrected in §0: these bytes are the frame overhead plus the last block's padding.)_

### F-08 — Anti-rollback is absent from the header as a structure **[MEASURED, LOGICALLY]**
The header has no version counter, no "minimum allowed version", no expiry: only `version`. So if
anti-rollback exists, it is **not here** — it is either in the signature (256 B in the tail, not
checkable without Sony's key) or in the camera's state.
`CWE-1284`/`CWE-1328` apply only once confirmed on the device.

---
## §5 Controls (without them every number above is worth nothing)

| # | Control | What it must show | Result |
|---|---|---|---|
| C6c | corrupting one bit in the known part of the header | the CRC-required bytes change (`f635cdf7`) | **went red** |
| C7c | predicting the run with a **wrong** key | the prediction does not match the measurement (there are no zero blocks) | **went red** |
| C8c | the same modified file without recomputing the CRC | the parser must reject it | **went red** |

The instrument's total: **15 non-control checks green, 3 controls red as they must be**
(`audit/checks.py`, the full output is `audit/checks_out.txt`).

Separately: in the first version of the CRC check on the modified file I got a **false "it is not
forgeable"** — I computed the CRC while the write had not yet been flushed to disk. This is recorded in
`audit/tamper_test.py` in a comment: the class of the error is "the instrument measures a state it is
itself changing".
And a second one, in the instrument that checks the report itself (`audit/report_check.py`): its first
version compared numbers with a **relative** precision of 1e-6, so it did not see
`739658240 → 739658241` — on a nine-digit number that is 1.3·10⁻⁹. A control went red precisely on that
and forced the comparison to be rewritten as "the precision printed in the text" (an integer exactly,
a fraction to the number of digits shown). Total: 2 checks green, 3 controls red,
`audit/report_check_out.txt`.

And a third one, in C10b itself: the first version computed the expected frequency as
"3 magics × N/2²⁴", whereas two of the three magics are four bytes long (expectation 0.17 over the
whole file, not 44), and the control was `/dev/urandom`, so the check was **flickering**: one run out of
three went red for a reason unrelated to the subject. Fixed: the length of each magic is accounted for
separately and the control comes from a **deterministic** stream (256 MiB of AES-CTR) — three runs in a
row green. This is the same class as F109/F114 in earlier work: an instrument that goes red by itself
devalues its own "green" too.

---
## §6 What I did NOT establish (plainly, without softening)

| # | Not measured | Why |
|---|---|---|
| 1 | Signature verification on the camera: what is signed, with what, and whether it is checked before use | a camera or a loader dump is needed; the file carries no open description of it |
| 2 | The root of trust (Boot ROM / a separate chip) | not contained in the file |
| 3 | Anti-rollback in practice | a camera is needed; the header has no structure for it (F-08) |
| 4 | Behaviour on an interrupted update / power loss | a camera is needed |
| 5 | The robustness of the camera's parser against garbage (overflows etc.) | no image to emulate; F-05 is a property of the format and of the **reference** implementation, not of the camera |
| 6 | What the 256-byte tail is (a signature or something else) | no public Sony key; the shape matches RSA-2048 (F-03, the tail) |
| 7 | What the 2 906 112 uncovered bytes are (F-07) | requires decrypting the body _(closed in §0 without any key)_ |
| 8 | What the model `0x91030083` is | no public code→model mapping |
| 9 | The debug interfaces of the release firmware | a device is required |
| 10 | The authenticity of the file (that Sony issued it) | the container carries no signature over the header; there is nothing to check it with (see F-02) |
| 11 | Key/IV reuse across different firmwares | one file; no comparison is possible |

---
## §7 Recommendations (per finding, not generic)

1. **F-02/F-03.** Remove the shared, hard-coded header key: one key for three camera generations means
   one publication (which has already happened) opens the headers of all of them. Instead of ECB, use
   an authenticated mode (AES-GCM/SIV) with a per-model key and with an integrity check that cannot be
   recomputed without the key.
2. **F-02 (logic).** The decision "install or not, roll back or not" must rest **only on signed data**.
   A header that anyone can read and craft will not do — either include it in full in the signed area
   or keep the version outside it.
3. **F-04/F-05.** CRC32 cannot be used as a trust boundary: it is linear and recomputed in a single
   pass. A MAC or a signature is needed; separately, **`offset`/`size` must be checked against the
   size of the image** and out-of-bounds values rejected (today the format does not require that —
   F-05).
4. **F-08.** Anti-rollback: a monotonic counter in a protected area of the camera (OTP/e-fuse) plus
   signature verification **before** any action on the image.
5. **F-07.** Close the question of the 2.9 MB: either they are part of the format contract, in which
   case they must be described and checked, or they are not needed.
   _(Closed in §0: they are the frame overhead plus the padding of the last block.)_
6. **Process.** Hand over to an audit not only the file but also a dump of the loader/parser: without it,
   §4.3–§4.5 of the terms of reference cannot be checked at all.

---
## §8 The answer to the terms of reference: "are there real paths to modify the firmware"

**From what was done — there is no proven path.** At the same time, the wording "the protection is
unbreakable" would be **wrong**: I did not break the body, I did not prove it strong.

What is proven: the container's and the internal integrity checks are not authentication (F-04, F-05);
the firmware header can be read and crafted by anyone (F-02); part of the metadata (model, 5.01,
`0x91030083`) is available without any camera key.
What is not proven: any path to **applying** a forged image on the camera. That runs into a signature
we did not check and into parser behaviour we have never seen.

Classification by access type: there is **no remote** vector in this file at all (it never goes
anywhere over a network). Everything here requires **local delivery of the file** into the camera
(USB/SD) and the user's participation — that is, physical access or social engineering on the camera
owner's side.
_(§0 adds: the body itself has since been opened with a public key, and the file system, the tar and one
private key have been extracted; the trust boundary still sits outside the file.)_

---
## §9 How to reproduce

```bash
# the environment (isolated, inside the project folder)
/work/SONY_A7SIII_UPDATE/env/venv/bin/python3 -c "import Crypto, yaml, numpy"   # pycryptodome, pyyaml, numpy

# everything essential in one command: 15 checks + 3 controls
cd /work/SONY_A7SIII_UPDATE && ./env/venv/bin/python3 audit/checks.py

# the report checking itself: 2 checks + 3 controls
cd /work/SONY_A7SIII_UPDATE && ./env/venv/bin/python3 audit/report_check.py

# the bounds of the format (a synthetic image, an offset beyond the end of the file)
./env/venv/bin/python3 audit/parser_bounds.py

# the independent tool (another implementation of the same format)
cd tools/fwtool.py-master && /work/SONY_A7SIII_UPDATE/env/venv/bin/python3 fwtool.py unpack \
    -f /work/SONY_A7SIII_UPDATE/BODYDATA.DAT -o /work/SONY_A7SIII_UPDATE/out_fwtool
```
Artifacts: `audit/checks.py` (the instrument), `audit/checks_out.txt` (its full output),
`audit/evidence.json` (every number, machine-readable), `audit/report_check.py` +
`audit/report_check_out.txt` (the report checking itself), `audit/parser_bounds.py`,
`audit/tamper_test.py`, `audit/ecb2.py` (finding runs without a key), `audit/entropy_profile.py`,
`audit/solve_crc.py`, `audit/header_plain.txt` (the decrypted header, 512 bytes), `out_fwtool/` (what
the reference tool wrote), `downloads/*.tar.gz` (the pinned sources).

<!-- EVIDENCE
file.size_bytes = 743818632
file.sha256 = dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb
container.dend_crc_stored = 0x1fafdcaa
container.fdat_payload_length = 743818512
fdat_header.model = 0x91030083
fdat_header.version = 5.01
fdat_header.firmware_offset = 1253888
fdat_header.firmware_size = 739658240
fdat_header.fs_user.size = 1253376
fdat_header.trailing_unaccounted_bytes = 2906112
fdat_header.cipher_len = 743818240
solved_plaintext_508_512 = 00000000
repeat_run_predicted_count = 26
repeat_run_measured.count = 26
repeat_run_measured.repeating_groups_in_file = 1
entropy_body_1mib.min = 7.999532
entropy_body_1mib.windows = 710
readable_with_public_key_bytes = 512
readable_with_public_key_percent = 6.9e-05
tail.flen_mod_1024 = 272
tail.footer_bytes = 272
-->
