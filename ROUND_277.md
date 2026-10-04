# ROUND 277 — F-07, the signature, the model name

_Every number below was obtained from the file `BODYDATA.DAT` itself (sha256 `dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb`, 743 818 632 B)
in this round. No experiment changed the original. The summary reproduces with one command_

```
cd /work/SONY_A7SIII_UPDATE && ./env/venv/bin/python3 audit/round277_check.py
# 13 non-control green out of 13, 5 controls red out of 5
```

_Corrections added later and kept visible rather than edited into the text: the squashfs was
unpacked in round 278 (§9.3 below was wrong about that); the file holds **6** distinct RSA moduli
and 8 `BEGIN PUBLIC KEY` literals, not 5 and 4 (F163); the `FDAT` body starts at byte **108**,
not 100 (the length field is at 100)._

## 1. The main point: the body is no longer closed

The owner's three points turned out to be achievable only together, because one key settles all of
them. The key was found in an **open, unmerged** PR `ma1co/fwtool.py#52` "Support CXD90057" (by
DavidBuchanan314, opened 2026-09-10, 12 comments, status open; issue #45 carries the same
"No decrypter found" for the A7RM5). It contains two 32-byte keys, and
**`key_cxd90057_k8` decrypts our file completely**:

| route | result |
|---|---|
| `AesCbcCrypter(key_aes, key_cxd90057_k8)` | decrypter `CXD90057_k8`, stream **740 912 128 B**, sha256 `11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66` |
| the reference `readFdat` on the unpacked file | **ok**: model `0x91030083`, version `5.01`, fs 1 253 376, fw 739 658 240 |
| `key_cxd90057_k0`, `key_cxd90045`, `key_cxd90014`, `key_cxd4132` | `BlockCryptException` (they do not fit) |

Independent check: unpacking with **my** block-wise code and unpacking with the **fwtool library**
give files of the same length and the same sha256 (compared byte for byte, see
`audit/verify_stream.json`, `identical: true`). Control: corrupting one byte of ciphertext is rejected
by both implementations.

Why round 276 believed the body was closed: I searched the **master** branch of fwtool (the key is not
there — the PR is unmerged) and master's `constants.py`. The key lives in the PR and in the fork. An
error of search, not of measurement; corrected.

## 2. F-07 closed: the "2 906 112 unexplained bytes" were an error of coordinate accounting, and that is measured

Measurements on the unpacked stream (`audit/stream_analysis.json`, `audit/round277_checks.json`):

| quantity | value |
|---|---|
| ciphertext blocks (1024 B each) | **726 385** (= 743 818 240 / 1024) |
| frames with a correct 16-bit sum | **726 385 out of 726 385** (0 bad) |
| payload size of a frame | 1020 B in all but the last block |
| the last block | payload **448 B**, the "last" flag set on it **only** |
| padding of the last block | **572 B, all 0xff** |
| frame overhead | 4 × 726 385 = **2 905 540 B** |
| 2 905 540 + 572 | **= 2 906 112 B** — exactly the number my previous report called an "uncovered remainder" |
| the stream | 512 + 1 253 376 + 739 658 240 = **740 912 128 B**, nothing beyond the declared components (`unaccounted = 0`) |

The mechanics of the error: `firmwareOffset/firmwareSize` are written in **stream** coordinates
(after the 4-byte frames are stripped), while I computed the "remainder" as the difference between the
**ciphertext** length and the sum of the components. That difference is exactly 4 bytes per block plus
the padding of the last block. Confirmed by three independent signs, all from this round:

1. `UDTRFIRM` sits at offset **4** in the ciphertext, not 0: the first 4 bytes `c4 a9 fc 03` read as a
   frame `checksum=0xa9c4`, `size|flag=0x03fc` (size 1020 = maximum, flag "not last").
2. The header crc32 matches over the area **[12:512)** (= the `FdatHeader` structure from fwtool,
   512 B), and it ends exactly where the file system is declared to start (512). In ciphertext
   coordinates the header would end at 516 — that is, it would overlap the file system.
3. Direct measurement after opening: 726 385 frames, 1020 B of payload in all but the last, and 572 ×
   0xff of padding. That is not a deduction but fields read out of the file.

**Item 4 of the terms of reference (divisibility and "meaningful sizes").** 2 906 112 = 2838 KiB =
2¹¹ · 3 · 11 · 43. The divisors that are multiples of 1024: 2838, 1419, 946, 473 KiB. The set of
"meaningful" sizes is empty here: it is not a power of two, not a multiple of 4096 (remainder 2048),
not a multiple of 128 KiB (remainder 22528), and it matches neither the size of the file system
(1 253 376) nor the 256-byte tail. The only decomposition that fits exactly is the arithmetic of the
frames: **4 × 726 385 + 572**. The second FS (slot `P`) is described in the header as `(512, 0)` —
size 0, with no data behind it.

## 3. The model name: the file names itself

- `ILCE-7SM3` occurs in the firmware image **61 times**: 13 times inside the image of partition
  `/dev/nflasha5` (WBI), and twice in each of the 24 regional files
  `0110_backup/SYSIPSX-DSLR/OT*/CX|CH8500x_*.bin`.
- Inside there is a ready model+version pair: the string **`ILCE-7SM3 v5.01`** (with the neighbouring
  fields `5.01` + `ILCE-7SM3`).
- Other model names in the file: only `ILCE-9` — **twice**, in a table next to `ILCE-7SM3` (to be
  treated as a caveat: the file could in principle belong to it too, but 61 against 2 and the
  placement inside the regional OT files point to the α7S III).
- The header: model `0x91030083`, version `5.01`, region 0.
- The public tables do **not** contain our code: master `devices.yml` (downloaded in this round,
  containing `ILCE-7C 0x91030019`, `ILCE-7RM4 0x91030010`, `ILCE-9M2 0x91030014`) and the diff of
  PR #52 (`ILCE-7M4 → CXD90057, 0x01030081`) — that is, our device is a **different** CXD90057 device
  from the a7 IV, and it is absent from the public lists.
- Consequence: `0x91030083` = `ILCE-7SM3` (α7S III) — **by the file's own internal evidence**, not by
  a public table. The recommendation in PR #52 ("round up the rest of the CXD90057 devices") is closed
  by this file: the table wants the row `ILCE-7SM3: arch CXD90057, model 0x91030083`.

## 4. The RSA-2048 signature (item 2 of the terms of reference): what was found and what was checked

Inside the file there are **three** public RSA keys (all in the firmware image tar):

| where | type | bits | e |
|---|---|---|---|
| `0800_appli/setting/public_key.pem` | SubjectPublicKeyInfo | 3072 | 65537 |
| `0800_appli/setting/verify_key.pem` | SubjectPublicKeyInfo | 3072 | 65537 |
| offset 429 029 376 in the stream | SubjectPublicKeyInfo | **2048** | 65537 |

Checking the tail (256 B after the 16-byte IV, outside the encrypted area):

1. **Structural test** (it needs no message): for a PKCS#1 v1.5 signature, raising the tail to the
   power `e` modulo `n` must yield `00 01 FF..FF 00 || DigestInfo`.
   - the 2048-bit key **from the file itself**: no structure (`m[:2] = 49 7f`), no PSS either.
   - the published 2048-bit Sony-PMCA-RE modulus (`lib/…librsaforinstaller.so`): no (`51 bb`).
   - the two 3072-bit keys in the file physically cannot sign 256 bytes (3072 bits = 384 B).
2. **Direct signature verification**: 2 keys × 10 candidate messages (the whole stream, the stream
   without its 512-byte header, the FS image, the firmware tar, the headers, the ciphertext, the
   payload with the tail) × 4 hashes × {PKCS#1 v1.5, PSS} — accepting combinations: **zero**.
3. **The tail as a hash carrier**: no md5/sha1/sha256/sha512/blake2b of any region appears inside the
   256 bytes; the tail itself does not appear inside the stream; its entropy is 7.2165 bits/byte — the
   81st percentile of the distribution of random 256-byte windows (control: 1171 windows of an
   AES-CTR stream). By measurement the tail is indistinguishable from random bytes.

**The conclusion on item 2, carefully:** the signature cannot be confirmed because there is no
verification key in the file; what the file does contain does not confirm the tail. So **the trust
boundary is not in the file but in the device** (the camera's loader/ROM). Which also means: anyone who
modifies the file will not be stopped by anything inside the file — see item 5.

What this does not mean: it is not "there is no signature". Those 256 bytes are exactly the size of an
RSA-2048 signature; formally that is the simplest explanation, but it cannot be checked without the key.

## 5. What else lies inside, and what forgery costs

- `fs_user` (1 253 376 B) is a **squashfs** image (`hsqs` at offset 0, sha256 `62e86fad…`); the blocks
  are compressed, so there are no strings in clear text in it (`strings` returned nothing).
- `firmware` (739 658 240 B) is a **tar of 159 members** (739 545 712 B of data): partition configs
  (`mount.conf`, `partinf.conf` — "Copyright (c) 2023 Sony Corporation", "Generated on:
  2023/06/29 8:17:15"), the regional backup files `CX85000_*.bin`, the images of partitions
  `/dev/nflasha5` (WBI, 300 MB), `/dev/nflasha8`, `/dev/nflasha15` (`/usr`, 500 MB), i2c firmware,
  licences, .sum files, two PEM keys, **170 root CA certificates** (ISRG, GlobalSign, GTS, DigiCert…)
  and **3 blocks of `OPENSSH PRIVATE KEY`** (a separate finding: private keys inside a publicly
  distributed image; round 278 corrected the count — 5 literal pairs, of which exactly one is a real
  key).
- **Internal integrity is CRC32.** The lines in the `*.sum` files look like
  `0,<crc32>,<size>,000001a4,00000000,000003e8,root,root,-1,-1,<name>,`. Checked on 12 members out of
  12 (0 mismatches). Control C5: after changing one byte of `mount.conf` I obtain a consistent new
  CRC32 **with no key at all** — that is, the internal integrity is forged in a single pass. The same
  holds for the container CRC32 in `DEND` (round 276, C8).
- Bottom line on trust: the confidentiality of the body is broken **publicly** (the key sits in an open
  PR since 2026-09-10); integrity inside the file is an unkeyed CRC32; the only thing that could stop a
  modified image is a check on the device itself, and that is invisible from a single file. Exactly
  that is what remains unknown.

## 6. What is not established (and why)

1. Who verifies the 256-byte tail and with which key. There is no key in the file; the 2048-bit key
   that is in the file does not confirm it as a signature.
2. Whether the camera verifies the tail at all (a loader dump or service mode is needed).
3. The contents of the squashfs were not unpacked (no `unsquashfs`/`squashfs-tools` in the container;
   that is the next cheap step). — _Done in round 278: 58 files, 3 151 747 B._
4. The marketing version "5.01" for the α7S III could not be confirmed from an external source: in
   this round `web_search` does not work (DuckDuckGo serves a challenge, Mojeek 403, grep.app 429), so
   Bing RSS and the GitHub API were used. The version is taken from the header and from the
   `ILCE-7SM3 v5.01` string inside the file.
5. The authenticity of the file itself: nothing inside the file proves that it has not been modified.

## 7. The instruments of this round and their errors

- `audit/round277_check.py` — 13 non-control green, 5 controls red (as they must be).
- `audit/f07.py` — entropy over 4 KiB/1 KiB/256 B, duplicate blocks of 16/32/64/1024, strings, a search
  for 58 digests/keys in the file, factorisation. Control: an AES-CTR stream and zeros.
- `audit/frame_probe.py` — the frame and the coordinates, the length arithmetic, an attempt to open
  with known keys.
- `audit/newkeys_probe.py` — five public keys against the body (this is what opened the file).
- `audit/unpack_full.py`, `audit/stream_analysis.py`, `audit/keys_and_sig.py`, `audit/allkeys_sig.py`,
  `audit/tail_rsa.py`, `audit/verify_stream.py`.

**F147–F152 (not one of them deleted).**
- F147 — the source of the whole F-07 confusion: comparing the ciphertext length with the stream
  offsets (my previous report; here it is measured what those bytes really were).
- F148 — `frame_probe.py` declared the `FdatHeader` structure to be 400 B; it is 512 B (I had
  re-estimated the size of the structure by eye; the version was measured: the crc over [12:512)
  matches, over [12:400) it does not).
- F149 — the first version of `round277_check.py` contained three controls phrased "in the same
  direction" as the check (they went green instead of red); fixed, now 5/5 red.
- F150 — that same version died of memory (`Killed`): the whole 743-MB file was read as a copy; now
  mmap.
- F151 — the "wrong key" control in `keys_and_sig.py` was blind: `decrypt()` is lazy and never reads
  bytes, so it "accepted" a key of zeros; in `verify_stream.py` the control reads the stream.
- F152 — the tail was measured as "entropy 7.2165" with no control; now there is a distribution over
  1171 random windows (the 81st percentile).

## 8. Artifact files

| file | what it contains |
|---|---|
| `audit/round277_checks.json` | 13 + 5 checks with their details |
| `audit/f07.json` | entropy/strings/duplicates/factorisation/digest search |
| `audit/frame_probe.json` | the frame of the first block, the coordinates, the length arithmetic |
| `audit/newkeys_probe.json` | five public keys against the body |
| `audit/unpack_full.json` | the unpacking, the header, the image types, the string context |
| `audit/stream_analysis.json` | frames, tar table of contents, keys, the tail, the reverse |
| `audit/keys_and_sig.json` | the PEM keys, the structural signature test, the version context |
| `audit/allkeys_sig.json` | every PEM block of the file and the .sum files |
| `audit/verify_stream.json` | two independent unpackers + controls |
| `audit/tail_rsa.json` | the tail against the Sony-PMCA-RE key |
| `out/stream.bin` | the unpacked stream (740 912 128 B) — **not** delivered to the volume |
| `out/tar_members.txt` | the list of the 159 tar members |

## 9. The fs_user image unpacked: this is the camera's own updater

`7z` (squashfs 4.0, ZLIB, created 2024-03-29 18:35) gives **58 files** — the update workbench of the
device: `bin/*.sh` (startupdate/endupdate/chkfirm/filecheck/us_crc32sum*…), `bin/*.elf` (ud_* — SPI/NOR/i2c
work, uc_mkfs, pformat), `bodylib/libupdaterbody.so`, `config/`, `cp/` (tomco.txt, udtrcp.bin),
`usr/lib/`. Three facts out of it:

1. `config/chassis` = **`CXD90057+CXD90058`** — an independent confirmation that the device is of the
   CXD90057 class (it matches the name of the decrypting `CXD90057_k8`).
2. `config/body_version` = `700.104.039` (the internal version of the body; it does not equal the
   `5.01` from the header — these are different counters and must not be confused).
3. **`config/config.xml` — the entire update pipeline consists of CRC32 checks**: every step
   `key=…_sum/…sum` calls `us_crc32sum*.sh`/`ul_crc32sumprfile.so` and only then the installer. There
   **is no signature step** in the pipeline. That is, the camera's updater (this layer) checks
   integrity with CRC32 and nothing more; a check of the 256-byte tail, if it exists, sits below this
   layer (bootloader/ROM) and is invisible from the file.
4. The updater binaries contain **no** RSA key material (a search for DER SPKI/PKCS#1: 0 hits), even
   though `pformat.elf` is linked against OpenSSL (`i2d_RSA_PUBKEY`, `PKCS7_ATTR_VERIFY_it`).

**In total the file contains 5 distinct public RSA keys**: 3 × 3071 bits, 1 × 3072 (the two PEM files
in `setting/`) and **1 × 2048** (offset 429 029 376). Only the last one could, by size, sign our 256
bytes — and it does not confirm them as a signature (no structure). Not one of the five confirms the
tail; nor does the published Sony-PMCA-RE modulus checked earlier. — _The re-verification of round 281
counted again and found **6** distinct moduli and 8 `BEGIN PUBLIC KEY` literals; the literal count is
not the key count (F163, D10b)._
