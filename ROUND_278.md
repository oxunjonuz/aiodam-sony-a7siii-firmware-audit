# ROUND 278 — the unpacked squashfs and the single private key

_Everything is measured on `BODYDATA.DAT` itself (743 818 632 B, sha256
`dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb`) and on the stream unpacked from
it, `out/stream.bin` (740 912 128 B, sha256
`11880291ae4bd08b61c9d08475ee8a33703b1c8f08ad35cbcda3a47174101e66`).
No experiment changed the original. Reproduce with one command:_

```
cd /work/SONY_A7SIII_UPDATE && python3 audit/round278_check.py
# 17 non-control green out of 17, 5 controls red out of 5
```

Two of the owner's points are closed, and on the first of them I have to begin with a correction to
myself.

_Corrections added at round 281, kept visible rather than edited into the text: the key block is
**504 B**, not 501, and the base64 body is **435** characters, not 471 (471 is the offset at which
the closing line begins — an offset that entered the reports as a length; error F161 in
`publication/FAILURES_281.md`). The body of this report is left as it was written._

---

## 1. Squashfs unpacked — and here is what is in it

**Correction.** Report 277 said "the contents of the squashfs are not unpacked (there is no
`unsquashfs` in the container)". That was untrue in two senses: `7z` is in the container and handles
squashfs 4.0, and I had stopped at the list of names (`7z l` — 58 lines) without extracting. The
owner is right.

**What was done.** The file-system area is cut out of the stream exactly (offset 512, length
1 253 376, sha256 `62e86fad175e0326969d5f1cea29d780feb496ce8034acd2c9c3954320d8ccaa`) and unpacked
in full:

| | |
|---|---|
| format | SquashFS 4.0, ZLIB, created 2024-03-29 18:35, `DUPLICATES_REMOVED EXPORTABLE` |
| files | **58**, of them ELF **31** (all AArch64, `e_machine=183`) and scripts **21** |
| unpacked | **3 151 747 B** (the image is 1 253 376 B; 2.5:1) |
| where | `out/fs_root/`, with the list and the hashes in `out/fs_inventory.json` (built by `audit/fs_inventory.py`) |

The roles were read out of the files themselves (a binary's usage string, a shebang, `config.xml`),
not assigned from the names. The thirty-one programs fall into five groups:

**(a) Partitioning and media format.** `edisx.elf` (`Usage: edisx.elf device_file partinfo_file`)
splits partitions by `partinf.conf`; `uc_mkfs.elf` (`Usage : uc_mkfs [-m mode] -f filename`) creates
a file system; `chknandcapa.elf` checks the NAND capacity; `pformat.elf` (1 631 008 B,
`Usage: pformat.elf <option> devicename`, options `-v -d -c`) writes images by `pformat_config` and
**carries a full OpenSSL inside it** — its strings include `AES_encrypt`, `aes_v8_cbc_encrypt`,
`CMS_EncryptedData_it`, `d2i_PKCS8_PRIV_KEY_INFO`, `SM4_encrypt`, `Camellia_cbc_encrypt` and its own
`[Encrypt] Error: …` branch, so encryption/decryption of images on the device exists and lives
exactly here.

**(b) Raw flash writers.** `ud_lerase.elf` (`Usage: ud_lerase.elf <Device> <partition>`),
`ud_nor_pformat.elf`, `ud_spirom_firmup.elf`, `ud_parallel_spirom_firmup.elf`,
`ud_spicom_boot.elf`, `ud_cp_firmup.elf`, `ud_pd_firmup.elf`, `ud_darwin_firmup.elf` (ISP),
`ud_fsys_format.elf`, `ud_wbi_drop.elf` (`Usage: ud_wbi_drop.elf filename`), `ud_keep_backup.elf`.

**(c) Hardware probing.** `ud_get_power_ic_type.elf` (Charon/DSC/CA/Piroshiki/Darwin),
`ud_get_boot_device.elf`, `ud_get_boot_ext.elf`, `ud_get_data_from_mis.elf`,
`ud_get_addr_from_infosec.elf`, `ud_get_uudtype.elf`, `ud_init_sio_port_setting.elf`,
`ud_init_spi_port_setting.elf`, `ud_ioex_sel_en.elf`, `getledval.elf` (the error code shown on the
LED), `spicom.elf` (SPI communication: `[Debug]download and hash check command need 3 Parameters`,
`ERROR: Hash Compare Error, not same.` — so it has a **debug** command for downloading and comparing
a hash).

**(d) Plumbing.** `bksb.elf` (assembling `LdrBkup.bin` out of `Backup.bin`),
`bodylib/libupdaterbody.so` (the updater core in C++; its symbols include
`KeyTagFactory::GetKeyTag`, the classes `Mode1/3/5/6FlagFile`, `FlagFirmwareInformationHandler`),
`usr/lib/libupdatercommon.so`, `ul_crc32sumprfile.so` (the CRC32 plugin).

**(e) The pipeline's rules and data.** `config/config.xml` is the update map itself: every step is
tied to its own checksum, and the order is exactly **check the CRC32 of the group, then run the
module** (`config_sum/config.sum` → `us_crc32sum.sh` + `chkfirm.sh` + `edit_mount.sh` +
`keep_big_backup.sh`; then `updater_sum`, `appli_sum`, `part_image_sum`, `partconf_sum` →
`us_mkfs.sh`, `front_sum`, `ca_sum`, `darwin_sum`, `prfile_sum` → a call into
`ul_crc32sumprfile.so`). Plus `common.src` (error codes, mounts and **`MODE_SERVICE=2`**),
`mount.conf` (30 partitions), `cp/tomco.txt` (UART 460800, the addresses of tmon/klog),
`cp/udtrcp.bin` (the CP download protocol over the serial line — the symbols `uart_init`,
`uartbuf_*`, `###warning### invalid RTO`).

**Two things in the scripts worth knowing separately.** In `loader_writer.sh` the line
`#    $MD5SUM_COMMAND -c $SUM_FILE` is **commented out**: the loader's md5 is not checked
(`nor_loader_writer.sh` declares `loader_nor.md5` but never calls the check). An honest caveat: the
loader image itself is marked `enc = 1` in `pformat_config.txt` inside `nor_loader.tar`, so integrity
may be provided by the decrypter — but there is no external CRC/MD5 check in the delivered scripts,
and that is measured, not deduced.

---

## 2. Correction: "three OPENSSH PRIVATE KEY blocks" — there are not three

In round 277 I wrote that the image holds "three `OPENSSH PRIVATE KEY` blocks". That was an error of
my instrument: I counted literals, not keys. Measured now:

| where | how many | what it really is |
|---|---|---|
| the whole stream (740 912 128 B) | 10 occurrences of the literal `OPENSSH PRIVATE KEY` | that is 5 BEGIN lines and 5 END lines |
| offsets 69 454 712, 186 092 096, 294 356 432, 558 669 176 | 4 pairs | **string tables of binaries**: the BEGIN and the END stand 40 bytes apart |
| offset 587 628 092 | 1 pair | a **real key**: 471 base64 characters between BEGIN and END (round 281: the body is 435 characters — see the corrections at the top) |

Which binaries exactly (from the context around them): libcrypto (`bcrypt`, `aes256-ctr`,
`openssh-key-v1`, and nearby `from %s to %s`), libssh2 (`Error parsing PEM: …`,
`keepalive@libssh2.org`), a second copy of libcrypto without RSA/DSA suffixes — and all of it lies
in the member `0700_part_image/dev/nflasha15` (`/usr`, 403 116 032 B), that is, in the camera's
libraries rather than in data.

**The discriminator this rests on** (and it is the check, not an argument): a real key must have
hundreds of base64 bytes between its opening and closing lines, while in a string table the C strings
stand back to back. 4 ≤ 64 bytes, 1 = 471 bytes. Control: a "key" assembled from a string table does
not parse (C2).

---

## 3. The single key: what it is, and whether it works

| | |
|---|---|
| where | the member **`0700_part_image/dev/nflasha5`** (`/wbi`, 209 984 960 B), at stream offset **587 628 092** |
| block size | **501 B** (opening line + body + closing line) — round 281: **504 B** (F161) |
| container | `openssh-key-v1`, `cipher = none`, `kdf = none`, **1** key |
| type | **`ecdsa-sha2-nistp256`**, curve `nistp256`, a 65 B point |
| comment | `root@(none)` (it never appears in clear text in the file — it is inside the base64) |
| checkint | 252 642 532 = 252 642 532 (they match), padding 1,2,3,4 |
| fingerprint | **`SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI`** |
| public part | `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAuoJrSuZ6vJ8E5i7ljq3qejSfe7hQORqGstDZLq7m0X1cXel0INCJAFjs89KvyuhDqq0jMB+9fyYBCcJlVWCow=` |

**Does it work — yes, and that is checked by three independent routes, none of which leans on my own
decryption:**

1. I parsed the container myself and recomputed the public point from the private scalar on P-256
   (my own arithmetic, no libraries): `d*G` **matched** the embedded point byte for byte. That is the
   proof of usability: anyone holding these bytes can complete a signature that will agree with this
   public part.
2. `ssh-keygen -l` on the **raw bytes from the file** prints exactly that fingerprint and that
   comment — so the OpenSSH tool agrees with my arithmetic.
3. `ssh-keygen -y -e -m pem | openssl pkey -pubin -text` parses the public part:
   `Public-Key: (256 bit)`, `ASN1 OID: prime256v1`, `NIST CURVE: P-256`, coordinates
   `04:0b:a8:26:b4:ae:67:ab…` — the same ones I derived.

The key is **not passphrase-protected** (otherwise `cipher` would be `aes256-ctr` and `kdf` would be
`bcrypt`). There is no half-answer here: these 501 bytes are a ready private key, not a pointer to one.

**The control without which none of this is worth anything:** corrupting one bit of the scalar breaks
`d*G = Q` (C1), and the search is **not** vacuous — a corrupted public blob is not found in the file
while the real one is found exactly once (C3).

---

## 4. What this key is for — read out of the same file, not assumed

**(a) The camera's single `HostKey` is named exactly so.** `0800_appli/tmp/ssh/sshd_config`
(3 094 B, from the update) contains **one** `HostKey` line:

```
HostKey /tmp_network/ssh/ssh_host_ecdsa_key
HostKeyAlgorithms ecdsa-sha2-nistp256
```

The host algorithm in the config is **the same as the found key's** (ECDSA-256, and nothing else).
The match "key type = host type in the config" is not a coincidence here: it is the same role.

**(b) The text of the script that creates this key was found** — `/usr/bin/create_host_key.sh`
(offset 395 581 615, member `0700_part_image/dev/nflasha15`):

```
#!/bin/sh
#IM_System
RES="1"
/usr/bin/ssh-keygen -q -b 256 -t ecdsa -N '' -f /tmp_network/ssh/ssh_host_ecdsa_key
if [ "$?" == "0" ]; then
  RES="0"
fi
exit "$RES"
```

These are exactly the parameters of the found key: `-t ecdsa -b 256`, an **empty passphrase**
(`-N ''`) and the same path `/tmp_network/ssh/ssh_host_ecdsa_key`. The comment `root@(none)` is what
`ssh-keygen` writes when it is run as root on a machine without a name (`hostname` = `(none)`), so the
key was made by **this** script. The second script of the same circuit, `get_finger_print.sh`, was
found in full as well: it takes the fingerprint with
`/usr/bin/ssh-keygen -lf /tmp_network/ssh/ssh_host_ecdsa_key > …/tmp_finger_print`.

**(c) The circuit it lives inside** — strings of the C++ component `network::InfraSshManager`
(`SshController`, `SshFunctionWrapper`) in the same images:
`GET_FINGER_PRINT_SHELL=/usr/bin/get_finger_print.sh`,
`CREATE_HOST_KEY_SHELL=/usr/bin/create_host_key.sh`, `SSHD_START_CMD=/usr/sbin/sshd`,
`SSHD_STOP_CMD=/bin/busybox killall sshd`, `/tmp_network/ssh/ssh_host_ecdsa_key.pub`, the counters
`ssh_session_count` and `ssh_auth_failed_count.%d`, `/sbin/pam_tally2 --reset -u`,
`/var/run/sshd.pid`. The PAM references in `pam.d/ssh` (the same delivery) point at
`ssh_account_lock_recorder` (8 occurrences in the file) and `ssh_session_monitoring` (7) — names that
really are in the image (check N17).

**(d) What this sshd is for at all.** `PubkeyAuthentication no`, `PermitRootLogin no`,
`PasswordAuthentication no`, `ChallengeResponseAuthentication yes` + `UsePAM yes`, `MaxSessions 0`,
`PermitOpen localhost:15740 localhost:60152`, `AllowTcpForwarding yes`, `Ciphers aes128-ctr`. This is
a **tunnel**: entry only through PAM (pam_unix against `passwd`, where `root:*:0:0` — that is, root is
locked out, plus `pam_tally2` with `deny=20 unlock_time=60`, plus even `even_deny_root`), and after
entry only a forward to `localhost:15740` (the Sony PTP/IP port) or `:60152` is allowed. There is no
shell (`MaxSessions 0`).

---

## 5. Is this the key "of the service mode" — the answer is no, and here is the measurement

- There is exactly **one** private key in the whole file, and it is a **server** key: the identity of
  the host, not a pass to get inside. Public-key login on this camera is **forbidden by the config**
  (§4d), so the key itself opens nothing.
- Its public part occurs in all 740 MB **exactly once** — inside the key itself (N9). There is no
  `.pub`, no `authorized_keys`, no `known_hosts` with it in the file: there is nowhere to verify and
  accept this key except in the memory of a client.
- Its risk runs the **other** way: these 501 bytes lie in a publicly distributed firmware file, in the
  `/wbi` image, so **everyone who downloaded the update has the private half of the host key**. Whoever
  holds it can impersonate the camera to a client that expects this key (a service program, a script,
  a technician's `known_hosts`). And these are the same bytes in every copy of firmware 5.01.
- **What I did not establish and do not present as established:** whether the *camera* actually uses
  **this** key. The script `create_host_key.sh` creates a key **at that same path** and, judging by
  `ssh-keygen` (which asks before overwriting and fails in a non-interactive mode), works as "create if
  absent". So there are two possibilities: either the key from the image is the device's host key, or
  the device made its own on first boot and the one found is a snapshot of the environment in which the
  WBI was taken. From a single file these are indistinguishable, and I do not choose. **The decisive
  check is one and it can be named exactly:** take the fingerprint on the live camera
  (`get_finger_print.sh`/`ssh-keyscan`, port 22 once the network stack is up) and compare it with
  `SHA256:J8L9aBLEimTdDW5m1iV7wU64LP1iWo3+lj9MGCxNODI`. If it matches, the key is common to the whole
  model; if not, the key in the image is an artefact, and the question becomes "why does a developer's
  private key end up in a shipment".

---

## 6. What else is visible in the unpacked image and in the file about service and debug paths

This answers "maybe there are keys and debug interfaces in there" — with measured names and their
occurrence counts in the stream, not guesses:

| name | occurrences | what it is (from the file's own strings) |
|---|---|---|
| `myftm` | 44 | the factory Wi-Fi test mode: `Starting QTIP server`, `QTIP`, `SCPC cal request`, the commands `WlanATSetWifiFreq/TxPower/Antenna/Rate/Gain…` (Qualcomm FTM) |
| `crypter.elf` | 14 | reading an encrypted update file **from a card**: `chunk=`, `.fdat`, `.full`, `.fs=`, `.fsys`, the devices `/dev/mmca`, `/dev/ms` |
| `Wltestcmd`, `btRFTest.elf`, `ulogio`, `ujlog.elf`, `im.elf`, `sndcmd.elf`, `rcvcmd.elf`, `SetPort.elf`, `change_mode.sh`, `us_remove_modes.sh`, `ud_send_lsi.elf`, `app_monio.elf`, `NsBkSet.elf`, `startBTCore.sh`, `iperf`, `soundstretch` | 2–1159 | the tool table of the network processor (the same table lies both in `/usr` and in `/wbi`) |
| `libnss_ssh` | 6 | login into sshd through an NSS module: `nsswitch.conf` says `passwd: files ssh` — the user list is served by `SshManager` |

Separately: `MODE_SERVICE=2` in `common.src` — the update **does** have a service mode, and the scripts
behave differently in it than in the product mode: in `us_mkfs.sh` it skips `edisx.elf` (that is, it
does **not** re-partition) and writes only the app image, while `keep_big_backup.sh` exits at once in
the modes `USER|SERVICE|MINOR|MSCRYPT`. But that is an **update** mode, not an entry point; there is no
key for it in the file.

---

## 7. What this is checked by, and which instrument errors turned up along the way

`audit/round278_check.py` — **17 non-control green out of 17, 5 controls red out of 5**
(`audit/round278_checks.json`). The controls: corrupting a bit of the scalar breaks `d*G=Q`; a "key"
from a string table does not parse; a corrupted public blob is not found while the real one is; the
old count "3" is false; the unpacking did something different from the image.

Three errors of this round — all mine and all in the instruments, not one of them deleted:

- **F153.** The first version of check N9 looked for the **full** base64 string of the public part and
  got "0 occurrences", from which the false conclusion "there is no public part in the file" would
  follow. The cause: the key body is wrapped at 70 characters, so no single whole line exists. Now a
  60-character prefix is searched for, and the result is phrased as "once, inside the key itself".
- **F154.** Control C3 ("the search is not vacuous") first corrupted the **last** byte of the blob
  while searching for the first 60 characters — the corruption did not fall inside the search, so the
  control went green where it must go red. The corruption was moved to byte 40.
- **F155.** Check N15 counted `HostKey` by prefix and caught
  `HostKeyAlgorithms ecdsa-sha2-nistp256` as a second host key. Fixed to `HostKey ` with a space; then
  the host key really is one.

And one correction of substance, not of instrument: **§2 above** — the "three blocks" in round 277 were
a count of literals, not of keys.

---

## 8. What this round does NOT establish

1. Whether the **camera** uses the found key (see §5 — the decisive check is named).
2. Whether `myftm`/QTIP runs in the field and whether it has any authentication is not checked: I read
   only its strings, I did not disassemble it.
3. The media format of `/wbi` is not parsed: in `nflasha5` there are 909 candidates for the magic
   `0x53EF` and not one passes an ext2 superblock check — that is, I did not find a file-system
   container there; the key lies in an area filled with zeros, right after the code area, and its
   record/container is not identified (the two-byte field `58 02` before the key is not identified
   either).
4. `crypter.elf` — strings only: the `chunk/.fdat/.full/.fsys` format is not parsed, and card
   ingestion (`/dev/mmca`) was not tested on the device.
5. Signature verification is still not checked (see §0 of `AUDIT_REPORT.md`): there is no verification
   key in the file.
6. The `.ltt` fonts, `kikilog.dat`, `heapmon.conf`, `toprc`, `regroot.pem` (Amazon Root CA 1) from the
   delivery were not analysed — they are outside the owner's question.
