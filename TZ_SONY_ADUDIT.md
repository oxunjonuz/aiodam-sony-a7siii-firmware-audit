## Terms of reference: security audit of the Sony A7S III (ILCE-7SM3) firmware

*Translated from the Russian terms of reference exactly as commissioned; nothing in the wording
was otherwise changed. The Russian original is preserved in the translation backup archive
(`/work/SONY_A7SIII_translation_backup/`).*

### 1. Goal
Identify possible vulnerabilities in the update process, the firmware format and the
authentication mechanisms that could lead to compromising the device or disrupting its
operation. The result is a report describing the potential weak points and recommendations
for removing them.

### 2. Scope
- The firmware update file (BODYDATA.DAT).
- The process by which the camera loads and verifies firmware.
- The firmware container format, the partition structure, the file system.
- The digital signature and encryption mechanisms.
- The update logic: version checking, anti-rollback, integrity.

### 3. Constraints and ethics
- **Static analysis only**, plus emulation in an isolated environment.

### 4. Stages of work

#### Stage 1. Collection and preparation
- Obtain the official update file from the Sony website.
- Record the hash sums (MD5, SHA-1, SHA-256).
- Determine the file type (`file`, `binwalk`, `strings`).
- Unpack the container (if possible) without breaking the signature.

#### Stage 2. First-pass analysis
- Study the file structure: headers, partitions, tables.
- Find strings that name the version, the model, the build date.
- Determine whether encryption is used (high entropy).
- Check for open regions (scripts, configs, binaries).

#### Stage 3. Analysis of the protection mechanisms
- Study how signature verification is implemented:
  - Where the root of trust lives (Boot ROM, a separate chip).
  - Which algorithms are used (RSA, ECDSA, SHA).
  - Whether there is anti-rollback protection.
- Check the error handling on a bad signature.
- Look for known weak points: partial signature comparison, predictable keys, partitions that are
  not checked at all.

#### Stage 4. Looking for vulnerabilities in the parser
- Analyse the code that parses the update file.
- Look for buffer overflows, integer overflows, format-string errors.
- Check how large files, non-standard headers and damaged data are handled.
- Use fuzzing in an emulator (QEMU, Unicorn) to look for crashes.

#### Stage 5. Analysis of the update logic
- Check whether the camera can be made to accept an older version (downgrade).
- Whether the file can be substituted through alternative paths (USB, memory card).
- How interrupts during the update and power loss are handled.
- Check for debug interfaces that may be active in a release firmware.

#### Stage 6. Documentation
- Write a report with a classification of the findings (CVSS, CWE).
- State which vulnerabilities require physical access and which are remote.
- Propose mitigations.
- Do not publish exploits before the vulnerabilities are fixed.

### 5. Tools (recommended)
- `binwalk`, `unsquashfs`, `7z`, `strings`, `hexdump`
- `Ghidra`, `IDA Free`, `radare2` — for disassembly
- `QEMU`, `Unicorn` — for emulation
- `AFL`, `honggfuzz` — for fuzzing
- `fwtool.py`, `Sony-PMCA-RE` — for understanding the format (if applicable)

### 6. Expected result
- A report listing the potential vulnerabilities.
- An assessment of whether they can be exploited (without writing exploits).
- Recommendations for strengthening the protection.
- A final conclusion: are there real paths to modify the firmware, or is the protection
  unbreakable at the current level.

### 7. Stop criteria
- If the agent finds that every critical partition is signed and verified correctly and the parser
  is robust, record that as the result.
- On finding a serious vulnerability, report it to the responsible person immediately and do not
  publish it.
