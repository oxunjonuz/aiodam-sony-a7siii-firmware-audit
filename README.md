# Sony ILCE-7SM3 (α7S III) firmware update audit

**What is openly readable in a Sony ILCE-7SM3 (α7S III) firmware update file, and where the trust boundary really sits**

Oxunjon Ubaydullayev and Aiodam (autonomous research agent), 4 October 2026.

**Archive:** [Zenodo, DOI 10.5281/zenodo.23142465](https://doi.org/10.5281/zenodo.23142465) · **Repository:** https://github.com/oxunjonuz/aiodam-sony-a7siii-firmware-audit

Read the [14-page paper](publication/paper/main.pdf), [verification report](publication/VERIFICATION.md), and [latest research report](ROUND_284.md).

## Scope and findings

### Credit for the firmware-decryption key

**David Buchanan ([DavidBuchanan314](https://github.com/DavidBuchanan314)) published the CXD90057 firmware-decryption key and support code on 11 September 2026 in [ma1co/fwtool.py PR #52](https://github.com/ma1co/fwtool.py/pull/52). AIODAM did not discover or extract this decryption key.** The contribution initially concerned Sony A7 IV (ILCE-7M4); the same PR discussion also records Buchanan's successful test on ILCE-7SM3 (A7S III). Accordingly, this work does not claim the first discovery of A7S III compatibility either. AIODAM located this recently published contribution, applied it to the exact firmware input audited here, and checked the resulting bytes and structures.

This firmware-decryption key is **not** the SSH private key subsequently identified inside the decrypted firmware. The two findings must not be conflated. The paper already credits DavidBuchanan314 in its section on body decryption; this note makes that attribution prominent on the project page.

This research audits one public `BODYDATA.DAT` file using static measurements, custom instruments, negative controls, and a bounded observation of the owner's camera. It distinguishes properties measured from firmware bytes from properties that require device-side evidence.

The paper reports recomputable CRC integrity checks, publicly documented decryption methods, recovered updater and firmware structures, and a shipped unencrypted SSH private key. The observed live camera host key **does not match** the shipped key. No authentication, camera modification, or operational exploit is claimed. Signature enforcement and other device-side trust-boundary questions remain outside what the file alone proves.

Earlier reports, instrument failures, corrections, and saved verification outputs are retained rather than rewritten as if the final result had been known from the start. Consult the final paper and the later reports when earlier measurements conflict.

## Contents

- `publication/paper/`: unchanged PDF, LaTeX source, and numerical appendix.
- `publication/`: verification instruments, number bindings, saved runs, correction records, and bounded live-observation evidence.
- `audit/`: research instruments and saved measurement outputs.
- `AUDIT_REPORT.md`, `ROUND_*.md`, `research_README.md`: original research records.
- `MAC_FINGERPRINT.sh`: original owner-device observation tool; it is not run during publication.
- `tools/`: reference tool sources with their original licenses; see [external inputs](EXTERNAL_INPUTS.md).
- `SOURCE_SNAPSHOT.json`: hashes of the original files copied into this release.
- `SHA256SUMS`: distribution checksums, independent of historical research manifests.

## Reproduction and limits of this distribution

The scripts preserve their original `/work/SONY_A7SIII_UPDATE` paths. Mount or place the checkout there for reproduction. The original instructions are in [research_README.md](research_README.md) and [publication/README.md](publication/README.md).

The proprietary firmware and extracted firmware trees are **not included**. You must independently obtain the exact input and regenerate the intermediate files before running the full audit. See [EXTERNAL_INPUTS.md](EXTERNAL_INPUTS.md). This release is not a self-contained firmware image or a claim that all checks were rerun during publishing. Saved outputs report the research runs; publication preparation checked file integrity and packaging.

Do not run device/network probes against systems you do not own or have permission to test. `publication/run_all.sh` includes the original audit workflow, which may attempt the documented live-camera check. A skipped live check is not a passing live check.

## Licenses

The paper, original reports, and original research data are licensed **CC BY 4.0**. Original AIODAM code is licensed **MIT**. Third-party code in `tools/` retains its original licenses and is not relicensed. Sony firmware is not redistributed or relicensed. See [LICENSE.md](LICENSE.md).

This is independent research, not a Sony publication or endorsement.
