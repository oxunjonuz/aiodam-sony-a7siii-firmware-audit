# External inputs and publication exclusions

## Exact firmware input

- Name: `BODYDATA.DAT`, Sony ILCE-7SM3 (α7S III) update file.
- Size: 743818632 bytes.
- SHA-256: `dbdd8b02ed81d6f0e0a0d36b55f5d12fa1bcf8682fbad1393996f10d1494c9eb`.
- Obtain firmware from Sony's official support/download service for this camera. The original records do not establish a durable direct download URL; do not assume a newer update is the same input. Require the hash above before comparing measurements.

The repository does not redistribute `BODYDATA.DAT`, `out/`, `out_fwtool/`, extracted filesystems, extracted SSH private-key bytes, virtual environments, caches, or temporary work. The observed private key is documented by public fingerprints and measurements, not distributed here.

## Reference implementations

- https://github.com/ma1co/fwtool.py
- https://github.com/ma1co/fwtool.py/pull/52 — David Buchanan (`DavidBuchanan314`) published the body-decryption constants and CXD90057 support on 11 September 2026. Initially developed for A7 IV; the author also reports A7S III compatibility in that discussion. AIODAM reused this recently published work, not a newly discovered decryption key.
- https://github.com/ma1co/Sony-PMCA-RE

The checked-in source copies retain their `LICENSE.txt` files. Their hashes are in `SOURCE_SNAPSHOT.json` and `SHA256SUMS`. Publicly published firmware-decryption constants used by the research are distinct from the extracted SSH private credential. The latter is not shipped.

The third-party sample `tools/Sony-PMCA-RE-master/certs/localtest.me.pem` is omitted because it contains a private-key block; it is not needed to read this paper or its static evidence. Download archives are omitted because their source trees are already included. Python caches and LaTeX build intermediates are omitted.

## Historical manifests

`publication/MANIFEST.sha256` and `publication/artifacts.json` are original research artifacts. They may precede the last source edits. They are preserved unchanged for provenance, not presented as the release-integrity authority. Use root `SHA256SUMS` for the files actually published. `SOURCE_SNAPSHOT.json` verifies the copied original files against the publication-time source snapshot.
