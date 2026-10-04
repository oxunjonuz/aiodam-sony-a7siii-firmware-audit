#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inventory of the unpacked squashfs (out/fs_root) -> out/fs_inventory.json.

Sizes, type (ELF/script/data) and architecture are measured; the role is read out of
the file itself (usage string, shebang, config.xml) and marked as read.
"""
import hashlib
import json
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FS = os.path.join(ROOT, 'out', 'fs_root')
OUT = os.path.join(ROOT, 'out', 'fs_inventory.json')

ROLE = {
    'pformat.elf': 'partition formatting/writing; usage: pformat.elf <option> devicename; carries OpenSSL (AES/CMS/PKCS8/SM4/Camellia) and the [Encrypt] path',
    'edisx.elf': 'partition splitting: edisx.elf device_file partinfo_file',
    'uc_mkfs.elf': 'creating a file system: uc_mkfs [-m mode] -f filename',
    'uc_crc32sum.elf': 'CRC32 over a list of files (not a signature)',
    'chknandcapa.elf': 'checking NAND capacity against partinf.conf',
    'ud_lerase.elf': 'erasing a partition: ud_lerase.elf <Device> <partition>',
    'ud_nor_pformat.elf': 'writing the loader image to NOR',
    'ud_spirom_firmup.elf': 'flashing the SPI-ROM',
    'ud_parallel_spirom_firmup.elf': 'flashing a parallel SPI-ROM',
    'ud_spicom_boot.elf': 'switching SPI into boot mode',
    'ud_cp_firmup.elf': 'flashing CP (the image processor)',
    'ud_pd_firmup.elf': 'flashing PD',
    'ud_darwin_firmup.elf': 'flashing Darwin (ISP)',
    'ud_fsys_format.elf': 'formatting the user file system (nflasha24)',
    'ud_wbi_drop.elf': 'dropping WBI: ud_wbi_drop.elf filename',
    'ud_keep_backup.elf': 'saving/dropping Backup.bin',
    'ud_get_power_ic_type.elf': 'determining the Power IC type (Charon/DSC/CA/Piroshiki/Darwin)',
    'ud_get_boot_device.elf': 'determining the boot device (NOR/eMMC)',
    'ud_get_boot_ext.elf': 'determining the external boot device',
    'ud_get_data_from_mis.elf': 'reading a header from MIS',
    'ud_get_addr_from_infosec.elf': 'reading the DDR training address from the Information Sector',
    'ud_get_uudtype.elf': 'the UUD type (needed to decide on dropping userdata)',
    'ud_init_sio_port_setting.elf': 'configuring the SIO port',
    'ud_init_spi_port_setting.elf': 'configuring the SPI port',
    'ud_ioex_sel_en.elf': 'enabling the IO-expander selector',
    'spicom.elf': 'SPI communication: download and hash comparison (debug commands)',
    'getledval.elf': 'the error code shown on the LED',
    'bksb.elf': 'assembling LdrBkup.bin out of Backup.bin by the LdrBkupList.txt list',
    'ul_crc32sumprfile.so': 'CRC32 plugin over prfile (called from config.xml as a function)',
    'bodylib/libupdaterbody.so': 'the updater core (C++), including KeyTagFactory::GetKeyTag and the Mode*FlagFile classes',
    'usr/lib/libupdatercommon.so': 'common functions of the updater core',
    'config/common.src': 'constants: mounts, error codes, UPDATER_ACTION_MODE (including MODE_SERVICE=2)',
    'config/config.xml': 'the update pipeline: for every group, check the CRC32, then run the module',
    'config/mount.conf': 'the table of 30 partitions and their mount points',
    'config/body_version': 'the internal body_version counter (700.104.039)',
    'config/chassis': 'CXD90057+CXD90058',
    'cp/tomco.txt': 'TOMCO/CP configuration: UART 460800, the addresses of tmon/klog/boottime',
    'cp/udtrcp.bin': 'the CP download protocol over the serial line (uart_*, RTO)',
    'bin/loader_writer.sh': 'writing the loader from eMMC (the md5 check inside the script is commented out)',
    'bin/nor_loader_writer.sh': 'writing the loader to NOR, assembling the NOR image from /cp/*.bin; the loader_nor.md5 check is never called',
    'bin/keep_big_backup.sh': 'keeping large files through a ramdisk',
    'bin/us_ca_firm.sh': 'flashing CA (an external adapter) through ka.ko',
}


def sha(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for b in iter(lambda: f.read(1 << 20), b''):
            h.update(b)
    return h.hexdigest()


items = []
for dirpath, _d, files in os.walk(FS):
    for fn in sorted(files):
        p = os.path.join(dirpath, fn)
        rel = os.path.relpath(p, FS)
        with open(p, 'rb') as f:
            head = f.read(4096)
        kind, arch = 'data', None
        if head[:4] == b'\x7fELF':
            kind, arch = ('elf-so' if head[16] in (3,) else 'elf-exec'), int.from_bytes(head[18:20], 'little')
        elif head[:2] == b'#!':
            kind = 'script (' + head.split(b'\n')[0][2:].decode('latin1', 'replace') + ')'
        elif rel.endswith('.txt') or rel.endswith('.conf') or rel.endswith('.src'):
            kind = 'text'
        items.append({'path': rel, 'bytes': os.path.getsize(p), 'sha256': sha(p),
                      'kind': kind, 'arch': arch, 'role': ROLE.get(rel)})

items.sort(key=lambda x: x['path'])
doc = {
    'source': 'BODYDATA.DAT -> out/stream.bin[512:512+1253376] = squashfs 4.0 ZLIB',
    'squashfs_sha256': sha(os.path.join(ROOT, 'out', 'fs_user.sqsh')),
    'files': len(items),
    'bytes_total': sum(i['bytes'] for i in items),
    'elf_count': sum(1 for i in items if i['kind'].startswith('elf')),
    'script_count': sum(1 for i in items if i['kind'].startswith('script')),
    'items': items,
}
json.dump(doc, open(OUT, 'w'), ensure_ascii=False, indent=1)
print(json.dumps({k: doc[k] for k in ('squashfs_sha256', 'files', 'bytes_total', 'elf_count', 'script_count')},
                 ensure_ascii=False, indent=1))
print('written:', OUT)
