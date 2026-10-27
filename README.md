# VnaolteFirmware Ghidra extension

Java support for ingesting the firmware formats encountered while turning cellular modems into RF instrumentation.

## Filesystems

- **Sierra CWE** (`sierracwe`) — parses the 400-byte Sierra component header, nested `SPKG`/`BOOT`/`MODM`/`APPL` containers, and zlib-compressed leaves.
- **Wide YAFFS2** (`yaffswide`) — reconstructs logical files from raw NAND pages using the 4096-byte data + 160-byte OOB geometry used by SWI9X30C firmware. This exists because stock Ghidra assumes 2048+64 YAFFS geometry.
- **Legacy Android boot** (`androidbootlegacy`) — handles the classic pre-`header_version` Android boot header where offset `0x28` is `dt_size`.
- **Qualcomm QCDT** (`qcdt`) — exposes each unique DTB from Qualcomm device-tree tables and records all selector tuples referring to it.

Together the EM7455 image can be browsed as:

```text
SWI9X30C_02.38.00.00.cwe
├── MODM/DSP2.yaffs2/image/modem.mdt + modem.bNN
├── MODM/TZON.elf
├── MODM/QRPM.elf
└── APPL/APPS.bootimg
    ├── kernel.bin
    └── dt.img
        └── dtb/*.dtb
```

Qualcomm executable loading is intentionally delegated to **QDig/QualcommLoaders**, which already handles split `modem.mdt + .bNN` images and Hexagon correctly on Ghidra 12.1+.

## Analyzers

`VNAOLTE Qualcomm q6zip Decompressor` runs before disassembly. It recognizes old DLPager q6zip RX segments structurally, infers dictionary sizes from the self-consistent absolute pointer table, scores dictionary order and lookback width by page decode quality, finds the modem-owned `runtime_start/runtime_end/compressed_start/compressed_end` descriptor, and maps the reconstructed executable pages at their real Hexagon runtime addresses. No EM7455 addresses or 10/12/9 compression parameters are hard-coded.

For SWI9X30C/MDM9635 the recovered mapping is `0x0559a000..0x05dfb000 -> 0xd0000000..0xd0eb3000`, with 3,763 virtual pages.

`VNAOLTE Qualcomm RF Triage` consumes QDig's recovered Qualcomm debug-descriptor comments after reference analysis. It follows descriptor xrefs back to containing functions, adds `VNAOLTE:*` function tags, creates `VNAOLTE/RF` analysis bookmarks, and preserves source-file/line/message evidence in repeatable function comments. It does not guess function names.

Current topics include FBRx, VSWR/S11, IQ/sample capture, couplers/RFFE, XPT/DPD, WTR3925, and FTM RF-test code.

## Utility scripts

- `ListCweTree.java` — recursively verifies container/filesystem recognition.
- `ExportEm7455Dsp.java` — exports the reconstructed DSP `/image` tree for tools that expect sibling `.mdt/.bNN` files.
- `RunVnaolteQ6zip.java` — explicitly reconstructs q6zip runtime pages on an existing Hexagon program (normally automatic).
- `RunVnaolteRfTriage.java` — explicitly runs the RF analyzer on an existing project.
- `DumpVnaolteRfReport.java` — exports tagged functions as TSV.

## Build

Ghidra 12.2 currently requires Java 25 and Gradle 9.1+:

```sh
JAVA_HOME=/path/to/jdk25 \
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC \
gradle clean buildExtension
```
