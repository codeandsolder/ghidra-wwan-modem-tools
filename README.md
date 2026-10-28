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

`VNAOLTE Qualcomm q6zip Decompressor` runs before disassembly. It recognizes DLPager q6zip RX segments structurally, infers dictionary sizes from the self-consistent absolute pointer table, scores dictionary order and lookback width by page decode quality, and maps reconstructed executable pages at modem-declared runtime addresses. DLPager descriptors are matched by invariants rather than one fixed struct layout: the packed start must name the candidate segment, any excluded tail must fit within one page, and a nearby unmapped runtime range must exactly match the decoded page count. If sampled dictionary layouts are nearly tied, the plausible candidates are rescored across the complete image before choosing. No modem addresses or known compression parameters are hard-coded.

The regression corpus currently covers Sierra EM7455/MDM9x35, Quectel EG25-G/MDM9607, Telit LN920, and negative q6zip cases on newer Quectel/Telit images. For SWI9X30C/MDM9635 the recovered mapping is `0x0559a000..0x05dfb000 -> 0xd0000000..0xd0eb3000`, with 3,763 virtual pages. The exact EM7455 image decodes 3,762 full 4096-byte pages plus one terminal 4092-byte page, which is padded to the modem-declared runtime extent.

`VNAOLTE Qualcomm zlib Debug Overlay` recognizes several structurally validated Qualcomm debug payloads. Older images use 16-byte source/line/format records validated by resolving both pointers; SDX55-class images can instead carry a dense NUL-terminated diagnostic string pool. A third observed form has a valid, complete raw DEFLATE body inside an RFC1950-looking wrapper with a stale/nonstandard Adler-32 trailer; that fallback is accepted only when raw DEFLATE reaches its final block and consumes the body exactly. Damaged/truncated bodies still fail closed. RF-interest strings/records are bookmarked.

`VNAOLTE Qualcomm CLADE Mapping` does not attempt proprietary CLADE decompression. When firmware contains a self-consistent compressed/runtime tuple, it annotates the full mapping. When a generation only self-identifies a high-entropy block next to literal `.clade.comp` metadata, it annotates that packed region and explicitly leaves the runtime mapping unresolved. CLADE support strings alone are not enough to guess a block.

The exact cross-vendor expectations and fixture hashes are recorded in [`docs/PACKED_REGRESSION_MATRIX.md`](docs/PACKED_REGRESSION_MATRIX.md).

`VNAOLTE Qualcomm RF Triage` consumes QDig's recovered Qualcomm debug-descriptor comments after reference analysis. It follows descriptor xrefs back to containing functions, adds `VNAOLTE:*` function tags, creates `VNAOLTE/RF` analysis bookmarks, and preserves source-file/line/message evidence in repeatable function comments. It does not guess function names.

Current topics include FBRx, VSWR/S11, IQ/sample capture, couplers/RFFE, XPT/DPD, WTR3925, and FTM RF-test code.

## Utility scripts

- `ListCweTree.java` — recursively verifies container/filesystem recognition.
- `ExportEm7455Dsp.java` — exports the reconstructed DSP `/image` tree for tools that expect sibling `.mdt/.bNN` files.
- `RunVnaolteQ6zip.java` — explicitly reconstructs q6zip runtime pages on an existing Hexagon program (normally automatic).
- `RunVnaolteRfTriage.java` — explicitly runs the RF analyzer on an existing project.
- `ProbeQualcommPacked.java` — generic no-analysis probe for q6zip, zlib/debug, and CLADE decisions on an arbitrary split Qualcomm modem image.
- `VerifyEm7455Packed.java` — no-analysis regression smoke for the known SWI9X30C EM7455 image; asserts q6zip runtime mapping, zlib overlay size, and recovered debug-bookmark count.
- `DumpVnaolteRfReport.java` — exports tagged functions as TSV.

## Build

Ghidra 12.2 requires Java 25. The checked-in Gradle wrapper pins Gradle 9.1.0 and its distribution checksum:

```sh
JAVA_HOME=/path/to/jdk25 \
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.2_PUBLIC \
./gradlew clean test buildExtension
```

## Exact EM7455 packed-segment smoke

After installing the extension and QDig loader, the known `SWI9X30C_02.38.00.00` DSP image can be verified without running the expensive normal analysis:

```sh
analyzeHeadless /tmp/ghidra-vnaolte packed-smoke \
  -import /path/to/modem.mdt \
  -noanalysis -postScript VerifyEm7455Packed.java
```

The verification must end with `EM7455_PACKED_VERIFY=PASS`.

## Continuous integration

`.github/workflows/ci.yml` builds on the repo-scoped Acer self-hosted Linux runner using JDK 25, the checked-in Gradle 9.1.0 wrapper, and the checksum-pinned official Ghidra 12.2 release. CI runs the focused unit tests, builds the extension, verifies the packaged JAR/scripts/docs, and uploads the extension ZIP for seven days.

The five-firmware packed-format matrix also runs in CI against a hash-pinned fixture corpus kept locally on the Acer runner; modem firmware is never uploaded to GitHub. Each run uses a throwaway Ghidra user configuration so CI cannot modify the interactive Ghidra setup. Fixture hashes and expected outcomes are documented in `docs/PACKED_REGRESSION_MATRIX.md`.
