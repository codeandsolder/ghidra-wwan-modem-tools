# Rust migration scope

This repository currently contains two different kinds of Java:

- roughly 3.3 kLOC of Ghidra extension code under `src/`, including filesystem/analyzer entry points;
- roughly 1.8 kLOC of headless archaeology/report scripts under `ghidra_scripts/`.

Those have very different Rust migration costs. The useful goal is **maximum Rust ownership of the reverse-engineering logic while continuing to use Ghidra where it is already the mature engine**. Replacing Ghidra's project database, analyzers, decompiler and UI solely to eliminate the remaining Java would be a separate reverse-engineering-platform project.

## Current Rust ecosystem

### `ghidra` crate (`ooojustin/ghidra-rs`)

The `ghidra` crate (0.1.0 as of 2026-10) is the closest fit for a Rust-first headless VNAOLTE tool. It embeds a Ghidra JVM and exposes typed Rust handles for projects/programs, import and analysis, functions, instructions, references, CFG/call graph, high P-code/data-flow graphs, decompilation, types and transactions.

- docs: <https://docs.rs/ghidra/latest/ghidra/>
- license: Apache-2.0
- current prerequisite: Ghidra 12.0+, a JDK, and `GHIDRA_INSTALL_DIR` when compiling the JNI bridge.

This is the preferred starting point for replacing our Java utility scripts and headless orchestration without giving up Ghidra ProgramDB or the decompiler.

### `libghidra` (`0xeb/libghidra`)

`libghidra` exposes a broad live Ghidra API to Rust/Python/C++ through a Java host extension and typed RPC client. Its remote backend includes project/program lifecycle, enumeration, decompilation, xrefs, types, comments/bookmarks and mutation. It also has a local backend using the native Sleigh/decompiler engine.

- project: <https://github.com/0xeb/libghidra>
- current release observed: 0.0.9 alpha

It is technically attractive for automation, but current releases use the Human-Origin Source License. Unmodified dependency use is permitted subject to its terms, but divergent derivative/competing implementations have additional restrictions. Do not use it as source material for an independent replacement without reviewing that license. Releases through 0.0.3 were MPL-2.0.

### Native/pure-Rust lower layers

These are useful if we later want a Ghidra-independent backend, but they do not replace ProgramDB/auto-analysis today:

- ReOxide: <https://reoxide.eu/> — drives and extends Ghidra's native decompiler from Rust; useful for custom decompiler passes.
- `wazabin/sleigh`: <https://github.com/wazabin/sleigh> — pure-Rust SLEIGH compiler/decoder/p-code lifting.
- `toolCHAINZ/jingle`: <https://github.com/toolCHAINZ/jingle> — Rust FFI to SLEIGH plus p-code/SMT analysis; research-grade.
- `radareorg/ghidra-native`: <https://github.com/radareorg/ghidra-native> — maintained extraction of Ghidra's native SLEIGH compiler/decompiler and processor specs.
- Fission: <https://github.com/fission-systems/Fission> — ambitious Rust-native loader/lifter/IR/decompiler/emulator workspace; useful prior art, but not currently a drop-in substitute for Ghidra analysis quality or project semantics.

## Recommended end state

### Rust owns

1. **Firmware/container algorithms** — q6zip decode and structural candidate scoring; zlib/raw-DEFLATE validation; CWE, YAFFS, legacy boot and QCDT parsing; BE8 helpers and GCT command-table decoding.
2. **Firmware archaeology** — raw/defined string scanning; scalar/address-use searches including ARM MOVW/MOVT reconstruction; RF topic scoring/report models; GCT PAM/RFFE/NV decoders and constructor emulation where practical.
3. **Headless orchestration** — project import/open/analyze/decompile through the Rust `ghidra` crate; deterministic Markdown/JSON reports; corpus regression runner and CLI.

### Java remains thin

Ghidra extension points are Java APIs. For the GUI extension, keep only adapters that need to implement things such as `GFileSystem` / filesystem factories, `AbstractAnalyzer` entry points, and ProgramDB mutations invoked inside the GUI.

The algorithmic work behind those adapters should become Rust or a format-neutral core. Do not add JNI merely to remove 50 lines of Java: native-library packaging, platform ABI support and Ghidra extension deployment would cost more complexity than it removes. A JNI bridge is justified only when a shared Rust algorithm is expensive enough that maintaining two implementations is worse.

## Migration size

| Slice | Current surface | Rust difficulty | Notes |
|---|---:|---|---|
| Headless archaeology scripts | ~1.8 kLOC Java | low-medium | Best first target; maps naturally onto embedded-Ghidra Rust APIs. |
| q6zip decoder + tests | ~0.8 kLOC Java | low-medium | Mostly algorithmic; excellent pure-Rust candidate. |
| CWE/QCDT/boot/YAFFS parsers | ~1.1 kLOC Java | medium | Parsing is easy; Ghidra filesystem presentation remains a thin Java adapter. |
| Qualcomm zlib/CLADE analyzers | ~0.9 kLOC Java | medium | Split recognition/decoding from ProgramDB annotation. |
| RF analyzer wrapper | ~0.2 kLOC Java | low | Rust can generate facts; Java can apply tags/bookmarks in GUI mode. |
| Entire Ghidra replacement | external-framework scale | very high | Requires function discovery, xrefs, types, decompiler, project DB, persistence, UI, etc.; not justified by this repo alone. |

A useful maximum-Rust port is therefore on the order of **a few thousand lines of Rust plus a small Java compatibility shell**, not a rewrite of Ghidra. The hard part is API-boundary design and regression parity, not code volume.

## Migration sequence

1. Add a Cargo workspace without changing current Java behavior. Make a pure `firmware-core` crate with byte/address abstractions and golden fixtures.
2. Port q6zip first and compare every known packed-page result byte-for-byte against the existing Java corpus.
3. Build a Rust `ghidra-wwan` CLI on the `ghidra` crate. Port `DecompileFunctions`, `FindAddressUses`, `FindScalarUses`, `DisassembleRanges` and report generation.
4. Port the GCT command/RF survey into typed Rust models; emit JSON plus Markdown so RF-specific logic no longer lives inside Ghidra scripts.
5. Port container/filesystem parsers into the pure core. Keep Java GFileSystem adapters as consumers of the same format model where practical.
6. Port Qualcomm zlib/CLADE recognition and annotation logic. Retain Java `AbstractAnalyzer` wrappers only for GUI auto-analysis.
7. Re-evaluate whether JNI/native packaging buys anything. If the remaining Java is merely glue, stop. If a large algorithm is still duplicated, add a narrow stable C ABI/JNI bridge for that algorithm only.
8. Treat a no-JVM backend as optional research: ReOxide/ghidra-native/wazabin-sleigh/Fission are candidates for experimentation, not prerequisites for the useful Rust migration.

## Non-goals

- Do not reimplement Ghidra's decompiler just to remove Java.
- Do not make libghidra's restricted-license implementation the design oracle for an independent clone.
- Do not regress the current Ghidra extension or firmware corpus while the Rust path is incomplete.
- Keep exact binary-output/corpus parity as the migration gate; aesthetic parity is not enough.
