# Ghidra WWAN modem tools

First-party Ghidra extensions for cellular modem firmware reverse engineering,
developed for VNAOLTE. Independently installable modules:

- [Qualcomm and modem firmware](qualcomm/README.md): Sierra CWE, wide YAFFS2,
  legacy Android boot, QCDT, q6zip, debug overlays, CLADE mapping and RF analysis.
- [MediaTek MDDB](mediatek/README.md): Catcher/META database inspection,
  schema/type recovery, program annotation and cross-build comparison.
- [Standalone MDDB CLI](cli/README.md): extraction and query without Ghidra.

The PC firmware utilities remain in the separate upstream-tracking
[ghidra-firmware-utils](https://github.com/codeandsolder/ghidra-firmware-utils) fork.

## Build and verify

Ghidra 12.2, Java 25 and the shared Gradle 9.1.0 wrapper:

```sh
./gradlew --no-daemon -PghidraInstallDir=/path/to/ghidra packageExtensions
```

Qualcomm ZIPs are in `qualcomm/dist/`, MediaTek ZIPs in `mediatek/dist/`.
Use `-ProcksdbPlatform=linux64`, `win64` or `osx` to select the MDDB native
runtime (default is the build host). Qualcomm does not bundle RocksDB.
Install either or both through Ghidra's extension manager.

The Ghidra-independent `core/` library and CLI build without the SDK:

```sh
./gradlew --no-daemon check :cli:distZip
```

The CLI and MediaTek extension use the same decoding and database implementation.

Both extension histories are preserved, including the original
[mtk-mddb-tools](https://github.com/codeandsolder/mtk-mddb-tools) project.

## License

First-party code: [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE),
at your option. See [third-party notices](THIRD-PARTY-NOTICES.md) and
[release history](CHANGELOG.md).

## Dependency updates

Gradle dependency lockfiles and SHA-256 verification metadata are committed.
Renovate manages updates using the shared fleet preset. To refresh them after
an intentional dependency change, run:

```sh
./gradlew --write-locks --write-verification-metadata sha256 :core:dependencies :cli:dependencies
```

Review the changed checksums against Maven Central and run the release dry run:

```sh
ci/package-release.sh /path/to/ghidra /path/to/empty/output
```
