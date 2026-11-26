# MediaTek MDDB command-line tools

Extract and query Catcher/META MDDB EDB files with Java 25, without Ghidra.
The CLI and MediaTek Ghidra extension use the same CATD/DATAI decoder,
RocksDB reader, and schema library in `core/`.

From the repository root:

```sh
./gradlew --no-daemon check :cli:installDist
cli/build/install/mtk-mddb-cli-linux64/bin/mtk-mddb extract modem.EDB -o out
cli/build/install/mtk-mddb-cli-linux64/bin/mtk-mddb query modem.EDB IQ_DUMP
```

Use `--keep-datai` to retain the original decompressed DATAI section.
Extraction produces a new directory containing the original files in
`rocksdb/`, DATAA.bin, and a SHA-256 JSON manifest. Existing directories are
not overwritten. The reader bounds each decompressed section at 512 MiB
and the LZMA dictionary at 128 MiB.

Build distributable ZIPs with `./gradlew :cli:distZip`. The directory and
ZIP names include the selected platform (linux64, win64, osx); Windows uses
the generated .bat launcher. Use `-ProcksdbPlatform=<platform>` for cross-packaging.
The ZIP contains all runtime libraries; Java 25 is required.

See [MediaTek extension documentation](../mediatek/README.md) for format notes,
database schema, and firmware analysis workflows.
