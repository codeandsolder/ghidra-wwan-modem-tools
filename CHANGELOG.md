# Changelog

## 0.3.0

First consolidated release for Ghidra 12.2 and Java 25.

- Qualcomm/Sierra and MediaTek tools are maintained together but remain separately installable.
- The MDDB extension and standalone Java CLI share one decoding and RocksDB query core; the previous Python CLI is retired.
- Archive validation, bounded compressed payload reads, streaming YAFFS extraction, and database session lifetime handling are improved.
- Platform-specific MDDB distributions avoid shipping unused native libraries.
- First-party code is available under MIT OR Apache-2.0.

See the archived [MediaTek releases](https://github.com/codeandsolder/mtk-mddb-tools/releases)
for previous standalone versions.
