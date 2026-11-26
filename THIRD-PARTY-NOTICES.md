# Third-party components

The project's dual license does not relicense these components.

| Component | License | Distributed in |
|---|---|---|
| [RocksDB JNI](https://github.com/facebook/rocksdb) | Apache-2.0 (chosen from GPL-2.0-only OR Apache-2.0) | MDDB extension and CLI |
| [XZ for Java](https://tukaani.org/xz/java.html) | 0BSD (version 1.10 onwards) | MDDB extension and CLI |
| [Gson](https://github.com/google/gson) | Apache-2.0 | CLI |
| [Error Prone annotations](https://github.com/google/error-prone) | Apache-2.0 | CLI (Gson dependency) |
| [Gradle wrapper](https://github.com/gradle/gradle) | Apache-2.0 | Source repository |

RocksDB copyright: Meta Platforms, Inc. and affiliates; original LevelDB code
copyright Google Inc. Gson and Error Prone copyright: Google Inc. and contributors.
See LICENSE-APACHE for the Apache-2.0 terms.

Ghidra (Apache-2.0) is a separate installation; its SDK is not redistributed
in the extension packages. JUnit and associated test libraries are build-only.

## RocksDB JNI bundled native components

The RocksDB v11.1.1 Java static build Makefile pins zlib 1.3.1, bzip2 1.0.8,
Snappy 1.2.2, LZ4 1.10.0 and Zstandard 1.5.7. Their upstream license texts
are preserved under `licenses/`, along with RocksDB's LevelDB attribution
and the XZ for Java 0BSD license.
