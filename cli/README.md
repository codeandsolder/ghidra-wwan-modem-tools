# MediaTek MDDB command-line tools

Extract and query Catcher/META MDDB EDB files without launching Ghidra.

```sh
uv sync
uv run mtk-mddb-extract modem.EDB -o out
uv run mtk-mddb-query modem.EDB IQ_DUMP
```

See [MediaTek extension documentation](../mediatek/README.md) for format notes,
database schema, and firmware analysis workflows.
