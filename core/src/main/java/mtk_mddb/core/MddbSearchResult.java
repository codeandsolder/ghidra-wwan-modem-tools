package mtk_mddb.core;

public record MddbSearchResult(String columnFamily, String field, byte[] key, int offset, byte[] value) {
    public MddbSearchResult {
        key = key.clone();
        value = value.clone();
    }

    @Override
    public byte[] key() { return key.clone(); }

    @Override
    public byte[] value() { return value.clone(); }

    public String keyHex() {
        return java.util.HexFormat.of().formatHex(key);
    }
}
