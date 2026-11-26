package vnaolte.ghidra.cwe;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import ghidra.app.util.bin.ByteProvider;

final class SierraCweHeader {
    static final int HEADER_SIZE = 0x190;
    static final int MAGIC_OFFSET = 0x100;
    static final byte[] MAGIC = { (byte) 0xf2, 0x69, 0x7a, (byte) 0xa7 };

    final long headerOffset;
    final String type;
    final String product;
    final long payloadSize;
    final long checksum;
    final String version;
    final String date;
    final boolean compressed;

    private SierraCweHeader(long headerOffset, String type, String product, long payloadSize,
            long checksum, String version, String date, boolean compressed) {
        this.headerOffset = headerOffset;
        this.type = type;
        this.product = product;
        this.payloadSize = payloadSize;
        this.checksum = checksum;
        this.version = version;
        this.date = date;
        this.compressed = compressed;
    }

    long payloadOffset() {
        return headerOffset + HEADER_SIZE;
    }

    long totalSize() {
        return HEADER_SIZE + payloadSize;
    }

    boolean isContainer() {
        return type.equals("SPKG") || type.equals("BOOT") || type.equals("MODM") ||
            type.equals("APPL");
    }

    static boolean hasMagic(byte[] bytes) {
        if (bytes.length < MAGIC_OFFSET + MAGIC.length) {
            return false;
        }
        for (int i = 0; i < MAGIC.length; i++) {
            if (bytes[MAGIC_OFFSET + i] != MAGIC[i]) {
                return false;
            }
        }
        return true;
    }

    static SierraCweHeader read(ByteProvider provider, long offset) throws IOException {
        if (offset < 0 || offset + HEADER_SIZE > provider.length()) {
            throw new IOException("Truncated CWE header at 0x" + Long.toHexString(offset));
        }
        byte[] h = provider.readBytes(offset, HEADER_SIZE);
        if (!hasMagic(h)) {
            throw new IOException("Bad CWE magic at 0x" + Long.toHexString(offset));
        }
        String type = ascii(h, 0x10c, 4);
        String product = ascii(h, 0x110, 4);
        long payloadSize = u32be(h, 0x114);
        long checksum = u32be(h, 0x118);
        String version = asciiZ(h, 0x11c, 0x54);
        String date = asciiZ(h, 0x170, 8);
        boolean compressed = h[0x17c] != 0;
        if (payloadSize > provider.length() - offset - HEADER_SIZE) {
            throw new IOException("CWE payload extends past EOF for " + type + " at 0x" +
                Long.toHexString(offset));
        }
        return new SierraCweHeader(offset, type, product, payloadSize, checksum, version, date,
            compressed);
    }

    private static long u32be(byte[] b, int off) {
        return ((long) (b[off] & 0xff) << 24) |
            ((long) (b[off + 1] & 0xff) << 16) |
            ((long) (b[off + 2] & 0xff) << 8) |
            (long) (b[off + 3] & 0xff);
    }

    private static String ascii(byte[] b, int off, int len) {
        return new String(b, off, len, StandardCharsets.US_ASCII);
    }

    private static String asciiZ(byte[] b, int off, int len) {
        int end = off;
        int limit = Math.min(b.length, off + len);
        while (end < limit && b[end] != 0) {
            end++;
        }
        return new String(b, off, end - off, StandardCharsets.US_ASCII);
    }
}
