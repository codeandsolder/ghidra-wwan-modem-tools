package vnaolte.ghidra.qcom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.zip.Deflater;

import org.junit.jupiter.api.Test;

final class QualcommZlibDebugOverlayAnalyzerTest {
    @Test
    void acceptsCompleteRawDeflateBodyWithBadAdlerTrailer() throws Exception {
        byte[] payload = payload();
        byte[] wrapped = withZlibHeaderAndBadAdler(rawDeflate(payload));

        assertArrayEquals(payload, QualcommZlibDebugOverlayAnalyzer.inflate(wrapped));
    }

    @Test
    void rejectsTruncatedRawDeflateBody() {
        byte[] raw = rawDeflate(payload());
        byte[] truncated = Arrays.copyOf(raw, raw.length - 2);
        byte[] wrapped = withZlibHeaderAndBadAdler(truncated);

        assertThrows(IOException.class,
            () -> QualcommZlibDebugOverlayAnalyzer.inflate(wrapped));
    }

    private static byte[] payload() {
        byte[] out = new byte[8192];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) ((i * 37 + (i >>> 3)) & 0xff);
        }
        return out;
    }

    private static byte[] rawDeflate(byte[] payload) {
        Deflater deflater = new Deflater(6, true);
        try {
            deflater.setInput(payload);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            while (!deflater.finished()) {
                int n = deflater.deflate(buf);
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
        finally {
            deflater.end();
        }
    }

    private static byte[] withZlibHeaderAndBadAdler(byte[] raw) {
        byte[] out = new byte[raw.length + 6];
        out[0] = 0x78;
        out[1] = (byte) 0x9c;
        System.arraycopy(raw, 0, out, 2, raw.length);
        // Deliberately wrong RFC1950 trailer; the strict raw-body fallback
        // should accept only when the DEFLATE body itself is complete.
        out[out.length - 4] = 0x12;
        out[out.length - 3] = 0x34;
        out[out.length - 2] = 0x56;
        out[out.length - 1] = 0x78;
        return out;
    }
}
