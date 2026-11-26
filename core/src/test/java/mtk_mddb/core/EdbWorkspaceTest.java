package mtk_mddb.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.tukaani.xz.LZMA2Options;
import org.tukaani.xz.LZMAOutputStream;

class EdbWorkspaceTest {
    private static final String CURRENT = "CURRENT";
    private static final String OUTPUT = "output";

    @TempDir
    Path tempDir;

    @Test
    void opensAndExtractsSyntheticCatd() throws Exception {
        byte[] current = "MANIFEST-000001\n".getBytes(StandardCharsets.US_ASCII);
        byte[] dataI = packedFile(CURRENT, current);
        byte[] dataA = "trace metadata".getBytes(StandardCharsets.US_ASCII);
        Path input = writeArchive(dataI, dataA);
        try (EdbWorkspace workspace = EdbWorkspace.open(input)) {
            assertArrayEquals(current, Files.readAllBytes(workspace.rocksDbRoot().resolve(CURRENT)));
            assertArrayEquals(dataA, workspace.dataA());
            assertTrue(Files.isDirectory(workspace.rocksDbRoot().resolve("db")));
        }
        Path output = tempDir.resolve(OUTPUT);
        EdbArchive.Manifest manifest = EdbArchive.extract(input, output, true);
        assertArrayEquals(dataA, Files.readAllBytes(output.resolve(EdbArchive.DATAA_FILE)));
        assertArrayEquals(dataI, Files.readAllBytes(output.resolve("DATAI.bin")));
        assertArrayEquals(current, Files.readAllBytes(output.resolve("rocksdb/CURRENT")));
        assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(current)),
            manifest.rocksdbFiles().getFirst().sha256());
        assertThrows(IOException.class, () -> EdbArchive.extract(input, output, false));
    }

    @Test
    void rejectsMalformedPathsAndDuplicateMembers() throws Exception {
        Path output = tempDir.resolve(OUTPUT);
        for (String name : List.of("../escape", "/absolute", "C:/escape", "dir/../escape", "dir//file",
                "dir/./file", "dir\\file", "NUL.txt", "name.", "")) {
            Path input = writeArchive(packedFile(name, new byte[] {1}), new byte[0]);
            assertThrows(IOException.class, () -> EdbArchive.extract(input, output, false), name);
            assertFalse(Files.exists(output));
        }
        byte[] data = packedFile(CURRENT, new byte[] {1});
        byte[] duplicate = new byte[data.length * 2];
        System.arraycopy(data, 0, duplicate, 0, data.length);
        System.arraycopy(data, 0, duplicate, data.length, data.length);
        Path input = writeArchive(duplicate, new byte[0]);
        assertThrows(IOException.class, () -> EdbArchive.extract(input, output, false));
        assertFalse(Files.exists(output));
    }

    @Test
    void rejectsMalformedLengthsAndUtf8() throws Exception {
        Path output = tempDir.resolve(OUTPUT);
        byte[] bad = packedFile(CURRENT, new byte[] {1});
        bad[8] = (byte) 0xff;
        Path input = writeArchive(bad, new byte[0]);
        assertThrows(IOException.class, () -> EdbArchive.extract(input, output, false));
        ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN).putLong(Long.MAX_VALUE);
        writeArchive(bad, new byte[0]);
        assertThrows(IOException.class, () -> EdbArchive.extract(input, output, false));
        writeArchive(packedFile(CURRENT, new byte[] {1}), new byte[0]);
        byte[] archive = Files.readAllBytes(input);
        ByteBuffer.wrap(archive).order(ByteOrder.LITTLE_ENDIAN).putInt(64, 1);
        Files.write(input, archive);
        assertThrows(IOException.class, () -> EdbArchive.extract(input, output, false));
        assertFalse(Files.exists(output));
    }

    private Path writeArchive(byte[] dataI, byte[] dataA) throws Exception {
        byte[] encodedI = rawLzma(dataI);
        byte[] encodedA = rawLzma(dataA);
        int dataIOffset = 94;
        int dataAOffset = dataIOffset + encodedI.length;
        byte[] edb = new byte[dataAOffset + encodedA.length];
        System.arraycopy("CATD".getBytes(StandardCharsets.US_ASCII), 0, edb, 0, 4);
        descriptor(edb, 48, "DATAI", dataIOffset, encodedI.length, dataI.length);
        descriptor(edb, 74, "DATAA", dataAOffset, encodedA.length, dataA.length);
        System.arraycopy(encodedI, 0, edb, dataIOffset, encodedI.length);
        System.arraycopy(encodedA, 0, edb, dataAOffset, encodedA.length);
        Path input = tempDir.resolve("synthetic.EDB");
        Files.write(input, edb);
        return input;
    }

    private static byte[] packedFile(String name, byte[] payload) {
        byte[] encodedName = name.getBytes(StandardCharsets.UTF_8);
        int total = 8 + encodedName.length + 1 + payload.length;
        ByteBuffer out = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN);
        out.putLong(total);
        out.put(encodedName).put((byte) 0).put(payload);
        return out.array();
    }

    private static byte[] rawLzma(byte[] data) throws Exception {
        LZMA2Options options = new LZMA2Options();
        options.setDictSize(1 << 20);
        ByteArrayOutputStream compressed = new ByteArrayOutputStream();
        int props;
        try (LZMAOutputStream lzma = new LZMAOutputStream(compressed, options, true)) {
            props = lzma.getProps();
            lzma.write(data);
        }
        ByteBuffer out = ByteBuffer.allocate(5 + compressed.size()).order(ByteOrder.LITTLE_ENDIAN);
        out.put((byte) props).putInt(options.getDictSize()).put(compressed.toByteArray());
        return out.array();
    }

    private static void descriptor(byte[] out, int at, String name, int offset, int compressed, int uncompressed) {
        byte[] tag = (name + "\0\0\0").getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(tag, 0, out, at, tag.length);
        ByteBuffer.wrap(out, at + 8, 12).order(ByteOrder.LITTLE_ENDIAN)
            .putInt(offset).putInt(compressed).putInt(uncompressed);
    }
}
