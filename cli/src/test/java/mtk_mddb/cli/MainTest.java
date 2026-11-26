package mtk_mddb.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.rocksdb.Options;
import org.rocksdb.RocksDB;

class MainTest {
    private static final String QUERY = "query";
    private static final String NEEDLE = "needle";

    @TempDir
    Path tempDir;

    @Test
    void queriesRealRocksDatabaseAndRejectsInvalidOptions() throws Exception {
        RocksDB.loadLibrary();
        Path path = tempDir.resolve("db");
        try (Options options = new Options().setCreateIfMissing(true);
                RocksDB db = RocksDB.open(options, path.toString())) {
            db.put("key".getBytes(StandardCharsets.UTF_8), NEEDLE.getBytes(StandardCharsets.UTF_8));
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try (PrintStream stream = new PrintStream(output, true, StandardCharsets.UTF_8)) {
            assertEquals(0, Main.run(new String[] {QUERY, path.toString(), NEEDLE, "--limit", "1"},
                stream, stream));
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("field=value key=6b6579 offset=0x0 len=6"));
            assertEquals(2, Main.run(new String[] {QUERY, path.toString(), NEEDLE, "--limit"}, stream, stream));
            assertEquals(2, Main.run(new String[] {QUERY, path.toString(), NEEDLE, "--context", "-1"}, stream, stream));
            assertEquals(2, Main.run(new String[] {QUERY, path.toString(), NEEDLE, "--cf", "missing"}, stream, stream));
        }
    }
}
