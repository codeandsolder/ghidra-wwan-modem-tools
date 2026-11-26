package mtk_mddb.core;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;

final class EdbWorkspace implements AutoCloseable {
    private final Path root;
    private final Path tempRoot;
    private final byte[] dataA;

    private EdbWorkspace(Path root, Path tempRoot, byte[] dataA) {
        this.root = root;
        this.tempRoot = tempRoot;
        this.dataA = dataA;
    }

    static EdbWorkspace open(Path source) throws IOException {
        if (Files.isDirectory(source)) {
            return fromExtractedDirectory(source);
        }
        Path temp = Files.createTempDirectory("mtk-mddb-ghidra-");
        boolean transferred = false;
        try {
            byte[] dataA = EdbArchive.unpack(source, temp);
            makeRocksDbCompatible(temp);
            EdbWorkspace workspace = new EdbWorkspace(temp, temp, dataA);
            transferred = true;
            return workspace;
        } finally {
            if (!transferred) {
                deleteTree(temp);
            }
        }
    }

    private static EdbWorkspace fromExtractedDirectory(Path source) throws IOException {
        Path rocks = Files.isDirectory(source.resolve("rocksdb")) ? source.resolve("rocksdb") : source;
        if (!Files.isRegularFile(rocks.resolve("CURRENT"))) {
            throw new IOException("Directory does not contain an extracted RocksDB: " + rocks);
        }
        Path temp = Files.createTempDirectory("mtk-mddb-ghidra-view-");
        boolean transferred = false;
        try {
            try (var entries = Files.list(rocks)) {
                for (Path entry : entries.toList()) {
                    if (Files.isRegularFile(entry)) {
                        Files.copy(entry, temp.resolve(entry.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                    }
                }
            }
            Path sp = rocks.resolve("sp");
            if (Files.isDirectory(sp)) {
                try (var entries = Files.list(sp)) {
                    for (Path entry : entries.toList()) {
                        if (Files.isRegularFile(entry) && entry.getFileName().toString().endsWith(".sst")) {
                            Files.copy(entry, temp.resolve(entry.getFileName()), StandardCopyOption.REPLACE_EXISTING);
                        }
                    }
                }
            }
            Files.createDirectories(temp.resolve("db"));
            Path dataAPath = Files.isDirectory(source.resolve("rocksdb"))
                ? source.resolve(EdbArchive.DATAA_FILE)
                : source.getParent() == null ? source.resolve(EdbArchive.DATAA_FILE) : source.getParent().resolve(EdbArchive.DATAA_FILE);
            byte[] dataA = Files.isRegularFile(dataAPath) ? Files.readAllBytes(dataAPath) : new byte[0];
            EdbWorkspace workspace = new EdbWorkspace(temp, temp, dataA);
            transferred = true;
            return workspace;
        } finally {
            if (!transferred) {
                deleteTree(temp);
            }
        }
    }

    Path rocksDbRoot() {
        return root;
    }

    byte[] dataA() {
        return dataA.clone();
    }

    int dataASize() {
        return dataA.length;
    }

    private static void makeRocksDbCompatible(Path root) throws IOException {
        Path sp = root.resolve("sp");
        if (Files.isDirectory(sp)) {
            try (var entries = Files.list(sp)) {
                for (Path entry : entries.toList()) {
                    if (!Files.isRegularFile(entry) || !entry.getFileName().toString().endsWith(".sst")) {
                        continue;
                    }
                    Path flat = root.resolve(entry.getFileName());
                    if (!Files.exists(flat)) {
                        try {
                            Files.createLink(flat, entry);
                        } catch (IOException e) {
                            Files.copy(entry, flat, StandardCopyOption.REPLACE_EXISTING);
                        }
                    }
                }
            }
        }
        Files.createDirectories(root.resolve("db"));
    }

    static void deleteTree(Path root) throws IOException {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var stream = Files.walk(root)) {
            for (Path path : stream.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    @Override
    public void close() throws IOException {
        deleteTree(tempRoot);
    }
}
