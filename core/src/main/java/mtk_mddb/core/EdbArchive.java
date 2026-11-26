package mtk_mddb.core;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.tukaani.xz.LZMAInputStream;

/** The CATD container and its DATAI archive, independent of Ghidra and RocksDB. */
public final class EdbArchive {
    private static final String DATAI = "DATAI";
    private static final String DATAA = "DATAA";
    public static final String DATAA_FILE = "DATAA.bin";
    private static final int MAX_SECTION_BYTES = 512 * 1024 * 1024;
    private static final int MAX_DICTIONARY_BYTES = 128 * 1024 * 1024;
    private static final int MAX_FILENAME_BYTES = 4096;

    public record Section(String name, int offset, int compressedSize, int uncompressedSize) {}
    public record SectionManifest(String name, int offset, int compressedSize,
            int uncompressedSize, String sha256) {}
    public record FileManifest(String name, int size, String sha256) {}
    public record Manifest(String input, int inputSize, String inputSha256,
            List<SectionManifest> sections, List<FileManifest> rocksdbFiles,
            int dataaSize, String dataaSha256) {}

    private record PackedFile(String name, int offset, int size) {}
    private record Decoded(byte[] dataI, byte[] dataA, List<PackedFile> files,
            List<SectionManifest> sections) {}

    private EdbArchive() {}

    /** Extract a faithful archive into a new directory (never overwrite existing files). */
    public static Manifest extract(Path input, Path output, boolean keepDataI) throws IOException {
        byte[] blob = Files.readAllBytes(input);
        Decoded decoded = decode(blob);
        Path target = output.toAbsolutePath().normalize();
        Path parent = target.getParent();
        if (parent == null || Files.exists(target, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Extraction requires a new output directory: " + output);
        }
        Files.createDirectories(parent);
        Path staged = Files.createTempDirectory(parent, ".mddb-extract-");
        boolean transferred = false;
        try {
            Path rocks = Files.createDirectory(staged.resolve("rocksdb"));
            List<FileManifest> files = writeFiles(decoded, rocks, true);
            Files.write(staged.resolve(DATAA_FILE), decoded.dataA());
            if (keepDataI) {
                Files.write(staged.resolve("DATAI.bin"), decoded.dataI());
            }
            Manifest manifest = new Manifest(input.toString(), blob.length, sha256(blob),
                decoded.sections(), files, decoded.dataA().length, sha256(decoded.dataA()));
            Files.move(staged, target);
            transferred = true;
            return manifest;
        } finally {
            if (!transferred) {
                EdbWorkspace.deleteTree(staged);
            }
        }
    }

    /** Extract just the database into a private workspace and return the DATAA bytes. */
    static byte[] unpack(Path input, Path root) throws IOException {
        Decoded decoded = decode(Files.readAllBytes(input));
        writeFiles(decoded, root, false);
        return decoded.dataA();
    }

    private static Decoded decode(byte[] blob) throws IOException {
        byte[] dataI = null;
        byte[] dataA = null;
        List<SectionManifest> sections = new ArrayList<>();
        for (Section section : parseSections(blob)) {
            byte[] decoded = decompress(blob, section);
            sections.add(new SectionManifest(section.name(), section.offset(), section.compressedSize(),
                section.uncompressedSize(), sha256(decoded)));
            if (DATAI.equals(section.name())) {
                dataI = decoded;
            } else {
                dataA = decoded;
            }
        }
        if (dataI == null || dataA == null) {
            throw new IOException("CATD database is missing DATAI or DATAA");
        }
        return new Decoded(dataI, dataA, parseDataI(dataI), List.copyOf(sections));
    }

    static List<Section> parseSections(byte[] blob) throws IOException {
        byte[] magic = "CATD".getBytes(StandardCharsets.US_ASCII);
        if (blob.length < magic.length || !Arrays.equals(blob, 0, magic.length, magic, 0, magic.length)) {
            throw new IOException("Not a MediaTek CATD EDB file");
        }
        List<Section> sections = new ArrayList<>();
        int headerEnd = magic.length;
        for (String name : List.of(DATAI, DATAA)) {
            byte[] tag = (name + "\0\0\0").getBytes(StandardCharsets.US_ASCII);
            int at = indexOf(blob, tag, magic.length, Math.min(blob.length, MAX_FILENAME_BYTES));
            if (at < 0 || at > blob.length - 20) {
                throw new IOException("Missing " + name + " descriptor");
            }
            headerEnd = Math.max(headerEnd, at + 20);
            long offset = Integer.toUnsignedLong(u32(blob, at + 8));
            long compressed = Integer.toUnsignedLong(u32(blob, at + 12));
            long uncompressed = Integer.toUnsignedLong(u32(blob, at + 16));
            if (compressed <= 5 || offset + compressed > blob.length || uncompressed > MAX_SECTION_BYTES) {
                throw new IOException("Invalid " + name + " bounds or decoded size exceeds limit");
            }
            sections.add(new Section(name, Math.toIntExact(offset), Math.toIntExact(compressed),
                Math.toIntExact(uncompressed)));
        }
        List<Section> ordered = sections.stream().sorted(Comparator.comparingInt(Section::offset)).toList();
        if (ordered.get(0).offset() < headerEnd ||
                (long) ordered.get(0).offset() + ordered.get(0).compressedSize() > ordered.get(1).offset()) {
            throw new IOException("Overlapping CATD header or sections");
        }
        return List.copyOf(sections);
    }

    private static byte[] decompress(byte[] blob, Section section) throws IOException {
        int at = section.offset();
        int prop = Byte.toUnsignedInt(blob[at]);
        long dictionary = Integer.toUnsignedLong(u32(blob, at + 1));
        if (prop >= 9 * 5 * 5 || dictionary > MAX_DICTIONARY_BYTES) {
            throw new IOException(section.name() + ": invalid or excessive LZMA parameters");
        }
        try (ByteArrayInputStream raw = new ByteArrayInputStream(blob, at + 5, section.compressedSize() - 5);
                LZMAInputStream lzma = new LZMAInputStream(raw, -1, (byte) prop, (int) dictionary)) {
            lzma.enableRelaxedEndCondition();
            byte[] decoded = lzma.readNBytes(section.uncompressedSize());
            if (decoded.length != section.uncompressedSize() || lzma.read() != -1) {
                throw new IOException(section.name() + ": decoded length disagrees with descriptor");
            }
            return decoded;
        }
    }

    private static List<PackedFile> parseDataI(byte[] data) throws IOException {
        List<PackedFile> files = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int pos = 0;
        while (pos < data.length) {
            if (data.length - pos < Long.BYTES) {
                throw new IOException("Truncated DATAI record header");
            }
            long span = ByteBuffer.wrap(data, pos, Long.BYTES).order(ByteOrder.LITTLE_ENDIAN).getLong();
            if (span < 9 || span > data.length - (long) pos) {
                throw new IOException("Invalid DATAI record span");
            }
            int end = pos + (int) span;
            int nameStart = pos + Long.BYTES;
            int nameEnd = nameStart;
            int nameLimit = (int) Math.min(end, (long) nameStart + MAX_FILENAME_BYTES);
            while (nameEnd < nameLimit && data[nameEnd] != 0) {
                nameEnd++;
            }
            if (nameEnd == nameLimit) {
                throw new IOException("Unterminated DATAI filename");
            }
            String name = StandardCharsets.UTF_8.newDecoder()
                .decode(ByteBuffer.wrap(data, nameStart, nameEnd - nameStart)).toString();
            validateName(name);
            if (!seen.add(name.toLowerCase(Locale.ROOT))) {
                throw new IOException("Duplicate DATAI filename: " + name);
            }
            files.add(new PackedFile(name, nameEnd + 1, end - nameEnd - 1));
            pos = end;
        }
        return List.copyOf(files);
    }

    private static void validateName(String name) throws IOException {
        // Validate a portable relative archive path before interpreting it on any host.
        for (String component : name.split("/", -1)) {
            if (component.isBlank() || ".".equals(component) || "..".equals(component) ||
                    component.endsWith(".") || component.endsWith(" ") ||
                    component.matches(".*[\\\\:<>|?*\"]+.*") ||
                    component.chars().anyMatch(ch -> ch < 32) ||
                    component.matches("(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\\..*)?")) {
                throw new IOException("Unsafe DATAI filename: " + name);
            }
        }
    }

    private static List<FileManifest> writeFiles(Decoded decoded, Path root, boolean hash) throws IOException {
        List<FileManifest> files = new ArrayList<>();
        for (PackedFile file : decoded.files()) {
            Path out = root.resolve(file.name());
            Files.createDirectories(out.getParent());
            try (var stream = Files.newOutputStream(out, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
                stream.write(decoded.dataI(), file.offset(), file.size());
            }
            if (hash) {
                MessageDigest digest = digest();
                digest.update(decoded.dataI(), file.offset(), file.size());
                files.add(new FileManifest(file.name(), file.size(), HexFormat.of().formatHex(digest.digest())));
            }
        }
        return List.copyOf(files);
    }

    private static int u32(byte[] data, int offset) {
        return ByteBuffer.wrap(data, offset, Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).getInt();
    }

    private static int indexOf(byte[] haystack, byte[] needle, int start, int end) {
        for (int i = start; i <= end - needle.length; i++) {
            if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
                return i;
            }
        }
        return -1;
    }

    private static MessageDigest digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Java must provide SHA-256", e);
        }
    }

    private static String sha256(byte[] bytes) {
        return HexFormat.of().formatHex(digest().digest(bytes));
    }
}
