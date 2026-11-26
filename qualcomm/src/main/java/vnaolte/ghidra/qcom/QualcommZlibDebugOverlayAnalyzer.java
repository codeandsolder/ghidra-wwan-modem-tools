package vnaolte.ghidra.qcom;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Restores Qualcomm zlib-compressed debug/ro-fatal metadata as an overlay.
 *
 * <p>Older MDM9x35 images contain a read-only zlib segment whose decompressed
 * stream begins with 16-byte records. In the observed SWI9X30C image the words are:
 *
 * <pre>
 *   u32 packed_source_metadata;  // low 16 bits are source line
 *   u32 metadata;
 *   u32 format_pointer;          // VA in the decompressed overlay
 *   u32 source_file_pointer;     // VA in ordinary modem image
 * </pre>
 *
 * <p>The exact semantics of the upper source bits and second word are left
 * deliberately unnamed. We only annotate facts validated by pointer targets:
 * source file, low-16 source line, and printable format string.
 *
 * <p>Newer images can use the same ELF-side zlib container for a dense
 * NUL-terminated diagnostic string pool without those old records. That form is
 * accepted only when the inflated payload is overwhelmingly textual and has a
 * large population of modem-diagnostic strings; RF-interest strings are then
 * bookmarked directly. The detector therefore generalizes by structure rather
 * than by chipset, address, or firmware version.
 */
public final class QualcommZlibDebugOverlayAnalyzer extends AbstractAnalyzer {
    private static final int MAX_PACKED = 4 * 1024 * 1024;
    private static final int MAX_UNPACKED = 64 * 1024 * 1024;
    private static final int MIN_VALID_RECORDS = 128;
    private static final int MIN_STRING_COUNT = 256;
    private static final int MIN_STRING_BYTES = 64 * 1024;
    private static final int MIN_DIAGNOSTIC_STRINGS = 64;
    private static final String BLOCK_PREFIX = "qcom_zlib_debug_";

    private static final String[] RF_NEEDLES = {
        "fbrx", "vswr", "s11", "return loss", "return_loss", "coupler",
        "iq capture", "iq_capture", "sample capture", "sample_capture",
        "wtr3925", "ftm_", "rflte_", "rffe", "xpt", "spectral flatness"
    };

    private record Record(int offset, int line, long formatPointer,
            long sourcePointer, String source, String format) {}

    private record StringEntry(int offset, String text) {}

    private record StringPool(List<StringEntry> strings, int printableBytes,
            int diagnosticStrings) {}

    public QualcommZlibDebugOverlayAnalyzer() {
        super("VNAOLTE Qualcomm zlib Debug Overlay",
            "Decompresses Qualcomm ro-fatal/debug zlib segments into overlays; annotates validated old source records or dense modern diagnostic string pools.",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        Processor p = program.getLanguage().getProcessor();
        return p != null && "Hexagon".equalsIgnoreCase(p.toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        Memory memory = program.getMemory();
        MemoryBlock[] snapshot = memory.getBlocks().clone();
        int mounted = 0;

        for (MemoryBlock packed : snapshot) {
            monitor.checkCancelled();
            if (!candidate(packed)) {
                continue;
            }

            byte[] compressed;
            try {
                compressed = new byte[(int) packed.getSize()];
                if (packed.getBytes(packed.getStart(), compressed) != compressed.length) {
                    continue;
                }
            }
            catch (MemoryAccessException | RuntimeException e) {
                continue;
            }

            byte[] decoded;
            try {
                decoded = inflate(compressed);
            }
            catch (IOException e) {
                continue;
            }
            if (decoded.length <= compressed.length || decoded.length > MAX_UNPACKED) {
                continue;
            }

            long base = packed.getStart().getOffset();
            List<Record> records = findRecords(program, decoded, base, monitor);
            StringPool pool = null;
            boolean recordLayout = records.size() >= MIN_VALID_RECORDS;
            if (!recordLayout) {
                pool = findStringPool(decoded, monitor);
                int requiredBytes = Math.max(MIN_STRING_BYTES, decoded.length / 3);
                if (pool.strings().size() < MIN_STRING_COUNT ||
                        pool.printableBytes() < requiredBytes ||
                        pool.diagnosticStrings() < MIN_DIAGNOSTIC_STRINGS) {
                    continue;
                }
            }

            String name = BLOCK_PREFIX + String.format(Locale.ROOT, "%08x", base);
            if (memory.getBlock(name) != null) {
                continue;
            }

            try {
                MemoryBlock overlay = memory.createInitializedBlock(name, packed.getStart(),
                    new ByteArrayInputStream(decoded), decoded.length, monitor, true);
                overlay.setPermissions(true, false, false);
                overlay.setArtificial(true);
                overlay.setSourceName("zlib:" + packed.getName());

                int rf;
                if (recordLayout) {
                    overlay.setComment(String.format(Locale.ROOT,
                        "VNAOLTE decompressed Qualcomm debug/ro-fatal overlay from %s; packed=0x%x decoded=0x%x; %d validated 16-byte source/format records",
                        packed.getName(), compressed.length, decoded.length, records.size()));
                    rf = annotate(program, overlay, records, monitor);
                    log.appendMsg(getName(), String.format(Locale.ROOT,
                        "%s -> %s, 0x%x -> 0x%x bytes; %d debug records (%d RF-interest)",
                        packed.getName(), overlay.getName(), compressed.length, decoded.length,
                        records.size(), rf));
                }
                else {
                    overlay.setComment(String.format(Locale.ROOT,
                        "VNAOLTE decompressed Qualcomm diagnostic string-pool overlay from %s; packed=0x%x decoded=0x%x; %d NUL-terminated printable strings, %d diagnostic strings",
                        packed.getName(), compressed.length, decoded.length, pool.strings().size(),
                        pool.diagnosticStrings()));
                    rf = annotateStringPool(program, overlay, pool, monitor);
                    log.appendMsg(getName(), String.format(Locale.ROOT,
                        "%s -> %s, 0x%x -> 0x%x bytes; dense diagnostic string pool: %d strings, %d diagnostic (%d RF-interest)",
                        packed.getName(), overlay.getName(), compressed.length, decoded.length,
                        pool.strings().size(), pool.diagnosticStrings(), rf));
                }
                mounted++;
            }
            catch (CancelledException e) {
                throw e;
            }
            catch (Exception e) {
                log.appendException(e);
            }
        }

        if (mounted == 0) {
            log.appendMsg(getName(), "no new Qualcomm zlib debug overlay mounted");
        }
        return true;
    }

    private static boolean candidate(MemoryBlock block) {
        if (!block.isInitialized() || block.getSize() < 0x10000 ||
                block.getSize() > MAX_PACKED) {
            return false;
        }
        try {
            byte[] h = new byte[2];
            if (block.getBytes(block.getStart(), h) != 2) {
                return false;
            }
            // Common zlib CMF/FLG validation, rather than hard-coding 78 9c.
            int cmf = h[0] & 0xff;
            int flg = h[1] & 0xff;
            int cinfo = cmf >>> 4;
            return (cmf & 0x0f) == 8 && cinfo <= 7 &&
                ((cmf << 8) + flg) % 31 == 0;
        }
        catch (MemoryAccessException e) {
            return false;
        }
    }

    static byte[] inflate(byte[] input) throws IOException {
        try {
            return inflateChecked(input);
        }
        catch (IOException checkedFailure) {
            // Some shipping Qualcomm images contain a standards-compliant raw
            // DEFLATE body inside an RFC1950-looking container but carry a
            // nonstandard/stale Adler-32 trailer. Accept that form only if the
            // raw body itself reaches the DEFLATE end marker and consumes the
            // entire body exactly. A damaged/truncated body still fails.
            if (input.length < 6 || (input[1] & 0x20) != 0) {
                throw checkedFailure;
            }
            try {
                return inflateRawBody(input);
            }
            catch (IOException rawFailure) {
                rawFailure.addSuppressed(checkedFailure);
                throw rawFailure;
            }
        }
    }

    private static byte[] inflateChecked(byte[] input) throws IOException {
        try (InflaterInputStream in = new InflaterInputStream(new ByteArrayInputStream(input));
                ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[32 * 1024];
            int n;
            while ((n = in.read(buf)) >= 0) {
                if ((long) out.size() + n > MAX_UNPACKED) {
                    throw new IOException("zlib output exceeds safety cap");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static byte[] inflateRawBody(byte[] input) throws IOException {
        Inflater inflater = new Inflater(true);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            inflater.setInput(input, 2, input.length - 6);
            byte[] buf = new byte[32 * 1024];
            while (!inflater.finished()) {
                int n;
                try {
                    n = inflater.inflate(buf);
                }
                catch (DataFormatException e) {
                    throw new IOException("raw DEFLATE body is invalid", e);
                }
                if (n > 0) {
                    if ((long) out.size() + n > MAX_UNPACKED) {
                        throw new IOException("raw DEFLATE output exceeds safety cap");
                    }
                    out.write(buf, 0, n);
                    continue;
                }
                if (inflater.needsDictionary()) {
                    throw new IOException("raw DEFLATE body unexpectedly needs a dictionary");
                }
                if (inflater.needsInput()) {
                    throw new IOException("raw DEFLATE body ended before the final block");
                }
                throw new IOException("raw DEFLATE decoder made no progress");
            }
            if (inflater.getRemaining() != 0) {
                throw new IOException("raw DEFLATE body has trailing bytes before Adler-32");
            }
            return out.toByteArray();
        }
        finally {
            inflater.end();
        }
    }

    private static List<Record> findRecords(Program program, byte[] decoded, long base,
            TaskMonitor monitor) throws CancelledException {
        List<Record> out = new ArrayList<>();
        int limit = decoded.length - 16;
        for (int off = 0; off <= limit; off += 16) {
            if ((off & 0xffff) == 0) {
                monitor.checkCancelled();
            }
            long packedMeta = u32(decoded, off);
            int line = (int) (packedMeta & 0xffff);
            long fmtPtr = u32(decoded, off + 8);
            long filePtr = u32(decoded, off + 12);
            if (line <= 0 || line >= 65000 ||
                    fmtPtr < base || fmtPtr >= base + decoded.length) {
                continue;
            }
            String format = cString(decoded, (int) (fmtPtr - base), 400);
            if (format == null) {
                continue;
            }
            String source = cString(program.getMemory(), program, filePtr, 96);
            if (!looksLikeSource(source)) {
                continue;
            }
            out.add(new Record(off, line, fmtPtr, filePtr, source, format));
        }
        return out;
    }

    private static StringPool findStringPool(byte[] decoded, TaskMonitor monitor)
            throws CancelledException {
        List<StringEntry> strings = new ArrayList<>();
        int printableBytes = 0;
        int diagnostics = 0;
        int off = 0;
        while (off < decoded.length) {
            if ((off & 0xffff) == 0) {
                monitor.checkCancelled();
            }
            int start = off;
            while (off < decoded.length) {
                int c = decoded[off] & 0xff;
                if (c < 0x20 || c > 0x7e) {
                    break;
                }
                off++;
            }
            int len = off - start;
            boolean terminated = off < decoded.length && decoded[off] == 0;
            if (terminated && len >= 8) {
                String text = new String(decoded, start, len, java.nio.charset.StandardCharsets.US_ASCII);
                strings.add(new StringEntry(start, text));
                printableBytes += len;
                if (isDiagnosticString(text)) {
                    diagnostics++;
                }
            }
            off = Math.max(off + 1, start + 1);
        }
        return new StringPool(strings, printableBytes, diagnostics);
    }

    private static boolean isDiagnosticString(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        return lower.contains("assertion ") || lower.contains(" failed") ||
            lower.contains("ftm_") || lower.contains("rflm_") ||
            lower.contains("iq capture") || lower.contains("iq_capture") ||
            lower.contains("fbrx") || lower.contains("vswr") ||
            lower.contains("diag") || lower.contains("fatal");
    }

    private static int annotateStringPool(Program program, MemoryBlock overlay, StringPool pool,
            TaskMonitor monitor) throws CancelledException {
        int rf = 0;
        for (StringEntry entry : pool.strings()) {
            monitor.checkCancelled();
            if (!isRfInterest(entry.text())) {
                continue;
            }
            Address a = overlay.getStart().add(entry.offset());
            program.getListing().setComment(a, CommentType.EOL, entry.text());
            program.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS,
                "VNAOLTE/Qualcomm debug string", compact(entry.text()));
            rf++;
        }
        return rf;
    }

    private static int annotate(Program program, MemoryBlock overlay, List<Record> records,
            TaskMonitor monitor) throws CancelledException {
        int rf = 0;
        for (Record r : records) {
            monitor.checkCancelled();
            Address a = overlay.getStart().add(r.offset());
            String text = r.source() + ":" + r.line() + "  " + r.format();
            program.getListing().setComment(a, CommentType.EOL, text);
            if (isRfInterest(text)) {
                program.getBookmarkManager().setBookmark(a, BookmarkType.ANALYSIS,
                    "VNAOLTE/Qualcomm debug", compact(text));
                rf++;
            }
        }
        return rf;
    }

    private static boolean isRfInterest(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        for (String n : RF_NEEDLES) {
            if (lower.contains(n)) {
                return true;
            }
        }
        return false;
    }

    private static String cString(byte[] d, int off, int max) {
        if (off < 0 || off >= d.length) {
            return null;
        }
        StringBuilder s = new StringBuilder();
        int end = Math.min(d.length, off + max + 1);
        for (int i = off; i < end; i++) {
            int c = d[i] & 0xff;
            if (c == 0) {
                return s.isEmpty() ? null : s.toString();
            }
            if (c < 0x20 || c > 0x7e) {
                return null;
            }
            s.append((char) c);
        }
        return null;
    }

    private static String cString(Memory memory, Program program, long ptr, int max) {
        try {
            Address a = program.getAddressFactory().getDefaultAddressSpace().getAddress(ptr);
            StringBuilder s = new StringBuilder();
            for (int i = 0; i <= max; i++) {
                int c = memory.getByte(a.add(i)) & 0xff;
                if (c == 0) {
                    return s.isEmpty() ? null : s.toString();
                }
                if (c < 0x20 || c > 0x7e) {
                    return null;
                }
                s.append((char) c);
            }
        }
        catch (Exception ignored) {
            // Pointer does not resolve in the normal modem image.
        }
        return null;
    }

    private static boolean looksLikeSource(String s) {
        if (s == null || s.length() < 3 || s.length() > 95) {
            return false;
        }
        String l = s.toLowerCase(Locale.ROOT);
        return l.endsWith(".c") || l.endsWith(".cpp") || l.endsWith(".cc") ||
            l.endsWith(".h") || l.endsWith(".hpp");
    }

    private static long u32(byte[] d, int o) {
        return ((long) d[o] & 0xff) |
            (((long) d[o + 1] & 0xff) << 8) |
            (((long) d[o + 2] & 0xff) << 16) |
            (((long) d[o + 3] & 0xff) << 24);
    }

    private static String compact(String s) {
        String one = s.replace('\n', ' ').replace('\r', ' ').trim();
        return one.length() <= 240 ? one : one.substring(0, 237) + "...";
    }
}
