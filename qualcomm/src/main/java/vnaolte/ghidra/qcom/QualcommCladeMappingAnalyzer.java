package vnaolte.ghidra.qcom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

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
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds self-described Qualcomm CLADE compressed-to-runtime mappings.
 *
 * <p>Modern QuRT modem images carry textual CLADE configuration evidence
 * (for example {@code .clade.comp}, {@code .clade.dict}, and
 * {@code QURTK_clade_*}). Some generations also carry a compact range tuple
 * describing the mapping from a compressed ELF region to the virtual executable
 * range produced by the CLADE hardware; others only self-identify the packed
 * block next to a {@code .clade.comp} registry key. This analyzer deliberately
 * does not decompress CLADE. It records a full mapping when one is structurally
 * recoverable and otherwise records only the self-described compressed region.
 *
 * <p>No chipset, firmware version, segment number, or address is hard-coded.
 * Full-mapping candidates must be page aligned, similarly sized, backed by an
 * initialized high-entropy packed block, point at an unmapped runtime range,
 * and occur only in a program which independently contains CLADE configuration
 * evidence. Compressed-only candidates additionally require the literal
 * {@code .clade.comp} metadata to sit next to an exact pointer to that block.
 */
public final class QualcommCladeMappingAnalyzer extends AbstractAnalyzer {
    private static final long PAGE_MASK = 0xfffL;
    private static final long MIN_REGION = 0x100000L;
    private static final long MAX_REGION = 0x40000000L;
    private static final long MAX_SPAN_DELTA = 0x10000L;
    private static final long MAX_PACKED_START_SLACK = 0x10000L;
    private static final long MAX_PACKED_END_SLACK = 0x10000L;
    private static final double MIN_ENTROPY = 6.0;
    private static final int ENTROPY_SAMPLE = 1 << 20;

    private record Mapping(Address tupleAddress, long compressedStart, long compressedEnd,
            long runtimeStart, long runtimeEnd, MemoryBlock packedBlock, double entropy) {}

    private record NamedRegion(Address metadataAddress, MemoryBlock packedBlock,
            double entropy) {}

    public QualcommCladeMappingAnalyzer() {
        super("VNAOLTE Qualcomm CLADE Mapping",
            "Finds structurally validated Qualcomm CLADE compressed-to-runtime range mappings without chipset-specific addresses.",
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
        if (!hasCladeEvidence(memory, monitor)) {
            log.appendMsg(getName(), "no CLADE configuration evidence found");
            return true;
        }

        List<Mapping> mappings = findMappings(memory, monitor);
        Set<String> seen = new HashSet<>();
        Set<Long> mappedBlocks = new HashSet<>();
        int annotated = 0;
        for (Mapping m : mappings) {
            monitor.checkCancelled();
            String key = Long.toUnsignedString(m.compressedStart()) + ":" +
                Long.toUnsignedString(m.runtimeStart());
            if (!seen.add(key)) {
                continue;
            }
            annotate(program, m);
            mappedBlocks.add(m.packedBlock().getStart().getOffset());
            annotated++;
            log.appendMsg(getName(), String.format(Locale.ROOT,
                "CLADE %s: compressed 0x%08x..0x%08x -> runtime 0x%08x..0x%08x; spans 0x%x/0x%x; entropy %.2f",
                m.packedBlock().getName(), m.compressedStart(), m.compressedEnd(),
                m.runtimeStart(), m.runtimeEnd(),
                m.compressedEnd() - m.compressedStart(),
                m.runtimeEnd() - m.runtimeStart(), m.entropy()));
        }

        for (NamedRegion region : findNamedRegions(memory, monitor)) {
            monitor.checkCancelled();
            long packedStart = region.packedBlock().getStart().getOffset();
            if (mappedBlocks.contains(packedStart) || !seen.add("named:" + packedStart)) {
                continue;
            }
            annotateNamedRegion(program, region);
            annotated++;
            log.appendMsg(getName(), String.format(Locale.ROOT,
                "CLADE %s: self-described .clade.comp packed region at 0x%08x (size 0x%x, entropy %.2f); runtime mapping not recovered",
                region.packedBlock().getName(), packedStart,
                region.packedBlock().getSize(), region.entropy()));
        }
        if (annotated == 0) {
            log.appendMsg(getName(), "CLADE support is present but no self-consistent mapping or named packed region was found");
        }
        return true;
    }

    private static List<NamedRegion> findNamedRegions(Memory memory, TaskMonitor monitor)
            throws CancelledException {
        byte[] needle = ".clade.comp".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        List<NamedRegion> out = new ArrayList<>();
        Set<Long> seenBlocks = new HashSet<>();
        for (MemoryBlock metadataBlock : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!metadataBlock.isInitialized() || metadataBlock.getSize() < needle.length) {
                continue;
            }
            Address search = metadataBlock.getStart();
            while (search != null && search.compareTo(metadataBlock.getEnd()) <= 0) {
                Address hit = memory.findBytes(search, metadataBlock.getEnd(), needle,
                    null, true, monitor);
                if (hit == null) {
                    break;
                }
                long hitOffset = hit.getOffset();
                long first = (Math.max(metadataBlock.getStart().getOffset(), hitOffset - 64) + 3) & ~3L;
                long last = Math.min(metadataBlock.getEnd().getOffset() - 3, hitOffset + 64);
                for (long p = first; p <= last; p += 4) {
                    try {
                        Address wordAddress = hit.getAddressSpace().getAddress(p);
                        long value = Integer.toUnsignedLong(memory.getInt(wordAddress, false));
                        Address candidateAddress = hit.getAddressSpace().getAddress(value);
                        MemoryBlock packed = memory.getBlock(candidateAddress);
                        if (packed == null || !packed.isInitialized() ||
                                packed.getStart().getOffset() != value ||
                                packed.getSize() < MIN_REGION ||
                                !seenBlocks.add(value)) {
                            continue;
                        }
                        double h = entropy(memory, packed, monitor);
                        if (h >= MIN_ENTROPY) {
                            out.add(new NamedRegion(hit, packed, h));
                        }
                        else {
                            seenBlocks.remove(value);
                        }
                    }
                    catch (CancelledException e) {
                        throw e;
                    }
                    catch (Exception ignored) {
                        // Keep scanning nearby metadata words.
                    }
                }
                try {
                    search = hit.add(needle.length);
                }
                catch (Exception e) {
                    break;
                }
            }
        }
        return out;
    }

    private static boolean hasCladeEvidence(Memory memory, TaskMonitor monitor)
            throws CancelledException {
        return contains(memory, ".clade.comp", monitor) &&
            (contains(memory, ".clade.dict", monitor) ||
             contains(memory, "QURTK_clade", monitor));
    }

    private static boolean contains(Memory memory, String text, TaskMonitor monitor)
            throws CancelledException {
        byte[] needle = text.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        for (MemoryBlock block : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || block.getSize() < needle.length) {
                continue;
            }
            Address hit = memory.findBytes(block.getStart(), block.getEnd(), needle, null, true, monitor);
            if (hit != null) {
                return true;
            }
        }
        return false;
    }

    private static List<Mapping> findMappings(Memory memory, TaskMonitor monitor)
            throws CancelledException {
        List<Mapping> found = new ArrayList<>();
        Map<Long, Double> starts = new HashMap<>();
        Set<MemoryBlock> packedCandidates = new HashSet<>();
        for (MemoryBlock block : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!block.isInitialized() || block.getSize() < MIN_REGION) {
                continue;
            }
            double packedEntropy = entropy(memory, block, monitor);
            if (packedEntropy < MIN_ENTROPY) {
                continue;
            }
            packedCandidates.add(block);
            long blockStart = block.getStart().getOffset();
            long blockEnd = block.getEnd().getOffset() + 1;
            long maxStart = Math.min(blockStart + MAX_PACKED_START_SLACK, blockEnd - 1);
            for (long candidate = blockStart; candidate <= maxStart;
                    candidate += PAGE_MASK + 1) {
                starts.put(candidate, packedEntropy);
            }
        }
        if (starts.isEmpty()) {
            return found;
        }

        // One linear pass over ordinary code/data blocks. This avoids repeatedly
        // asking Ghidra to rescan the complete address space for each plausible
        // packed start, and it also avoids treating entropy-dense packed bytes as
        // a source of accidental mapping tuples.
        final int chunkSize = 1 << 20;
        for (MemoryBlock tupleBlock : memory.getBlocks()) {
            monitor.checkCancelled();
            if (!tupleBlock.isInitialized() || tupleBlock.getSize() < 16 ||
                    packedCandidates.contains(tupleBlock)) {
                continue;
            }
            long blockOffset = 0;
            byte[] buf = new byte[chunkSize + 12];
            while (blockOffset < tupleBlock.getSize()) {
                monitor.checkCancelled();
                int want = (int) Math.min(buf.length, tupleBlock.getSize() - blockOffset);
                Address chunkStart = tupleBlock.getStart().add(blockOffset);
                int got;
                try {
                    got = memory.getBytes(chunkStart, buf, 0, want);
                }
                catch (Exception e) {
                    break;
                }
                if (got < 16) {
                    break;
                }
                int scan = got - 15;
                long absoluteStart = chunkStart.getOffset();
                int firstAligned = (int) ((4 - (absoluteStart & 3)) & 3);
                for (int off = firstAligned; off < scan; off += 4) {
                    long compressedStart = u32(buf, off);
                    Double packedEntropy = starts.get(compressedStart);
                    if (packedEntropy == null) {
                        continue;
                    }
                    long compressedEnd = u32(buf, off + 4);
                    long runtimeStart = u32(buf, off + 8);
                    long runtimeEnd = u32(buf, off + 12);
                    Mapping candidate = validate(memory, chunkStart.add(off),
                        compressedStart, compressedEnd, runtimeStart, runtimeEnd, packedEntropy);
                    if (candidate != null) {
                        found.add(candidate);
                    }
                }
                if (got <= 12) {
                    break;
                }
                blockOffset += got - 12L;
            }
        }
        return found;
    }

    private static Mapping validate(Memory memory, Address tupleAddress,
            long compressedStart, long compressedEnd, long runtimeStart, long runtimeEnd,
            double packedEntropy) {
        if (((compressedStart | compressedEnd | runtimeStart | runtimeEnd) & PAGE_MASK) != 0 ||
                Long.compareUnsigned(compressedEnd, compressedStart) <= 0 ||
                Long.compareUnsigned(runtimeEnd, runtimeStart) <= 0) {
            return null;
        }
        long compressedSpan = compressedEnd - compressedStart;
        long runtimeSpan = runtimeEnd - runtimeStart;
        if (compressedSpan < MIN_REGION || runtimeSpan < MIN_REGION ||
                compressedSpan > MAX_REGION || runtimeSpan > MAX_REGION ||
                Math.abs(compressedSpan - runtimeSpan) > MAX_SPAN_DELTA) {
            return null;
        }

        Address compressedAddress;
        Address runtimeAddress;
        Address runtimeLast;
        try {
            var space = memory.getProgram().getAddressFactory().getDefaultAddressSpace();
            compressedAddress = space.getAddress(compressedStart);
            runtimeAddress = space.getAddress(runtimeStart);
            runtimeLast = space.getAddress(runtimeEnd - 1);
        }
        catch (Exception e) {
            return null;
        }
        MemoryBlock packed = memory.getBlock(compressedAddress);
        if (packed == null || !packed.isInitialized()) {
            return null;
        }
        long packedStart = packed.getStart().getOffset();
        long packedEndExclusive = packed.getEnd().getOffset() + 1;
        if (Long.compareUnsigned(compressedStart, packedStart) < 0 ||
                compressedStart - packedStart > MAX_PACKED_START_SLACK ||
                Long.compareUnsigned(compressedEnd, packedEndExclusive + MAX_PACKED_END_SLACK) > 0) {
            return null;
        }
        if (memory.getBlock(runtimeAddress) != null || memory.getBlock(runtimeLast) != null) {
            return null;
        }
        return new Mapping(tupleAddress, compressedStart, compressedEnd,
            runtimeStart, runtimeEnd, packed, packedEntropy);
    }

    private static double entropy(Memory memory, MemoryBlock block, TaskMonitor monitor)
            throws CancelledException {
        int n = (int) Math.min(block.getSize(), ENTROPY_SAMPLE);
        if (n <= 0) {
            return 0.0;
        }
        byte[] sample = new byte[n];
        try {
            int got = memory.getBytes(block.getStart(), sample);
            if (got <= 0) {
                return 0.0;
            }
            n = got;
        }
        catch (Exception e) {
            return 0.0;
        }
        long[] counts = new long[256];
        for (int i = 0; i < n; i++) {
            if ((i & 0xffff) == 0) {
                monitor.checkCancelled();
            }
            counts[sample[i] & 0xff]++;
        }
        double h = 0.0;
        for (long count : counts) {
            if (count == 0) continue;
            double p = (double) count / n;
            h -= p * (Math.log(p) / Math.log(2.0));
        }
        return h;
    }

    private static void annotate(Program program, Mapping m) {
        String text = String.format(Locale.ROOT,
            "Qualcomm CLADE mapping: compressed 0x%08x..0x%08x (%s) -> runtime 0x%08x..0x%08x; packed/runtime spans 0x%x/0x%x; entropy %.2f",
            m.compressedStart(), m.compressedEnd(), m.packedBlock().getName(),
            m.runtimeStart(), m.runtimeEnd(),
            m.compressedEnd() - m.compressedStart(),
            m.runtimeEnd() - m.runtimeStart(), m.entropy());
        program.getListing().setComment(m.tupleAddress(), CommentType.EOL, text);
        program.getBookmarkManager().setBookmark(m.tupleAddress(), BookmarkType.ANALYSIS,
            "VNAOLTE/Qualcomm CLADE", text);
        program.getBookmarkManager().setBookmark(m.packedBlock().getStart(), BookmarkType.ANALYSIS,
            "VNAOLTE/Qualcomm CLADE", text);
        String old = m.packedBlock().getComment();
        if (old == null || old.isBlank()) {
            m.packedBlock().setComment(text);
        }
        else if (!old.contains("Qualcomm CLADE mapping")) {
            m.packedBlock().setComment(old + "\n" + text);
        }
    }

    private static void annotateNamedRegion(Program program, NamedRegion region) {
        MemoryBlock packed = region.packedBlock();
        String text = String.format(Locale.ROOT,
            "Qualcomm CLADE compressed region: %s at 0x%08x, size 0x%x, entropy %.2f; identified by nearby .clade.comp metadata; runtime mapping not recovered",
            packed.getName(), packed.getStart().getOffset(), packed.getSize(), region.entropy());
        program.getListing().setComment(region.metadataAddress(), CommentType.EOL, text);
        program.getBookmarkManager().setBookmark(region.metadataAddress(), BookmarkType.ANALYSIS,
            "VNAOLTE/Qualcomm CLADE", text);
        program.getBookmarkManager().setBookmark(packed.getStart(), BookmarkType.ANALYSIS,
            "VNAOLTE/Qualcomm CLADE", text);
        String old = packed.getComment();
        if (old == null || old.isBlank()) {
            packed.setComment(text);
        }
        else if (!old.contains("Qualcomm CLADE compressed region")) {
            packed.setComment(old + "\n" + text);
        }
    }

    private static long u32(byte[] b, int off) {
        return Integer.toUnsignedLong((b[off] & 0xff) |
            ((b[off + 1] & 0xff) << 8) |
            ((b[off + 2] & 0xff) << 16) |
            ((b[off + 3] & 0xff) << 24));
    }
}
