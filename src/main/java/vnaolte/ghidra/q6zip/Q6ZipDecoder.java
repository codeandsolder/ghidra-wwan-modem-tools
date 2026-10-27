package vnaolte.ghidra.q6zip;

import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Decoder and structural detector for Qualcomm's older DLPager q6zip code
 * compression format.
 *
 * <p>The on-flash segment is:
 * <pre>
 *   u16 page_count;
 *   u16 version;
 *   u32 dict1[2^a];
 *   u32 dict2[2^b];
 *   u32 compressed_page_ptr[page_count];
 *   ... compressed pages ...
 * </pre>
 *
 * <p>The pointer-table location lets us infer the dictionary sizes without a
 * target-specific constant.  We then score dictionary order and lookback width
 * by decoding representative pages; correct parameters overwhelmingly produce
 * complete 4096-byte pages.
 */
public final class Q6ZipDecoder {
    public static final int PAGE_SIZE = 0x1000;
    private static final int PAGE_WORDS = PAGE_SIZE / 4;
    private static final int SAMPLE_PAGES = 192;

    public record Parameters(
            int pageCount,
            int version,
            int dict1Bits,
            int dict2Bits,
            int lookbackBits,
            int pointerTableOffset,
            int dataOffset,
            boolean metadataHeaders) {}

    public record RuntimeRange(long start, long end) {
        public long size() {
            return end - start;
        }
    }

    public record Result(
            Parameters parameters,
            RuntimeRange runtime,
            byte[] image,
            int exactPages,
            int shortPages) {}

    private record LayoutCandidate(
            int pageCount,
            int version,
            int dict1Bits,
            int dict2Bits,
            int pointerTableOffset,
            int dataOffset) {}

    private record ScoredParameters(
            LayoutCandidate layout,
            int lookbackBits,
            boolean metadataHeaders,
            int exact,
            long deviation) {}

    private Q6ZipDecoder() {}

    /**
     * Fast structural test. Besides the small header, require the first
     * compressed-page pointer to land exactly where one plausible pair of
     * power-of-two dictionaries plus the page-pointer table says data begins.
     * That cheaply eliminates ordinary data blocks whose first halfword happens
     * to look like a page count.
     */
    public static boolean looksLikeQ6Zip(MemoryBlock block) {
        if (!block.isInitialized() || block.getSize() < 0x10000) {
            return false;
        }
        byte[] head = new byte[4];
        try {
            if (block.getBytes(block.getStart(), head) != head.length) {
                return false;
            }
            int pages = u16(head, 0);
            int version = u16(head, 2);
            if (pages < 16 || pages > 0x10000 ||
                    !(version == 0 || (version & 0xff00) == 0x0600)) {
                return false;
            }

            long base = block.getStart().getOffset();
            byte[] ptr = new byte[4];
            for (int b1 = 8; b1 <= 15; b1++) {
                for (int b2 = 8; b2 <= 15; b2++) {
                    if (b1 == b2) {
                        continue;
                    }
                    long ptrOffset = 4L + 4L * ((1L << b1) + (1L << b2));
                    long dataOffset = ptrOffset + 4L * pages;
                    if (dataOffset >= block.getSize()) {
                        continue;
                    }
                    if (block.getBytes(block.getStart().add(ptrOffset), ptr) != ptr.length) {
                        continue;
                    }
                    long firstPointer = Integer.toUnsignedLong(
                        (ptr[0] & 0xff) | ((ptr[1] & 0xff) << 8) |
                        ((ptr[2] & 0xff) << 16) | ((ptr[3] & 0xff) << 24));
                    if (firstPointer == base + dataOffset) {
                        return true;
                    }
                }
            }
            return false;
        }
        catch (MemoryAccessException | RuntimeException e) {
            return false;
        }
    }

    public static Result decompress(Memory memory, MemoryBlock block, TaskMonitor monitor)
            throws IOException, CancelledException, MemoryAccessException {
        List<LayoutCandidate> layouts = findLayouts(memory, block);
        if (layouts.isEmpty()) {
            throw new IOException("q6zip header found, but dictionary/pointer layout is not self-consistent");
        }

        ScoredParameters best = null;
        for (LayoutCandidate layout : layouts) {
            monitor.checkCancelled();
            ScoredParameters scored = scoreLayout(memory, block, layout, monitor);
            if (scored != null && better(scored, best)) {
                best = scored;
            }
        }
        if (best == null) {
            throw new IOException("could not infer q6zip dictionary order/lookback");
        }

        Parameters params = new Parameters(
            best.layout.pageCount,
            best.layout.version,
            best.layout.dict1Bits,
            best.layout.dict2Bits,
            best.lookbackBits,
            best.layout.pointerTableOffset,
            best.layout.dataOffset,
            best.metadataHeaders);

        long[] ptrs = readPointers(memory, block, best.layout);
        int[] dict1 = readWords(memory, block.getStart().add(4),
            1 << best.layout.dict1Bits);
        int[] dict2 = readWords(memory,
            block.getStart().add(4L + 4L * (1 << best.layout.dict1Bits)),
            1 << best.layout.dict2Bits);

        RuntimeRange runtime = findRuntimeRange(memory, block, best.layout.pageCount, monitor);
        if (runtime == null) {
            throw new IOException(String.format(
                "q6zip compressed segment %s has no DLPager runtime mapping descriptor",
                block.getName()));
        }
        long expectedSize = (long) best.layout.pageCount * PAGE_SIZE;
        if (runtime.size() != expectedSize || expectedSize > Integer.MAX_VALUE) {
            throw new IOException(String.format(
                "unexpected q6zip runtime size 0x%x (expected 0x%x)",
                runtime.size(), expectedSize));
        }

        byte[] image = new byte[(int) expectedSize];
        int exact = 0;
        int shortPages = 0;
        long blockEndExclusive = block.getStart().getOffset() + block.getSize();

        for (int i = 0; i < best.layout.pageCount; i++) {
            if ((i & 0x3f) == 0) {
                monitor.checkCancelled();
                monitor.setMessage(String.format("q6zip: decompressing page %d/%d",
                    i, best.layout.pageCount));
            }
            long chunkStart = ptrs[i];
            long chunkEnd = (i + 1 < ptrs.length) ? ptrs[i + 1] : blockEndExclusive;
            int[] compressed = readChunkWords(memory, block, chunkStart, chunkEnd);
            int skip = (best.metadataHeaders && hasMetadataHeader(compressed)) ? 2 : 0;
            int[] page = decodePage(compressed, skip, dict1, dict2, best.lookbackBits);

            if (page.length == PAGE_WORDS) {
                exact++;
            }
            else {
                shortPages++;
            }
            int n = Math.min(PAGE_WORDS, page.length);
            int dst = i * PAGE_SIZE;
            for (int w = 0; w < n; w++) {
                putLe32(image, dst + w * 4, page[w]);
            }
            // byte[] is already zero-filled when a q6zip page decodes short.
        }

        // q6zip parameter inference should be overwhelming, not marginal.
        if (exact < Math.max(8, (best.layout.pageCount * 9) / 10)) {
            throw new IOException(String.format(
                "q6zip inference is weak: only %d/%d pages decode to 4096 bytes",
                exact, best.layout.pageCount));
        }

        return new Result(params, runtime, image, exact, shortPages);
    }

    private static boolean better(ScoredParameters a, ScoredParameters b) {
        if (b == null) {
            return true;
        }
        if (a.exact != b.exact) {
            return a.exact > b.exact;
        }
        if (a.deviation != b.deviation) {
            return a.deviation < b.deviation;
        }
        // Qualcomm's common layout has the smaller dictionary first.
        if (a.layout.dict1Bits != b.layout.dict1Bits) {
            return a.layout.dict1Bits < b.layout.dict1Bits;
        }
        return a.lookbackBits < b.lookbackBits;
    }

    private static List<LayoutCandidate> findLayouts(Memory memory, MemoryBlock block)
            throws MemoryAccessException {
        byte[] head = new byte[4];
        block.getBytes(block.getStart(), head);
        int pages = u16(head, 0);
        int version = u16(head, 2);
        long base = block.getStart().getOffset();
        long endExclusive = base + block.getSize();
        List<LayoutCandidate> out = new ArrayList<>();

        for (int b1 = 8; b1 <= 15; b1++) {
            for (int b2 = 8; b2 <= 15; b2++) {
                if (b1 == b2) {
                    continue;
                }
                long ptrOffLong = 4L + 4L * ((1L << b1) + (1L << b2));
                long dataOffLong = ptrOffLong + 4L * pages;
                if (dataOffLong >= block.getSize() ||
                        ptrOffLong > Integer.MAX_VALUE ||
                        dataOffLong > Integer.MAX_VALUE) {
                    continue;
                }
                long firstPtr = u32(memory.getInt(block.getStart().add(ptrOffLong), false));
                if (firstPtr != base + dataOffLong) {
                    continue;
                }

                // A few pointer checks reject accidental arithmetic matches.
                long prev = firstPtr;
                boolean valid = true;
                int checks = Math.min(pages, 32);
                for (int i = 1; i < checks; i++) {
                    long p = u32(memory.getInt(
                        block.getStart().add(ptrOffLong + 4L * i), false));
                    if (p <= prev || p < base + dataOffLong || p >= endExclusive) {
                        valid = false;
                        break;
                    }
                    prev = p;
                }
                if (valid) {
                    out.add(new LayoutCandidate(pages, version, b1, b2,
                        (int) ptrOffLong, (int) dataOffLong));
                }
            }
        }
        return out;
    }

    private static ScoredParameters scoreLayout(Memory memory, MemoryBlock block,
            LayoutCandidate layout, TaskMonitor monitor)
            throws IOException, CancelledException {
        int[] dict1;
        int[] dict2;
        long[] ptrs;
        try {
            dict1 = readWords(memory, block.getStart().add(4),
                1 << layout.dict1Bits);
            dict2 = readWords(memory,
                block.getStart().add(4L + 4L * (1 << layout.dict1Bits)),
                1 << layout.dict2Bits);
            ptrs = readPointers(memory, block, layout);
        }
        catch (MemoryAccessException e) {
            throw new IOException(e);
        }

        boolean meta = false;
        try {
            if (ptrs.length > 0) {
                long end = ptrs.length > 1 ? ptrs[1] :
                    block.getStart().getOffset() + block.getSize();
                meta = hasMetadataHeader(readChunkWords(memory, block, ptrs[0], end));
            }
        }
        catch (MemoryAccessException e) {
            throw new IOException(e);
        }

      ScoredParameters best = null;
        int samples = Math.min(SAMPLE_PAGES, layout.pageCount);
        long blockEndExclusive = block.getStart().getOffset() + block.getSize();

        for (int lb = 4; lb <= 12; lb++) {
            int exact = 0;
            long deviation = 0;
            for (int s = 0; s < samples; s++) {
                monitor.checkCancelled();
                int i = (int) (((long) s * layout.pageCount) / samples);
                if (i >= layout.pageCount) {
                    i = layout.pageCount - 1;
                }
                long chunkStart = ptrs[i];
                long chunkEnd = (i + 1 < ptrs.length) ? ptrs[i + 1] : blockEndExclusive;
                int[] compressed;
                try {
                    compressed = readChunkWords(memory, block, chunkStart, chunkEnd);
                }
                catch (MemoryAccessException e) {
                    throw new IOException(e);
                }
                int skip = (meta && hasMetadataHeader(compressed)) ? 2 : 0;
                int[] page;
                try {
                    page = decodePage(compressed, skip, dict1, dict2, lb);
                }
                catch (IOException e) {
                    deviation += PAGE_WORDS;
                    continue;
                }
                int expected = (i == layout.pageCount - 1) ? PAGE_WORDS - 1 : PAGE_WORDS;
                if (page.length == PAGE_WORDS ||
                        (i == layout.pageCount - 1 && page.length == PAGE_WORDS - 1)) {
                    exact++;
                }
                deviation += Math.abs((long) expected - page.length);
            }
            ScoredParameters scored = new ScoredParameters(layout, lb, meta, exact, deviation);
            if (better(scored, best)) {
                best = scored;
            }
        }
        return best;
    }

    private static long[] readPointers(Memory memory, MemoryBlock block,
            LayoutCandidate layout) throws MemoryAccessException, IOException {
        long[] ptrs = new long[layout.pageCount];
        long base = block.getStart().getOffset();
        long endExclusive = base + block.getSize();
        long prev = 0;
        for (int i = 0; i < ptrs.length; i++) {
            long p = u32(memory.getInt(
                block.getStart().add(layout.pointerTableOffset + 4L * i), false));
            if (p < base + layout.dataOffset || p >= endExclusive ||
                    (i > 0 && p <= prev)) {
                throw new IOException(String.format(
                    "invalid q6zip page pointer[%d]=0x%0x", i, p));
            }
            ptrs[i] = p;
            prev = p;
        }
        return ptrs;
    }

    private static int[] readWords(Memory memory, Address start, int count)
            throws MemoryAccessException {
        int[] out = new int[count];
        memory.getInts(start, out, 0, count, false);
        return out;
    }

    private static int[] readChunkWords(Memory memory, MemoryBlock block,
            long start, long end) throws MemoryAccessException, IOException {
        long base = block.getStart().getOffset();
        long blockEnd = base + block.getSize();
        if (start < base || end <= start || end > blockEnd) {
            throw new IOException(String.format(
                "invalid q6zip chunk range 0x%x..0x%x for block 0x%x..0x%x",
                start, end, base, blockEnd));
        }
        int bytes = (int) (end - start);
        int words = bytes / 4;
        int[] out = new int[words];
        memory.getInts(block.getStart().getAddressSpace().getAddress(start),
            out, 0, words, false);
        return out;
    }

    /**
     * Find the DLPager descriptor:
     *   runtime_start, runtime_end, compressed_start, compressed_end
     */
    public static RuntimeRange findRuntimeRange(Memory memory, MemoryBlock block,
            int pages, TaskMonitor monitor) throws CancelledException {
        long compressedStart = block.getStart().getOffset();
        long compressedEnd = compressedStart + block.getSize();
        byte[] needle = new byte[8];
        putLe32(needle, 0, (int) compressedStart);
        putLe32(needle, 4, (int) compressedEnd);

        Address search = memory.getMinAddress();
        Address max = memory.getMaxAddress();
        while (search != null && search.compareTo(max) <= 0) {
            monitor.checkCancelled();
            Address hit = memory.findBytes(search, max, needle, null, true, monitor);
            if (hit == null) {
                return null;
            }
            try {
                Address descriptor = hit.subtract(8);
                long runtimeStart = u32(memory.getInt(descriptor, false));
                long runtimeEnd = u32(memory.getInt(descriptor.add(4), false));
                if ((runtimeStart & (PAGE_SIZE - 1)) == 0 &&
                        runtimeEnd > runtimeStart &&
                        runtimeEnd - runtimeStart == (long) pages * PAGE_SIZE) {
                    return new RuntimeRange(runtimeStart, runtimeEnd);
                }
            }
            catch (Exception ignored) {
                // Search the next occurrence.
            }
            try {
                search = hit.next();
            }
            catch (Exception e) {
                return null;
            }
      }
        return null;
    }

    private static boolean hasMetadataHeader(int[] words) {
        if (words.length < 3) {
            return false;
        }
        Meta a = meta(words[0]);
        Meta b = meta(words[1]);
        return a.lastSeq == -1 && b.lastSeq == -1 &&
            a.bitsLeft >= 1 && a.bitsLeft <= 32 &&
            b.bitsLeft >= 1 && b.bitsLeft <= 32 &&
            a.inDelta >= 0 && a.inDelta <= 8 &&
            a.outDelta >= -2 && a.outDelta <= 8 &&
            b.inDelta >= 0 && b.inDelta <= 0x3ff &&
            b.outDelta >= -8 && b.outDelta <= 8;
    }

    private record Meta(int lastSeq, int bitsLeft, int inDelta, int outDelta) {}

    private static Meta meta(int value) {
        int last = value & 0x3ff;
        if (last > 0x1ff) {
            last -= 0x400;
        }
        int bitsLeft = (value >>> 10) & 0x3f;
        int inDelta = (value >>> 16) & 0x3ff;
        int out = (value >>> 26) & 0x3f;
        if (out > 0x1f) {
            out -= 0x40;
        }
        return new Meta(last, bitsLeft, inDelta, out);
    }

    static int[] decodePage(int[] compressed, int skipWords, int[] dict1, int[] dict2,
            int lookbackBits) throws IOException {
        if (skipWords < 0 || skipWords >= compressed.length) {
            throw new IOException("invalid q6zip metadata skip");
        }
        BitReader bits = new BitReader(compressed, skipWords);
        int[] out = new int[PAGE_WORDS + 2];
        int outCount = 0;
        int lastOut = -1;

        try {
            while (outCount <= PAGE_WORDS - 1) {
                int op = readOpcode(bits);
                switch (op) {
                    case 0x304 -> { // 3 bits, 100: dict1
                        int ix = bits.get(ilog2(dict1.length));
                        out[outCount++] = dict1[ix];
                    }
                    case 0x405 -> { // 4 bits, 0101: dict2
                        int ix = bits.get(ilog2(dict2.length));
                        out[outCount++] = dict2[ix];
                    }
                    case 0x303 -> out[outCount++] = bits.get(32); // literal
                    case 0x307 -> { // sequential
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = prev;
                    }
                    case 0x71a -> { // mask 8 @16, or break
                        int m = bits.get(8);
                        if (m == 0xff) {
                            if (outCount >= PAGE_WORDS - 1) {
                            break;
                            }
                        }
                        else {
                            int prev = previous(out, outCount, lastOut);
                            out[outCount++] = (prev & ~(0xff << 16)) | (m << 16);
                        }
                    }
                    case 0x75a -> { // mask 8 @8
                        int m = bits.get(8);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~(0xff << 8)) | (m << 8);
                    }
                    case 0x306 -> { // mask 8 @0
                        int m = bits.get(8);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~0xff) | m;
                    }
                    case 0x51d -> { // mask 12 @0
                        int m = bits.get(12);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~0xfff) | m;
                    }
                    case 0x60a -> { // mask 16 @0
                        int m = bits.get(16);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~0xffff) | m;
                    }
                    case 0x301 -> { // lookback
                        int lb = bits.get(lookbackBits);
                        lastOut = lb - (1 << lookbackBits);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = prev;
                    }
                    case 0x62a -> { // lookback mask 8 @16
                        int lb = bits.get(lookbackBits);
                        int m = bits.get(8);
                        lastOut = lb - (1 << lookbackBits);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~(0xff << 16)) | (m << 16);
                    }
                    case 0x63a -> { // lookback mask 8 @8
                        int lb = bits.get(lookbackBits);
                        int m = bits.get(8);
                        lastOut = lb - (1 << lookbackBits);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~(0xff << 8)) | (m << 8);
                    }
                    case 0x300 -> { // lookback mask 8 @0
                        int lb = bits.get(lookbackBits);
                        int m = bits.get(8);
                        lastOut = lb - (1 << lookbackBits);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~0xff) | m;
                    }
                    case 0x402 -> { // lookback mask 12 @0
                        int lb = bits.get(lookbackBits);
                        int m = bits.get(12);
                        lastOut = lb - (1 << lookbackBits);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~0xfff) | m;
                    }
                    case 0x50d -> { // lookback mask 16 @0
                        int lb = bits.get(lookbackBits);
                        int m = bits.get(16);
                        lastOut = lb - (1 << lookbackBits);
                        int prev = previous(out, outCount, lastOut);
                        out[outCount++] = (prev & ~0xffff) | m;
                    }
                    default -> throw new IOException(String.format(
                        "unhandled q6zip opcode 0x%0x", op));
                }
            }
        }
        catch (EOFException ignored) {
            // Some q6zip pages legitimately end short; the caller zero-fills the tail.
        }
        catch (ArrayIndexOutOfBoundsException e) {
            throw new IOException("q6zip dictionary index out of range", e);
        }
        return Arrays.copyOf(out, outCount);
    }

    private static int previous(int[] out, int outCount, int relative) {
        int ix = outCount + relative;
        return ix < 0 ? 0 : out[ix];
    }

    private static int readOpcode(BitReader bits) throws EOFException, IOException {
        int code = 0;
        for (int len = 1; len <= 7; len++) {
            code |= bits.get(1) << (len - 1);
            int key = (len << 8) | code;
            if (isOpcode(key)) {
                return key;
            }
        }
        throw new IOException(String.format("invalid q6zip opcode prefix 0x%0x", code));
    }

    private static boolean isOpcode(int key) {
        return switch (key) {
            case 0x304, 0x405, 0x303, 0x307,
                  0x71a, 0x75a, 0x306, 0x51d, 0x60a,
                 0x301, 0x62a, 0x63a, 0x300, 0x402, 0x50d -> true;
            default -> false;
        };
    }

    private static int ilog2(int n) {
        return 31 - Integer.numberOfLeadingZeros(n);
    }

    private static final class BitReader {
        private final int[] words;
        private int wordIndex;
        private int bitPos;

        BitReader(int[] words, int skipWords) {
            this.words = words;
            this.wordIndex = skipWords;
            this.bitPos = 0;
        }

        int get(int count) throws EOFException {
            if (count < 0 || count > 32) {
                throw new IllegalArgumentException("bit count " + count);
            }
            long result = 0;
            int shift = 0;
            int remaining = count;
            while (remaining > 0) {
                if (wordIndex >= words.length) {
                    throw new EOFException();
                }
                int available = 32 - bitPos;
                int take = Math.min(available, remaining);
                long current = Integer.toUnsignedLong(words[wordIndex]);
                long mask = take == 32 ? 0xffff_ffffL : ((1L << take) - 1);
                result |= ((current >>> bitPos) & mask) << shift;
                bitPos += take;
                shift += take;
                remaining -= take;
                if (bitPos == 32) {
                    wordIndex++;
                    bitPos = 0;
                }
            }
            return (int) result;
        }
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    private static long u32(int value) {
        return Integer.toUnsignedLong(value);
    }

    private static void putLe32(byte[] b, int off, int value) {
        b[off] = (byte) value;
        b[off + 1] = (byte) (value >>> 8);
        b[off + 2] = (byte) (value >>> 16);
        b[off + 3] = (byte) (value >>> 24);
    }
}
