package vnaolte.ghidra.q6zip;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

final class Q6ZipDecoderTest {
    @Test
    void midPageBreakIsOnlyASplitMarker() throws Exception {
        BitWriter bits = new BitWriter();
        bits.opcode(0x303).put(0x11223344, 32);
        bits.opcode(0x71a).put(0xff, 8);
        bits.opcode(0x303).put(0x55667788, 32);

        int[] decoded = Q6ZipDecoder.decodePage(
            bits.words(), 0, new int[1], new int[1], 4);

        assertArrayEquals(new int[] { 0x11223344, 0x55667788 }, decoded);
    }

    @Test
    void terminalBreakStopsBeforeTrailingBits() throws Exception {
        BitWriter bits = new BitWriter();
        for (int i = 0; i < 1023; i++) {
            bits.opcode(0x303).put(0x40000000 | i, 32);
        }
        bits.opcode(0x71a).put(0xff, 8);
        // A decoder that merely breaks out of the switch consumes this value.
        bits.opcode(0x303).put(0x7badf00d, 32);

        int[] decoded = Q6ZipDecoder.decodePage(
            bits.words(), 0, new int[1], new int[1], 4);

        assertEquals(1023, decoded.length);
        assertEquals(0x40000000, decoded[0]);
        assertEquals(0x400003fe, decoded[1022]);
    }

    private static final class BitWriter {
        private final List<Integer> words = new ArrayList<>();
        private int current;
        private int bitPos;

        BitWriter opcode(int key) {
            int length = key >>> 8;
            int code = key & 0xff;
            return put(code, length);
        }

        BitWriter put(int value, int count) {
            long unsigned = Integer.toUnsignedLong(value);
            int consumed = 0;
            while (consumed < count) {
                int room = 32 - bitPos;
                int take = Math.min(room, count - consumed);
                long mask = take == 32 ? 0xffff_ffffL : (1L << take) - 1;
                current |= (int) (((unsigned >>> consumed) & mask) << bitPos);
                bitPos += take;
                consumed += take;
                if (bitPos == 32) {
                    words.add(current);
                    current = 0;
                    bitPos = 0;
                }
            }
            return this;
        }

        int[] words() {
            List<Integer> result = new ArrayList<>(words);
            if (bitPos != 0) {
                result.add(current);
            }
            return result.stream().mapToInt(Integer::intValue).toArray();
        }
    }
}
