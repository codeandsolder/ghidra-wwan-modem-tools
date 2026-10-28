// Verify the exact SWI9X30C_02.38.00.00 EM7455 packed-segment ingestion.
// Intended as a cheap no-analysis regression smoke.
// @category VNAOLTE

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.mem.MemoryBlock;
import vnaolte.ghidra.q6zip.QualcommQ6ZipAnalyzer;
import vnaolte.ghidra.qcom.QualcommZlibDebugOverlayAnalyzer;

public class VerifyEm7455Packed extends GhidraScript {
    @Override
    public void run() throws Exception {
        var range = currentProgram.getMemory().getLoadedAndInitializedAddressSet();

        MessageLog qlog = new MessageLog();
        boolean qok = new QualcommQ6ZipAnalyzer().added(currentProgram, range, monitor, qlog);
        println("Q6ZIP_OK=" + qok);
        println(qlog.toString());

        MessageLog zlog = new MessageLog();
        boolean zok = new QualcommZlibDebugOverlayAnalyzer().added(currentProgram, range, monitor, zlog);
        println("ZLIB_OK=" + zok);
        println(zlog.toString());

        MemoryBlock q = currentProgram.getMemory().getBlock("q6zip_rx_d0000000");
        MemoryBlock z = currentProgram.getMemory().getBlock("qcom_zlib_debug_0550e000");
        if (q == null || q.getStart().getOffset() != 0xd0000000L ||
                q.getSize() != 0xeb3000L || !q.isExecute()) {
            throw new AssertionError(
                "EM7455 q6zip mapping does not match the known SWI9X30C image");
        }
        if (z == null || !z.isOverlay() || z.getSize() != 0x2ebbfeL || z.isExecute()) {
            throw new AssertionError(
                "EM7455 zlib debug overlay does not match the known SWI9X30C image");
        }

        int bookmarks = currentProgram.getBookmarkManager().getBookmarkCount();
        if (bookmarks < 300) {
            throw new AssertionError(
                "expected hundreds of recovered Qualcomm debug bookmarks, got " + bookmarks);
        }

        println(String.format(
            "Q6ZIP_BLOCK=%s %s..%s size=0x%x",
            q.getName(), q.getStart(), q.getEnd(), q.getSize()));
        println(String.format(
            "ZLIB_BLOCK=%s %s..%s size=0x%x overlay=%s",
            z.getName(), z.getStart(), z.getEnd(), z.getSize(), z.isOverlay()));
        println("BOOKMARKS=" + bookmarks);
        println("EM7455_PACKED_VERIFY=PASS");
    }
}
