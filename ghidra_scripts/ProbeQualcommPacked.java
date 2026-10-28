// Probe Qualcomm packed segments without assuming a specific firmware image.
// Reports what the generic q6zip/zlib/CLADE analyzers accept and what they create.
// @category VNAOLTE

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.mem.MemoryBlock;
import vnaolte.ghidra.q6zip.QualcommQ6ZipAnalyzer;
import vnaolte.ghidra.qcom.QualcommZlibDebugOverlayAnalyzer;
import vnaolte.ghidra.qcom.QualcommCladeMappingAnalyzer;

public class ProbeQualcommPacked extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) throw new IllegalStateException("No current program");

        MessageLog qlog = new MessageLog();
        MessageLog zlog = new MessageLog();
        QualcommQ6ZipAnalyzer q = new QualcommQ6ZipAnalyzer();
        QualcommZlibDebugOverlayAnalyzer z = new QualcommZlibDebugOverlayAnalyzer();
        QualcommCladeMappingAnalyzer c = new QualcommCladeMappingAnalyzer();

        boolean qok = !q.canAnalyze(currentProgram) || q.added(currentProgram,
            currentProgram.getMemory().getLoadedAndInitializedAddressSet(), monitor, qlog);
        boolean zok = !z.canAnalyze(currentProgram) || z.added(currentProgram,
            currentProgram.getMemory().getLoadedAndInitializedAddressSet(), monitor, zlog);
        MessageLog clog = new MessageLog();
        boolean cok = !c.canAnalyze(currentProgram) || c.added(currentProgram,
            currentProgram.getMemory().getLoadedAndInitializedAddressSet(), monitor, clog);

        println("PACKED_PROBE_Q6ZIP_OK=" + qok);
        if (!qlog.toString().isBlank()) println(qlog.toString());
        println("PACKED_PROBE_ZLIB_OK=" + zok);
        if (!zlog.toString().isBlank()) println(zlog.toString());
        println("PACKED_PROBE_CLADE_OK=" + cok);
        if (!clog.toString().isBlank()) println(clog.toString());

        int qblocks = 0, zblocks = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (b.getName().startsWith("q6zip_")) {
                qblocks++;
                println("PACKED_PROBE_Q6ZIP_BLOCK=" + b.getName() + " " + b.getStart() + ".." + b.getEnd() +
                    " size=0x" + Long.toHexString(b.getSize()) + " overlay=" + b.isOverlay());
            }
            if (b.getName().startsWith("qcom_zlib_debug_")) {
                zblocks++;
                println("PACKED_PROBE_ZLIB_BLOCK=" + b.getName() + " " + b.getStart() + ".." + b.getEnd() +
                    " size=0x" + Long.toHexString(b.getSize()) + " overlay=" + b.isOverlay());
            }
        }

        int rfBookmarks = 0;
        int cladeBookmarks = 0;
        var it = currentProgram.getBookmarkManager().getBookmarksIterator();
        while (it.hasNext()) {
            Bookmark b = it.next();
            String category = b.getCategory();
            if (category != null && category.startsWith("VNAOLTE/")) rfBookmarks++;
            if ("VNAOLTE/Qualcomm CLADE".equals(category)) cladeBookmarks++;
        }
        println("PACKED_PROBE_SUMMARY q6zip_blocks=" + qblocks + " zlib_blocks=" + zblocks +
            " clade_bookmarks=" + cladeBookmarks + " vnaolte_bookmarks=" + rfBookmarks);
    }
}
