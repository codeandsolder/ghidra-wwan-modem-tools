// Run the VNAOLTE q6zip decompressor explicitly on an already-created program.
// @category VNAOLTE

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import vnaolte.ghidra.q6zip.QualcommQ6ZipAnalyzer;

public class RunVnaolteQ6zip extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No current program");
        }
        MessageLog log = new MessageLog();
        QualcommQ6ZipAnalyzer analyzer = new QualcommQ6ZipAnalyzer();
        if (!analyzer.canAnalyze(currentProgram)) {
            throw new IllegalStateException("VNAOLTE q6zip analyzer does not support " + currentProgram.getLanguageID());
        }
        boolean ok = analyzer.added(currentProgram,
            currentProgram.getMemory().getLoadedAndInitializedAddressSet(), monitor, log);
        println("VNAOLTE q6zip: " + (ok ? "OK" : "FAILED"));
        println(log.toString());
        currentProgram.getMemory().getBlocks();
    }
}
