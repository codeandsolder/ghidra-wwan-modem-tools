// Run the VNAOLTE RF analyzer explicitly on an already-created program.
// @category VNAOLTE

import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import vnaolte.ghidra.analysis.VnaolteRfAnalyzer;

public class RunVnaolteRfTriage extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("No current program");
        }
        MessageLog log = new MessageLog();
        VnaolteRfAnalyzer analyzer = new VnaolteRfAnalyzer();
        if (!analyzer.canAnalyze(currentProgram)) {
            throw new IllegalStateException("VNAOLTE RF analyzer does not support " +
                currentProgram.getLanguageID());
        }
        boolean ok = analyzer.added(currentProgram,
            currentProgram.getMemory().getLoadedAndInitializedAddressSet(), monitor, log);
        println("VNAOLTE RF triage: " + (ok ? "OK" : "FAILED"));
        println(log.toString());
    }
}
