// Decompile functions by exact name or address into a compact Markdown report.
// Args: output path name-or-address [name-or-address ...]
// Prefix an address with @ or pass a normal 0x.../hex address.
// @category VNAOLTE

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DecompileFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: OUTPUT.md NAME_OR_ADDRESS [NAME_OR_ADDRESS ...]");
        }
        Path outPath = Path.of(args[0]);
        Files.createDirectories(outPath.toAbsolutePath().getParent());
        FunctionManager fm = currentProgram.getFunctionManager();
        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(outPath))) {
            out.println("# Function decompilation — " + currentProgram.getName());
            out.println();
            out.println("Language: `" + currentProgram.getLanguageID() + "`");
            out.println();
            for (int i = 1; i < args.length; i++) {
                String query = args[i];
                Function f = resolve(fm, query);
                out.println("## `" + query.replace("`", "'") + "`");
                out.println();
                if (f == null) {
                    out.println("Not found.");
                    out.println();
                    continue;
                }
                out.println("Resolved: `" + f.getName() + "` @ `" + f.getEntryPoint() + "`");
                out.println();
                Set<Function> callers = f.getCallingFunctions(monitor);
                Set<Function> callees = f.getCalledFunctions(monitor);
                out.println("### Callers");
                out.println();
                if (callers.isEmpty()) out.println("- none resolved");
                else callers.stream().sorted(Comparator.comparing(Function::getEntryPoint)).limit(120)
                    .forEach(x -> out.println("- `" + x.getEntryPoint() + "` `" + x.getName() + "`"));
                out.println();
                out.println("### Callees");
                out.println();
                if (callees.isEmpty()) out.println("- none resolved");
                else callees.stream().sorted(Comparator.comparing(Function::getEntryPoint)).limit(160)
                    .forEach(x -> out.println("- `" + x.getEntryPoint() + "` `" + x.getName() + "`"));
                out.println();
                out.println("### Decompile");
                out.println();
                DecompileResults r = decomp.decompileFunction(f, 60, monitor);
                if (r.decompileCompleted() && r.getDecompiledFunction() != null) {
                    out.println("```c");
                    out.print(r.getDecompiledFunction().getC());
                    if (!r.getDecompiledFunction().getC().endsWith("\n")) out.println();
                    out.println("```");
                } else {
                    out.println("Decompiler failed: `" + safe(r.getErrorMessage()) + "`");
                }
                out.println();
            }
        } finally {
            decomp.dispose();
        }
        println("DECOMPILE_FUNCTIONS_REPORT=" + outPath.toAbsolutePath());
    }

    private Function resolve(FunctionManager fm, String query) {
        String q = query.startsWith("@") ? query.substring(1) : query;
        if (q.matches("(?i)(0x)?[0-9a-f]{6,16}")) {
            try {
                long value = Long.parseUnsignedLong(q.replaceFirst("(?i)^0x", ""), 16);
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                Function f = fm.getFunctionAt(a);
                return f != null ? f : fm.getFunctionContaining(a);
            } catch (RuntimeException ignored) {
            }
        }
        for (Function candidate : fm.getFunctions(true)) {
            if (candidate.getName().equals(query)) return candidate;
        }
        return null;
    }

    private static String safe(String s) {
        return s == null ? "" : s.replace("`", "'");
    }
}
