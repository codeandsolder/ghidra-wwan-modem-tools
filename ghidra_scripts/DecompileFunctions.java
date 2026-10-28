// Decompile functions by exact name or address into a compact Markdown report.
// Args: output path [--no-decompile] [--timeout=N] [--asm-limit=N] name-or-address [...]
// Prefix an address with @ or pass a normal 0x.../hex address.
// Use thumb:ADDRESS (or an odd Thumb function pointer) to force ARM Thumb mode.
// @category VNAOLTE

import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Listing;

public class DecompileFunctions extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: OUTPUT.md NAME_OR_ADDRESS [NAME_OR_ADDRESS ...]");
        }
        Path outPath = Path.of(args[0]);
        Files.createDirectories(outPath.toAbsolutePath().getParent());
        boolean doDecompile = true;
        int timeoutSeconds = 60;
        int asmLimit = 400;
        java.util.List<String> queries = new java.util.ArrayList<>();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--no-decompile")) doDecompile = false;
            else if (arg.startsWith("--timeout=")) timeoutSeconds = Integer.parseInt(arg.substring(10));
            else if (arg.startsWith("--asm-limit=")) asmLimit = Integer.parseInt(arg.substring(12));
            else queries.add(arg);
        }
        if (queries.isEmpty()) throw new IllegalArgumentException("at least one function query is required");
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
            for (String query : queries) {
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
                out.println("### Assembly");
                out.println();
                out.println("```asm");
                int emitted = 0;
                var instructions = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (instructions.hasNext() && emitted < asmLimit) {
                    var ins = instructions.next();
                    out.println(ins.getAddress() + "  " + ins);
                    emitted++;
                }
                if (instructions.hasNext()) out.println("; ... truncated after " + asmLimit + " instructions");
                out.println("```");
                out.println();
                if (doDecompile) {
                    out.println("### Decompile");
                    out.println();
                    DecompileResults r = decomp.decompileFunction(f, timeoutSeconds, monitor);
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
            }
        } finally {
            decomp.dispose();
        }
        println("DECOMPILE_FUNCTIONS_REPORT=" + outPath.toAbsolutePath());
    }

    private Function resolve(FunctionManager fm, String query) throws Exception {
        String q = query.startsWith("@") ? query.substring(1) : query;
        boolean forceThumbMode = q.regionMatches(true, 0, "thumb:", 0, 6);
        if (forceThumbMode) q = q.substring(6);
        if (q.matches("(?i)(0x)?[0-9a-f]{6,16}")) {
            try {
                long value = Long.parseUnsignedLong(q.replaceFirst("(?i)^0x", ""), 16);
                boolean thumbPointer = (value & 1L) != 0;
                boolean thumbMode = forceThumbMode || thumbPointer;
                long codeValue = thumbPointer ? value & ~1L : value;
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(codeValue);
                if (thumbMode) forceThumb(a);

                Function f = fm.getFunctionAt(a);
                if (f != null) return f;
                f = fm.getFunctionContaining(a);
                if (f != null) return f;

                // Exact-address queries are often recovered from command tables before
                // Ghidra has discovered a function boundary. Make that workflow durable:
                // disassemble at the requested entry and create the function if possible.
                disassemble(a);
                Function created = createFunction(a, null);
                if (created != null) return created;
                f = fm.getFunctionAt(a);
                return f != null ? f : fm.getFunctionContaining(a);
            } catch (RuntimeException ignored) {
            }
        }
        for (Function candidate : fm.getFunctions(true)) {
            if (candidate.getName().equals(query)) return candidate;
        }
        return null;
    }


    private void forceThumb(Address address) throws Exception {
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");
        if (tmode == null) return;
        BigInteger current = currentProgram.getProgramContext().getValue(tmode, address, false);
        if (BigInteger.ONE.equals(current)) return;

        Listing listing = currentProgram.getListing();
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        if (function != null) {
            currentProgram.getFunctionManager().removeFunction(address);
        }
        CodeUnit unit = listing.getCodeUnitContaining(address);
        if (unit != null) {
            clearListing(unit.getMinAddress(), unit.getMaxAddress());
        }
        currentProgram.getProgramContext().setValue(tmode, address, address, BigInteger.ONE);
    }

    private static String safe(String s) {
        return s == null ? "" : s.replace("`", "'");
    }
}
