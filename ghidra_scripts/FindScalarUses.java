// Find instruction operands that use selected scalar/immediate values.
// Args: output.md [--context=N] [--range=START:END] VALUE [...]
//@category VNAOLTE

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;

public class FindScalarUses extends GhidraScript {
    private record Hit(Instruction instruction, Function function, int operand, long value) {}

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: OUTPUT.md [--context=N] [--range=START:END] VALUE [...]");
        }
        Path output = Path.of(args[0]);
        int context = 0;
        Long rangeStart = null;
        Long rangeEnd = null;
        LinkedHashMap<Long, List<Hit>> hits = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--context=")) {
                context = Integer.parseInt(arg.substring("--context=".length()));
                if (context < 0 || context > 32) throw new IllegalArgumentException("context must be 0..32");
                continue;
            }
            if (arg.startsWith("--range=")) {
                String[] parts = arg.substring("--range=".length()).split(":", -1);
                if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
                    throw new IllegalArgumentException("range must be START:END");
                }
                rangeStart = parseHexAddress(parts[0]);
                rangeEnd = parseHexAddress(parts[1]);
                if (Long.compareUnsigned(rangeStart, rangeEnd) > 0) {
                    throw new IllegalArgumentException("range start must not exceed end");
                }
                continue;
            }
            long value = parseValue(arg);
            hits.putIfAbsent(value, new ArrayList<>());
        }
        if (hits.isEmpty()) throw new IllegalArgumentException("at least one scalar is required");

        var listing = currentProgram.getListing();
        var startAddress = rangeStart == null
            ? currentProgram.getMinAddress()
            : currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(rangeStart);
        var it = listing.getInstructions(startAddress, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction ins = it.next();
            long at = ins.getAddress().getOffset();
            if (rangeEnd != null && Long.compareUnsigned(at, rangeEnd) > 0) break;
            for (int op = 0; op < ins.getNumOperands(); op++) {
                for (Object obj : ins.getOpObjects(op)) {
                    if (!(obj instanceof Scalar scalar)) continue;
                    long unsigned = scalar.getUnsignedValue();
                    long signed = scalar.getSignedValue();
                    for (long wanted : hits.keySet()) {
                        if (unsigned == wanted || signed == wanted) {
                            hits.get(wanted).add(new Hit(ins, getFunctionContaining(ins.getAddress()), op, unsigned));
                        }
                    }
                }
            }
        }

        Files.createDirectories(output.toAbsolutePath().getParent());
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(output))) {
            out.println("# Scalar/immediate uses — " + currentProgram.getName());
            out.println();
            out.println("Language: `" + currentProgram.getLanguageID() + "`");
            out.println();
            for (var entry : hits.entrySet()) {
                out.printf("## `0x%x`%n%n", entry.getKey());
                if (entry.getValue().isEmpty()) {
                    out.println("No instruction operand found.");
                    out.println();
                    continue;
                }
                for (Hit hit : entry.getValue()) {
                    Function f = hit.function();
                    String fn = f == null ? "<outside function>" : "`" + f.getName() + "` @ `" + f.getEntryPoint() + "`";
                    out.println("- `" + hit.instruction().getAddress() + "` — operand " + hit.operand() + " — " + fn + " — `" + hit.instruction() + "`");
                    if (context > 0) printContext(out, hit.instruction(), context);
                }
                out.println();
            }
        }
        println("FIND_SCALAR_USES_REPORT=" + output.toAbsolutePath());
    }

    private static long parseValue(String text) {
        String s = text.trim().toLowerCase(Locale.ROOT);
        boolean negative = s.startsWith("-");
        if (negative) s = s.substring(1);
        int radix = s.startsWith("0x") ? 16 : 10;
        if (radix == 16) s = s.substring(2);
        long value = Long.parseUnsignedLong(s, radix);
        return negative ? -value : value;
    }

    private static long parseHexAddress(String text) {
        String s = text.trim().toLowerCase(Locale.ROOT).replaceFirst("^0x", "");
        return Long.parseUnsignedLong(s, 16);
    }

    private void printContext(PrintWriter out, Instruction center, int radius) {
        var listing = currentProgram.getListing();
        List<Instruction> before = new ArrayList<>();
        Instruction cursor = center;
        Instruction prev = cursor;
        for (int i = 0; i < radius; i++) {
            prev = listing.getInstructionBefore(prev.getAddress());
            if (prev == null) break;
            before.add(prev);
        }
        Collections.reverse(before);
        out.println();
        out.println("```asm");
        for (Instruction ins : before) out.println(ins.getAddress() + "  " + ins);
        out.println(cursor.getAddress() + "  " + cursor + "    ; <-- use");
        Instruction next = cursor;
        for (int i = 0; i < radius; i++) {
            next = listing.getInstructionAfter(next.getAddress());
            if (next == null) break;
            out.println(next.getAddress() + "  " + next);
        }
        out.println("```");
    }
}
