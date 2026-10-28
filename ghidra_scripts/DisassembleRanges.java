// Dump bounded disassembly ranges into a compact Markdown report.
// Args: output.md [--max=N] START:END [START:END ...]
// Addresses are hexadecimal, with optional 0x prefix.
// @category VNAOLTE

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;

public class DisassembleRanges extends GhidraScript {
    private record Range(Address start, Address end) {}

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: OUTPUT.md [--max=N] START:END [START:END ...]");
        }

        Path output = Path.of(args[0]);
        int maxInstructions = 4096;
        List<Range> ranges = new ArrayList<>();

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--max=")) {
                maxInstructions = Integer.parseInt(arg.substring("--max=".length()));
                if (maxInstructions < 1 || maxInstructions > 100000) {
                    throw new IllegalArgumentException("max must be 1..100000");
                }
                continue;
            }

            String[] parts = arg.split(":", -1);
            if (parts.length != 2) {
                throw new IllegalArgumentException("range must be START:END: " + arg);
            }
            Address start = address(parts[0]);
            Address end = address(parts[1]);
            if (start.compareTo(end) > 0) {
                throw new IllegalArgumentException("range start is after end: " + arg);
            }
            ranges.add(new Range(start, end));
        }
        if (ranges.isEmpty()) throw new IllegalArgumentException("at least one range is required");

        Files.createDirectories(output.toAbsolutePath().getParent());
        Listing listing = currentProgram.getListing();
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(output))) {
            out.println("# Bounded disassembly — " + currentProgram.getName());
            out.println();
            out.println("Language: `" + currentProgram.getLanguageID() + "`");
            out.println();

            for (Range range : ranges) {
                monitor.checkCancelled();
                out.println("## `" + range.start() + ":" + range.end() + "`");
                out.println();

                Function atStart = getFunctionContaining(range.start());
                Function atEnd = getFunctionContaining(range.end());
                out.println("Start function: " + functionLabel(atStart));
                out.println();
                if (atEnd != atStart) {
                    out.println("End function: " + functionLabel(atEnd));
                    out.println();
                }

                out.println("```asm");
                int emitted = 0;
                Instruction ins = listing.getInstructionAt(range.start());
                if (ins == null) ins = listing.getInstructionAfter(range.start());
                while (ins != null && ins.getAddress().compareTo(range.end()) <= 0 &&
                       emitted < maxInstructions) {
                    monitor.checkCancelled();
                    Function f = getFunctionContaining(ins.getAddress());
                    String label = "";
                    if (f != null && ins.getAddress().equals(f.getEntryPoint())) {
                        label = "    ; <" + f.getName() + ">";
                    }
                    out.println(ins.getAddress() + "  " + ins + label);
                    emitted++;
                    ins = listing.getInstructionAfter(ins.getAddress());
                }
                if (emitted == maxInstructions && ins != null &&
                    ins.getAddress().compareTo(range.end()) <= 0) {
                    out.println("; ... truncated after " + maxInstructions + " instructions");
                }
                if (emitted == 0) out.println("; no defined instructions in range");
                out.println("```");
                out.println();
            }
        }
        println("DISASSEMBLY_RANGES_REPORT=" + output.toAbsolutePath());
    }

    private Address address(String text) {
        long value = Long.parseUnsignedLong(text.replaceFirst("(?i)^0x", ""), 16);
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
    }

    private static String functionLabel(Function function) {
        if (function == null) return "`<outside function>`";
        return "`" + function.getName() + "` @ `" + function.getEntryPoint() + "`";
    }
}
