// Find code uses of absolute addresses, including ARM MOVW/MOVT split-immediate loads.
// Args: output.md [--context=N] [--alias-radius=N] [--range=START:END:STEP] ADDRESS [...]
//@category VNAOLTE

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

public class FindAddressUses extends GhidraScript {
    private record Use(Address at, String kind, String detail, Function function) {}
    private record MovHalf(Address at, int value, Function function, long ordinal) {}

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException("usage: OUTPUT.md [--context=N] [--alias-radius=N] [--range=START:END:STEP] ADDRESS [...]");
        }

        Path output = Path.of(args[0]);
        int context = 0;
        int aliasRadius = 4;
        Map<Long, Address> targets = new LinkedHashMap<>();
        for (int i = 1; i < args.length; i++) {
            if (args[i].startsWith("--context=")) {
                context = Integer.parseInt(args[i].substring("--context=".length()));
                if (context < 0 || context > 32) throw new IllegalArgumentException("context must be 0..32");
                continue;
            }
            if (args[i].startsWith("--alias-radius=")) {
                aliasRadius = Integer.parseInt(args[i].substring("--alias-radius=".length()));
                if (aliasRadius < 0 || aliasRadius > 64) throw new IllegalArgumentException("alias radius must be 0..64");
                continue;
            }
            if (args[i].startsWith("--range=")) {
                String[] parts = args[i].substring("--range=".length()).split(":");
                if (parts.length != 3) throw new IllegalArgumentException("range must be START:END:STEP");
                long start = parseHexAddress(parts[0]);
                long end = parseHexAddress(parts[1]);
                long step = parseHexAddress(parts[2]);
                if (step <= 0 || Long.compareUnsigned(start, end) > 0) {
                    throw new IllegalArgumentException("invalid address range");
                }
                long count = Long.divideUnsigned(end - start, step) + 1;
                if (count > 4096) throw new IllegalArgumentException("range exceeds 4096 addresses");
                for (long value = start; Long.compareUnsigned(value, end) <= 0; value += step) {
                    Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
                    targets.put(address.getOffset(), address);
                    if (Long.compareUnsigned(value, end - step) > 0) break;
                }
                continue;
            }
            long value = parseHexAddress(args[i]);
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(value);
            targets.put(address.getOffset(), address);
        }

        // Diagnostic strings in these modem images often have a one-byte log-level prefix
        // immediately before the printable text. By default search a tiny neighborhood around
        // each requested address. Use --alias-radius=0 for adjacent MMIO/register addresses.
        Map<Long, Set<Long>> aliases = new HashMap<>();
        for (long target : targets.keySet()) {
            for (long delta = -aliasRadius; delta <= aliasRadius; delta++) {
                aliases.computeIfAbsent(target + delta, ignored -> new LinkedHashSet<>()).add(target);
            }
        }
        if (targets.isEmpty()) throw new IllegalArgumentException("at least one address is required");
        Map<Long, List<Use>> uses = new LinkedHashMap<>();
        for (long target : targets.keySet()) uses.put(target, new ArrayList<>());

        Map<String, MovHalf> lastMovw = new HashMap<>();
        long ordinal = 0;
        var it = currentProgram.getListing().getInstructions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction ins = it.next();
            ordinal++;
            Function function = getFunctionContaining(ins.getAddress());

            for (Reference ref : ins.getReferencesFrom()) {
                long off = ref.getToAddress().getOffset();
                Set<Long> requestedTargets = aliases.get(off);
                if (requestedTargets != null) {
                    for (long requested : requestedTargets) {
                        uses.get(requested).add(new Use(ins.getAddress(), "reference to " +
                            currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(off),
                            ins.toString(), function));
                    }
                }
            }

            String mnemonic = ins.getMnemonicString().toLowerCase(Locale.ROOT);
            if (!mnemonic.equals("movw") && !mnemonic.equals("movt")) continue;
            Register reg = null;
            Integer imm = null;
            for (int op = 0; op < ins.getNumOperands(); op++) {
                for (Object obj : ins.getOpObjects(op)) {
                    if (obj instanceof Register r && reg == null) reg = r;
                    if (obj instanceof Scalar s) imm = (int)(s.getUnsignedValue() & 0xffffL);
                }
            }
            if (reg == null || imm == null) continue;
            String key = (function == null ? "<none>" : function.getEntryPoint().toString()) + ":" + reg.getName();
            if (mnemonic.equals("movw")) {
                lastMovw.put(key, new MovHalf(ins.getAddress(), imm, function, ordinal));
                continue;
            }
            MovHalf lo = lastMovw.get(key);
            if (lo == null || ordinal - lo.ordinal() > 12) continue;
            long combined = ((long)imm << 16) | (lo.value() & 0xffffL);
            Set<Long> requestedTargets = aliases.get(combined);
            if (requestedTargets != null) {
                String detail = lo.at() + " `" + currentProgram.getListing().getInstructionAt(lo.at()) + "` → " +
                    ins.getAddress() + " `" + ins + "` = " +
                    currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(combined);
                for (long requested : requestedTargets) {
                    uses.get(requested).add(new Use(ins.getAddress(), "MOVW/MOVT", detail, function));
                }
            }
        }

        Files.createDirectories(output.toAbsolutePath().getParent());
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(output))) {
            out.println("# Absolute address uses — " + currentProgram.getName());
            out.println();
            out.println("Language: `" + currentProgram.getLanguageID() + "`");
            out.println();
            for (var entry : targets.entrySet()) {
                long target = entry.getKey();
                out.println("## `" + entry.getValue() + "`");
                out.println();
                List<Use> found = uses.get(target);
                if (found.isEmpty()) {
                    out.println("No direct reference or nearby ARM MOVW/MOVT construction found.");
                    out.println();
                    continue;
                }
                found.sort(Comparator.comparing(Use::at));
                for (Use use : found) {
                    String fn = use.function() == null ? "<outside function>" :
                        "`" + use.function().getName() + "` @ `" + use.function().getEntryPoint() + "`";
                    out.println("- `" + use.at() + "` — " + use.kind() + " — " + fn + " — " + use.detail());
                    if (context > 0) printContext(out, use.at(), context);
                }
                out.println();
            }
        }
        println("FIND_ADDRESS_USES_REPORT=" + output.toAbsolutePath());
    }
    private static long parseHexAddress(String text) {
        return Long.parseUnsignedLong(text.replaceFirst("(?i)^0x", ""), 16);
    }

    private void printContext(PrintWriter out, Address center, int radius) {
        var listing = currentProgram.getListing();
        List<Instruction> before = new ArrayList<>();
        Instruction cursor = listing.getInstructionAt(center);
        if (cursor == null) cursor = listing.getInstructionContaining(center);
        if (cursor == null) return;
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
