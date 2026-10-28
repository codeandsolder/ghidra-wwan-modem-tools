// Emulate GCT/GDM7243 PAM profile constructors and dump their 0x22-byte output.
// Args: OUTPUT.md [--freq=LABEL:KHZ ...] PAM_ID:THUMB_FUNCTION [...]
//@category VNAOLTE

import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;

public class DumpGctPamProfiles extends GhidraScript {
    private static final long PAM_IDENTITY_TABLE = 0xD56AC6E8L;
    private static final int PAM_IDENTITY_STRIDE = 6;
    private static final int PROFILE_SIZE = 0x22;
    private static final long SCRATCH_BASE = 0xD56E0000L;
    private static final long STACK_POINTER = SCRATCH_BASE + 0x2000;
    private static final long DESTINATION = SCRATCH_BASE + 0x3000;
    private static final long RETURN_SENTINEL = 0xD5100000L;
    private static final int MAX_STEPS = 200_000;
    private static final long MEMCPY = 0xD5115CE0L;
    private static final long MEMSET = 0xD5116300L;

    private record PamSpec(int id, Address entry) {}
    private record FreqSpec(String label, long khz) {}
    private record Result(PamSpec pam, FreqSpec freq, byte[] profile, int steps) {}

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            throw new IllegalArgumentException(
                "usage: OUTPUT.md [--freq=LABEL:KHZ ...] PAM_ID:THUMB_FUNCTION [...]");
        }

        Path output = Path.of(args[0]);
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        List<FreqSpec> freqs = new ArrayList<>();
        List<PamSpec> pams = new ArrayList<>();

        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("--freq=")) {
                String spec = arg.substring("--freq=".length());
                int colon = spec.lastIndexOf(58);
                if (colon <= 0 || colon == spec.length() - 1) {
                    throw new IllegalArgumentException("frequency must be LABEL:KHZ: " + spec);
                }
                freqs.add(new FreqSpec(spec.substring(0, colon), Long.parseLong(spec.substring(colon + 1))));
                continue;
            }
            int colon = arg.indexOf(58);
            if (colon <= 0 || colon == arg.length() - 1) {
                throw new IllegalArgumentException("PAM must be ID:ADDRESS: " + arg);
            }
            int id = Integer.parseInt(arg.substring(0, colon));
            long raw = parseHex(arg.substring(colon + 1));
            if ((raw & 1L) != 0) raw &= ~1L;
            pams.add(new PamSpec(id, space.getAddress(raw)));
        }

        if (pams.isEmpty()) throw new IllegalArgumentException("at least one PAM constructor is required");
        if (freqs.isEmpty()) {
            freqs.addAll(List.of(
                new FreqSpec("low", 700_000),
                new FreqSpec("lb", 900_000),
                new FreqSpec("mb-low", 1_700_000),
                new FreqSpec("mb-high", 1_900_000),
                new FreqSpec("hb-low", 2_300_000),
                new FreqSpec("hb", 2_500_000),
                new FreqSpec("uhb-edge", 2_600_000)));
        }

        List<Result> results = new ArrayList<>();
        for (PamSpec pam : pams) {
            for (FreqSpec freq : freqs) {
                monitor.checkCancelled();
                results.add(emulate(pam, freq, space));
            }
        }

        Files.createDirectories(output.toAbsolutePath().getParent());
        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(output))) {
            out.println("# GCT PAM profiles — " + currentProgram.getName());
            out.println();
            out.println("Language: `" + currentProgram.getLanguageID() + "`");
            out.println();
            out.println("Profile bytes are the exact 0x22-byte constructor outputs for each frequency sample.");
            out.println();

            for (PamSpec pam : pams) {
                byte[] identity = readIdentity(pam.id(), space);
                out.printf(Locale.ROOT,
                    "## PAM %d @ `%s` — default USID `0x%02x`, product `0x%02x`, manufacturer `0x%02x`%n%n",
                    pam.id(), pam.entry(), u8(identity[2]), u8(identity[4]), u8(identity[5]));
                out.println("| label | kHz | registers | bank 0 | bank 1 | bank 2 | bank 3 | raw profile |");
                out.println("|---|---:|---|---|---|---|---|---|");
                for (Result result : results) {
                    if (result.pam().id() != pam.id()) continue;
                    byte[] profile = result.profile();
                    out.printf(Locale.ROOT, "| %s | %d | `%s` | %s | %s | %s | %s | `%s` |%n",
                        result.freq().label(), result.freq().khz(), registerList(profile),
                        bankPairs(profile, 0), bankPairs(profile, 1), bankPairs(profile, 2), bankPairs(profile, 3),
                        hex(profile));
                }
                out.println();
            }

            out.println("## Pairwise differences at each frequency");
            out.println();
            for (FreqSpec freq : freqs) {
                out.println("### " + freq.label() + " — " + freq.khz() + " kHz");
                out.println();
                for (int i = 0; i < pams.size(); i++) {
                    for (int j = i + 1; j < pams.size(); j++) {
                        Result a = find(results, pams.get(i).id(), freq.label());
                        Result b = find(results, pams.get(j).id(), freq.label());
                        out.printf("- PAM %d vs %d: %s%n", a.pam().id(), b.pam().id(), differences(a.profile(), b.profile()));
                    }
                }
                out.println();
            }
        }
        println("DUMP_GCT_PAM_PROFILES=" + output.toAbsolutePath());
    }

    private Result emulate(PamSpec pam, FreqSpec freq, AddressSpace space) throws Exception {
        Address scratch = space.getAddress(SCRATCH_BASE);
        Address dest = space.getAddress(DESTINATION);
        Address sentinel = space.getAddress(RETURN_SENTINEL);

        EmulatorHelper emu = new EmulatorHelper(currentProgram);
        try {
            emu.writeMemory(scratch, new byte[0x4000]);
            emu.writeRegister("sp", STACK_POINTER);
            emu.writeRegister("lr", RETURN_SENTINEL | 1L);
            emu.writeRegister("r0", freq.khz());
            emu.writeRegister("r1", DESTINATION);
            emu.writeRegister("pc", pam.entry().getOffset());
            for (String reg : List.of("r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "CY", "ZR", "NG", "OV")) {
                try { emu.writeRegister(reg, 0); } catch (RuntimeException ignored) { }
            }

            Register tmode = currentProgram.getLanguage().getRegister("TMode");
            if (tmode != null) emu.setContextRegister(tmode, BigInteger.ONE);
            Register itmode = currentProgram.getLanguage().getRegister("itmode");
            if (itmode != null) emu.setContextRegister(itmode, BigInteger.ZERO);

            int steps = 0;
            while (steps < MAX_STEPS) {
                Address pc = emu.getExecutionAddress();
                if (pc != null && pc.equals(sentinel)) break;

                Instruction ins = pc == null ? null : currentProgram.getListing().getInstructionAt(pc);
                if (ins == null) {
                    throw new IllegalStateException("no instruction for PAM " + pam.id() + " at pc=" + pc);
                }
                if (simulateHelperCall(emu, ins, space) || simulateReturn(emu, ins)) {
                    steps++;
                    continue;
                }
                if (!emu.step(monitor)) {
                    throw new IllegalStateException("emulation failed for PAM " + pam.id() + " at " + freq.khz() +
                        " kHz, pc=" + emu.getExecutionAddress() + ": " + emu.getLastError());
                }
                Register forceThumb = currentProgram.getLanguage().getRegister("TMode");
                if (forceThumb != null) emu.setContextRegister(forceThumb, BigInteger.ONE);
                steps++;
            }
            if (steps >= MAX_STEPS) {
                throw new IllegalStateException("step limit exceeded for PAM " + pam.id() + " at " + freq.khz());
            }
            return new Result(pam, freq, emu.readMemory(dest, PROFILE_SIZE), steps);
        } finally {
            emu.dispose();
        }
    }


    private boolean simulateHelperCall(EmulatorHelper emu, Instruction ins, AddressSpace space) throws Exception {
        Address[] flows = ins.getFlows();
        if (flows.length != 1) return false;
        long target = flows[0].getOffset();
        if (target != MEMCPY && target != MEMSET) return false;

        int length = PROFILE_SIZE;
        long dstValue = emu.readRegister("r0").longValue();
        Address dst = space.getAddress(dstValue);
        if (target == MEMSET) {
            byte[] data = new byte[length];
            emu.writeMemory(dst, data);
        } else {
            Address src = space.getAddress(emu.readRegister("r1").longValue());
            emu.writeMemory(dst, emu.readMemory(src, length));
        }
        Address fallThrough = ins.getFallThrough();
        if (fallThrough == null) throw new IllegalStateException("helper call has no fall-through at " + ins.getAddress());
        emu.writeRegister("lr", fallThrough.getOffset() | 1L);
        emu.writeRegister("pc", fallThrough.getOffset());
        Register tmode = currentProgram.getLanguage().getRegister("TMode");
        if (tmode != null) emu.setContextRegister(tmode, BigInteger.ONE);
        return true;
    }

    private boolean simulateReturn(EmulatorHelper emu, Instruction ins) {
        String mnemonic = ins.getMnemonicString().toLowerCase(Locale.ROOT);
        String text = ins.toString().toLowerCase(Locale.ROOT);
        if ((mnemonic.startsWith("pop") && text.contains("pc")) ||
            (mnemonic.equals("bx") && text.contains("lr"))) {
            emu.writeRegister("pc", RETURN_SENTINEL);
            Register tmode = currentProgram.getLanguage().getRegister("TMode");
            if (tmode != null) emu.setContextRegister(tmode, BigInteger.ONE);
            return true;
        }
        return false;
    }

    private byte[] readIdentity(int pamId, AddressSpace space) throws Exception {
        Address at = space.getAddress(PAM_IDENTITY_TABLE + (long)pamId * PAM_IDENTITY_STRIDE);
        byte[] row = new byte[PAM_IDENTITY_STRIDE];
        int read = currentProgram.getMemory().getBytes(at, row);
        if (read != row.length) throw new IllegalStateException("short identity-table read at " + at);
        return row;
    }

    private static Result find(List<Result> results, int pamId, String label) {
        return results.stream().filter(r -> r.pam().id() == pamId && r.freq().label().equals(label)).findFirst().orElseThrow();
    }

    private static int u8(byte value) { return value & 0xff; }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append(String.format(Locale.ROOT, "%02x", u8(b)));
        return sb.toString();
    }

    private static String registerList(byte[] profile) {
        List<String> registers = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            registers.add(String.format(Locale.ROOT, "0x%02x", u8(profile[i])));
        }
        return String.join(",", registers);
    }

    private static String bankPairs(byte[] profile, int bank) {
        int count = Math.min(u8(profile[0x1e + bank]), 6);
        List<String> pairs = new ArrayList<>();
        int values = 6 + bank * 6;
        for (int i = 0; i < count; i++) {
            pairs.add(String.format(Locale.ROOT, "r%02x=%02x", u8(profile[i]), u8(profile[values + i])));
        }
        return "`n=" + count + " " + String.join(" ", pairs) + "`";
    }

    private static String differences(byte[] a, byte[] b) {
        List<String> values = new ArrayList<>();
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            if (a[i] != b[i]) {
                values.add(String.format(Locale.ROOT, "+0x%02x 0x%02x→0x%02x", i, u8(a[i]), u8(b[i])));
            }
        }
        return values.isEmpty() ? "identical" : String.join(", ", values);
    }

    private static long parseHex(String text) {
        return Long.parseUnsignedLong(text.replaceFirst("(?i)^0x", ""), 16);
    }
}
