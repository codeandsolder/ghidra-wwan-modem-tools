// Survey GCT modem firmware for RF-chain, calibration, RFFE, loopback and IQ paths.
// Also recovers GCT command tables stored as big-endian data in BE8 firmware.
// Args: output Markdown path [max decompiled roots, default 96]
// @category VNAOLTE

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

public class GctRfSurvey extends GhidraScript {
    private record Topic(String name, String tag, String[] needles) {}
    private record Evidence(Address stringAddress, String text, Address refFrom) {}
    private enum CommandLayout { NAME_DESC_FLAGS_TARGET, TARGET_NAME_DESC_FLAGS }
    private record CommandRecord(Address tableAddress, CommandLayout layout, String name,
            String description, long flags, Address target, boolean functionTarget) {}
    private record CommandRun(Address start, CommandLayout layout, List<CommandRecord> records) {}

    private static final List<Topic> TOPICS = List.of(
        new Topic("LO / PLL / mixer", "VNAOLTE:GCT-PLL", new String[] {
            "setrfpllsel", "controlrfpll", "set_rf_pll", "rfpll", "set_rx_vco_lo_pll",
            "set_tx_vco_lo_pll", "rpll0", "rpll1", "tpll0", "tpll1", "mixer_0",
            "mixer_1", "mixer_2", "mixer_3", "mixer_4", "mixer_5", "mixer_6", "mixer_7",
            "pll locking", "pll_lock", "calc_pll", "set_tpll", "frequency setting"
        }),
        new Topic("ADC / DAC / ATE", "VNAOLTE:GCT-ATE", new String[] {
            "rx ate setting", "tx ate setting", "set_rx_adc_ant_mux_sel", "adc_copy_mode",
            "adc adaptor", "rxadc", "txdac", "dac1ctl", "dac2ctl", "rfm cal dac",
            "adc23_on", "rfm_change_adc", "rfm_suspend_adc23", "rfm_resume_adc23",
            "adc clock phase", "rtx ate"
        }),
        new Topic("Loopback / complex IQ", "VNAOLTE:GCT-IQ", new String[] {
            "pmuxloopback", "ciq_metric", "iq_put", "iq dump", "iq_dump", "iq capture",
            "iq_capture", "complex iq", "fft", "loopback", "corr_i", "corr_q",
            "multi-tone correl", "cal multi tone", "calpath", "cal path"
        }),
        new Topic("RFFE / switch / PA", "VNAOLTE:GCT-RFFE", new String[] {
            "rffe", "rfsw", "extlna", "rffe_pam", "rffe_sw", "mipi_pa", "pam gain",
            "rffe control board definition", "rffe_clk", "rffe_data", "rffe_vio",
            "band switch", "asd control"
        }),
        new Topic("RF calibration / AGC", "VNAOLTE:GCT-CAL", new String[] {
            "rfm cal", "giscalibration", "gisrxrfgcalibration", "fixagc", "rx_agc",
            "agc_mode_ctrl", "agc_gd", "rxcal", "tx cl calibration", "rx imb2 calibration",
            "rf gain", "afc-dac", "agc info", "afc info"
        }),
        new Topic("Power detector / measurement", "VNAOLTE:GCT-MEAS", new String[] {
            "powerdetectoradc", "pdetadc", "thadc", "average power", "adc power", "rssi",
            "cinr", "rsrp", "rsrq", "display rx power"
        }),
        new Topic("RF channel / bandwidth", "VNAOLTE:GCT-CHAN", new String[] {
            "_grf_cfg_chan", "setrfrxband", "setrftxband", "dlearfcn", "ulearfcn",
            "dlbw", "ulbw", "freq_khz", "rx_freq", "downlink frequency",
            "uplink frequency", "band setting", "bandwidth"
        })
    );

    private static final Set<String> PRIORITY_NEEDLES = Set.of(
        "pmuxloopback", "ciq_metric", "rx ate setting", "tx ate setting",
        "set_rx_adc_ant_mux_sel", "adc_copy_mode", "rfm cal dac", "powerdetectoradc",
        "pdetadc", "setrfpllsel", "controlrfpll", "set_rx_vco_lo_pll",
        "set_tx_vco_lo_pll", "_grf_cfg_chan", "rfm cal rfpll", "rfm rffe w",
        "rfm rffe r", "rfm_change_4rx_mode", "corr_i", "corr_q", "multi-tone correl"
    );

    private static final Set<String> PRIORITY_COMMANDS = Set.of(
        "-fft1", "-fft2", "-txt", "-rxirr", "-cpen", "-cpmen", "-cpden", "-cpdis",
        "-txcl", "-rximb2", "-ate", "-sfd", "-sfu", "-sf", "-rxp", "-txg", "-tx",
        "-cal", "-rffe", "-bandsw", "-test_fo", "-force_rx_path", "-adc_clock_phase",
        "-rfm"
    );

    private static final int MIN_COMMAND_RUN = 3;
    private static final int MAX_CSTRING = 240;

    private static final class Hit {
        final Function function;
        final Set<Topic> topics = new LinkedHashSet<>();
        final List<Evidence> evidence = new ArrayList<>();
        int score;
        Hit(Function function) { this.function = function; }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1 || args.length > 2) {
            throw new IllegalArgumentException("usage: GctRfSurvey.java OUTPUT.md [MAX_DECOMPILE]");
        }
        Path output = Path.of(args[0]);
        int maxDecompile = args.length == 2 ? Integer.parseInt(args[1]) : 96;

        Memory memory = currentProgram.getMemory();
        ReferenceManager refs = currentProgram.getReferenceManager();
        FunctionManager funcs = currentProgram.getFunctionManager();
        Map<Address, Hit> hits = new LinkedHashMap<>();
        List<String> matchingStrings = new ArrayList<>();
        int definedStrings = 0;
        int matchedStrings = 0;
        int matchedRefs = 0;
        int unresolvedRefs = 0;

        List<CommandRun> commandRuns = findCommandRuns(memory);
        List<CommandRecord> commands = new ArrayList<>();
        for (CommandRun run : commandRuns) {
            commands.addAll(run.records());
            for (CommandRecord command : run.records()) {
                annotateCommand(command, funcs);
            }
        }

        var dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            monitor.checkCancelled();
            definedStrings++;
            Object value = data.getValue();
            if (!(value instanceof String text) || text.isBlank()) continue;
            List<Topic> topics = topicsFor(text);
            if (topics.isEmpty()) continue;
            matchedStrings++;
            String compact = compact(text, 260);
            matchingStrings.add(data.getAddress() + "\t" + compact);

            ReferenceIterator rit = refs.getReferencesTo(data.getAddress());
            while (rit.hasNext()) {
                Reference ref = rit.next();
                matchedRefs++;
                Function f = funcs.getFunctionContaining(ref.getFromAddress());
                if (f == null) {
                    unresolvedRefs++;
                    continue;
                }
                Hit hit = hits.computeIfAbsent(f.getEntryPoint(), ignored -> new Hit(f));
                hit.topics.addAll(topics);
                if (hit.evidence.size() < 64) {
                    hit.evidence.add(new Evidence(data.getAddress(), compact, ref.getFromAddress()));
                }
                hit.score += score(text, topics);
            }
        }

        for (CommandRecord command : commands) {
            if (!command.functionTarget()) continue;
            Function f = funcs.getFunctionAt(command.target());
            if (f == null) f = funcs.getFunctionContaining(command.target());
            if (f == null) continue;
            String evidenceText = command.name() + " — " + command.description();
            List<Topic> topics = topicsFor(evidenceText);
            if (topics.isEmpty() && !PRIORITY_COMMANDS.contains(command.name())) continue;
            final Function commandFunction = f;
            Hit hit = hits.computeIfAbsent(commandFunction.getEntryPoint(), ignored -> new Hit(commandFunction));
            hit.topics.addAll(topics);
            if (hit.evidence.size() < 64) {
                hit.evidence.add(new Evidence(command.tableAddress(),
                    "command " + evidenceText, command.tableAddress()));
            }
            hit.score += 16 + (PRIORITY_COMMANDS.contains(command.name()) ? 24 : 0);
        }

        List<Hit> ranked = new ArrayList<>(hits.values());
        ranked.sort(Comparator.<Hit>comparingInt(h -> h.score).reversed()
            .thenComparing(h -> h.function.getEntryPoint()));

        for (Hit hit : ranked) {
            hit.function.addTag("VNAOLTE:RF");
            hit.function.addTag("VNAOLTE:GCT-RF");
            for (Topic topic : hit.topics) hit.function.addTag(topic.tag());
        }

        Files.createDirectories(output.toAbsolutePath().getParent());
        DecompInterface decomp = new DecompInterface();
        decomp.toggleCCode(true);
        decomp.toggleSyntaxTree(true);
        decomp.setSimplificationStyle("decompile");
        decomp.openProgram(currentProgram);

        try (PrintWriter out = new PrintWriter(Files.newBufferedWriter(output))) {
            out.println("# GCT RF survey — " + currentProgram.getName());
            out.println();
            out.println("- Language: `" + currentProgram.getLanguageID() + "`");
            out.println("- Program data endian: `" + (memory.isBigEndian() ? "big" : "little") + "`");
            out.println("- Image base: `" + currentProgram.getImageBase() + "`");
            out.println("- Defined strings scanned: " + definedStrings);
            out.println("- RF-relevant strings: " + matchedStrings);
            out.println("- References to RF strings: " + matchedRefs);
            out.println("- Referenced RF functions: " + ranked.size());
            out.println("- RF-string references outside known functions: " + unresolvedRefs);
            out.println("- GCT command-table runs: " + commandRuns.size());
            out.println("- GCT command records: " + commands.size());
            out.println();

            out.println("## Recovered GCT command tables");
            out.println();
            if (commandRuns.isEmpty()) {
                out.println("No command-table runs recovered.");
                out.println();
            }
            for (CommandRun run : commandRuns) {
                out.println("### `" + run.start() + "` — `" + run.layout() + "` (" + run.records().size() + " records)");
                out.println();
                out.println("| row | command | description | flags | target kind | target | function |");
                out.println("|---|---|---|---:|---|---|---|");
                for (CommandRecord command : run.records()) {
                    Function f = null;
                    if (command.functionTarget()) {
                        f = funcs.getFunctionAt(command.target());
                        if (f == null) f = funcs.getFunctionContaining(command.target());
                    }
                    String fn = f == null ? "" : f.getName();
                    out.printf(Locale.ROOT, "| `%s` | `%s` | %s | `0x%x` | %s | `%s` | `%s` |%n",
                        command.tableAddress(), escapeTicks(command.name()),
                        escapePipe(command.description()), command.flags(),
                        command.functionTarget() ? "function" : "subtable", command.target(),
                        escapePipe(fn));
                }
                out.println();
            }

            out.println("## Ranked RF functions");
            out.println();
            out.println("| score | entry | function | topics | callers | callees |");
            out.println("|---:|---|---|---|---:|---:|");
            for (Hit hit : ranked) {
                Set<Function> callers = hit.function.getCallingFunctions(monitor);
                Set<Function> callees = hit.function.getCalledFunctions(monitor);
                out.printf(Locale.ROOT, "| %d | `%s` | `%s` | %s | %d | %d |%n",
                    hit.score, hit.function.getEntryPoint(), escapePipe(hit.function.getName()),
                    escapePipe(hit.topics.stream().map(Topic::name).sorted().toList().toString()),
                    callers.size(), callees.size());
            }
            out.println();

            out.println("## Matching strings");
            out.println();
            out.println("```text");
            matchingStrings.stream().sorted().forEach(out::println);
            out.println("```");
            out.println();

            int decompiled = 0;
            for (Hit hit : ranked) {
                if (decompiled >= maxDecompile) break;
                monitor.checkCancelled();
                decompiled++;
                Function f = hit.function;
                out.println("## " + f.getName() + " @ `" + f.getEntryPoint() + "` (score " + hit.score + ")");
                out.println();
                out.println("Topics: " + hit.topics.stream().map(Topic::name).sorted().toList());
                out.println();
                out.println("### Evidence");
                out.println();
                for (Evidence e : hit.evidence) {
                    out.println("- `" + e.refFrom() + "` → `" + e.stringAddress() + "`: `" +
                        escapeTicks(e.text()) + "`");
                }
                out.println();

                Set<Function> callers = f.getCallingFunctions(monitor);
                Set<Function> callees = f.getCalledFunctions(monitor);
                out.println("### Immediate callers");
                out.println();
                if (callers.isEmpty()) out.println("- none resolved");
                else callers.stream().sorted(Comparator.comparing(Function::getEntryPoint)).limit(80)
                    .forEach(x -> out.println("- `" + x.getEntryPoint() + "` `" + x.getName() + "`"));
                out.println();
                out.println("### Immediate callees");
                out.println();
                if (callees.isEmpty()) out.println("- none resolved");
                else callees.stream().sorted(Comparator.comparing(Function::getEntryPoint)).limit(120)
                    .forEach(x -> out.println("- `" + x.getEntryPoint() + "` `" + x.getName() + "`"));
                out.println();

                out.println("### Decompile");
                out.println();
                DecompileResults result = decomp.decompileFunction(f, 45, monitor);
                if (result.decompileCompleted() && result.getDecompiledFunction() != null) {
                    out.println("```c");
                    out.print(result.getDecompiledFunction().getC());
                    if (!result.getDecompiledFunction().getC().endsWith("\n")) out.println();
                    out.println("```");
                } else {
                    out.println("Decompiler failed: `" + escapeTicks(result.getErrorMessage()) + "`");
                }
                out.println();
            }
        } finally {
            decomp.dispose();
        }

        println("GCT_RF_SURVEY_DEFINED_STRINGS=" + definedStrings);
        println("GCT_RF_SURVEY_MATCHED_STRINGS=" + matchedStrings);
        println("GCT_RF_SURVEY_REFERENCED_FUNCTIONS=" + ranked.size());
        println("GCT_RF_SURVEY_COMMAND_RUNS=" + commandRuns.size());
        println("GCT_RF_SURVEY_COMMANDS=" + commands.size());
        println("GCT_RF_SURVEY_REPORT=" + output.toAbsolutePath());
    }

    private List<CommandRun> findCommandRuns(Memory memory) throws Exception {
        List<CommandRun> out = new ArrayList<>();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isInitialized() || block.isOverlay() || block.getSize() < 16) continue;
            for (CommandLayout layout : CommandLayout.values()) {
                long off = 0;
                while (off + 16 <= block.getSize()) {
                    monitor.checkCancelled();
                    Address row = block.getStart().add(off);
                    CommandRecord first = commandAt(memory, row, layout);
                    if (first == null) {
                        off += 4;
                        continue;
                    }
                    List<CommandRecord> run = new ArrayList<>();
                    long cursor = off;
                    while (cursor + 16 <= block.getSize()) {
                        CommandRecord item = commandAt(memory, block.getStart().add(cursor), layout);
                        if (item == null) break;
                        run.add(item);
                        cursor += 16;
                    }
                    if (run.size() >= MIN_COMMAND_RUN) {
                        out.add(new CommandRun(row, layout, List.copyOf(run)));
                        off = cursor;
                    } else {
                        off += 4;
                    }
                }
            }
        }
        out.sort(Comparator.comparing(CommandRun::start).thenComparing(r -> r.layout().ordinal()));
        return dedupeRuns(out);
    }

    private List<CommandRun> dedupeRuns(List<CommandRun> runs) {
        List<CommandRun> candidates = new ArrayList<>(runs);
        candidates.sort(Comparator.<CommandRun>comparingInt(r -> r.records().size()).reversed()
            .thenComparing(CommandRun::start));
        List<CommandRun> accepted = new ArrayList<>();
        for (CommandRun run : candidates) {
            boolean overlaps = false;
            for (CommandRun prior : accepted) {
                if (rangesOverlap(run, prior)) {
                    overlaps = true;
                    break;
                }
            }
            if (!overlaps) accepted.add(run);
        }
        accepted.sort(Comparator.comparing(CommandRun::start));
        return accepted;
    }

    private static boolean rangesOverlap(CommandRun a, CommandRun b) {
        long a0 = a.start().getOffset();
        long a1 = a.records().get(a.records().size() - 1).tableAddress().getOffset() + 16;
        long b0 = b.start().getOffset();
        long b1 = b.records().get(b.records().size() - 1).tableAddress().getOffset() + 16;
        return a0 < b1 && b0 < a1;
    }

    private CommandRecord commandAt(Memory memory, Address row, CommandLayout layout) {
        CommandRecord shape = recordShapeAt(memory, row, layout);
        if (shape == null) return null;
        if (shape.functionTarget()) return shape;
        return looksLikeCommandTableAt(memory, shape.target()) ? shape : null;
    }

    private CommandRecord recordShapeAt(Memory memory, Address row, CommandLayout layout) {
        try {
            long w0 = u32(memory.getInt(row, true));
            long w1 = u32(memory.getInt(row.add(4), true));
            long w2 = u32(memory.getInt(row.add(8), true));
            long w3 = u32(memory.getInt(row.add(12), true));
            long namePtr;
            long descPtr;
            long flags;
            long targetPtr;
            if (layout == CommandLayout.NAME_DESC_FLAGS_TARGET) {
                namePtr = w0; descPtr = w1; flags = w2; targetPtr = w3;
            } else {
                targetPtr = w0; namePtr = w1; descPtr = w2; flags = w3;
            }
            if (flags == 0 || flags > 0x00ff_ffffL || targetPtr == 0) return null;
            String name = cString(memory, address(namePtr), 64);
            if (!looksLikeCommandName(name)) return null;
            String description = descPtr == 0 ? "" : cString(memory, address(descPtr), MAX_CSTRING);
            if (description == null || (!description.isEmpty() && !looksPrintable(description))) return null;
            boolean functionTarget = (targetPtr & 1L) != 0;
            Address target = address(functionTarget ? targetPtr & ~1L : targetPtr);
            if (!memory.contains(target)) return null;
            return new CommandRecord(row, layout, name, description, flags, target, functionTarget);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean looksLikeCommandTableAt(Memory memory, Address target) {
        for (CommandLayout layout : CommandLayout.values()) {
            if (recordShapeAt(memory, target, layout) != null) return true;
        }
        return false;
    }

    private void annotateCommand(CommandRecord command, FunctionManager funcs) throws Exception {
        String targetKind = command.functionTarget() ? "handler" : "subtable";
        String summary = "GCT command " + command.name() +
            (command.description().isBlank() ? "" : " — " + command.description()) +
            String.format(Locale.ROOT, " [flags=0x%x, %s=%s]", command.flags(), targetKind, command.target());
        String old = currentProgram.getListing().getComment(CommentType.EOL, command.tableAddress());
        if (old == null || old.isBlank()) {
            currentProgram.getListing().setComment(command.tableAddress(), CommentType.EOL, summary);
        } else if (!old.contains("GCT command ")) {
            currentProgram.getListing().setComment(command.tableAddress(), CommentType.EOL, old + "\n" + summary);
        }
        currentProgram.getBookmarkManager().setBookmark(command.target(), BookmarkType.ANALYSIS,
            command.functionTarget() ? "VNAOLTE/GCT command" : "VNAOLTE/GCT command group",
            command.name() + (command.description().isBlank() ? "" : " — " + command.description()));

        if (!command.functionTarget()) return;
        Function f = funcs.getFunctionAt(command.target());
        if (f == null) f = funcs.getFunctionContaining(command.target());
        if (f == null) return;
        f.addTag("VNAOLTE:GCT-CMD");
        List<Topic> topics = topicsFor(command.name() + " " + command.description());
        for (Topic topic : topics) f.addTag(topic.tag());
        if (f.getEntryPoint().equals(command.target()) && f.getName().startsWith("FUN_")) {
            try {
                f.setName("gct_cmd_" + sanitizeCommand(command.name()), SourceType.ANALYSIS);
            } catch (Exception ignored) {
                // Name recovery is helpful but never required for the survey.
            }
        }
    }

    private static String sanitizeCommand(String name) {
        String s = name.startsWith("-") ? name.substring(1) : name;
        s = s.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "_");
        s = s.replaceAll("^_+|_+$", "");
        return s.isBlank() ? "command" : s;
    }

    private Address address(long value) {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        return space.getAddress(value);
    }

    private static long u32(int value) {
        return Integer.toUnsignedLong(value);
    }

    private static String cString(Memory memory, Address start, int max) throws MemoryAccessException {
        if (start == null || !memory.contains(start)) return null;
        StringBuilder out = new StringBuilder();
        Address cur = start;
        for (int i = 0; i < max; i++) {
            if (!memory.contains(cur)) return null;
            int b = memory.getByte(cur) & 0xff;
            if (b == 0) return out.toString();
            if (b < 0x20 || b > 0x7e) return null;
            out.append((char) b);
            cur = cur.add(1);
        }
        return null;
    }

    private static boolean looksLikeCommandName(String name) {
        if (name == null || name.length() < 2 || name.length() > 48 || name.charAt(0) != '-') return false;
        for (int i = 1; i < name.length(); i++) {
            char c = name.charAt(i);
            if (!(Character.isLetterOrDigit(c) || c == '_' || c == '-')) return false;
        }
        return true;
    }

    private static boolean looksPrintable(String s) {
        if (s.length() > MAX_CSTRING) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7e) return false;
        }
        return true;
    }

    private static List<Topic> topicsFor(String text) {
        String lower = text.toLowerCase(Locale.ROOT);
        List<Topic> result = new ArrayList<>();
        for (Topic topic : TOPICS) {
            for (String needle : topic.needles()) {
                if (lower.contains(needle)) {
                    result.add(topic);
                    break;
                }
            }
        }
        return result;
    }

    private static int score(String text, List<Topic> topics) {
        String lower = text.toLowerCase(Locale.ROOT);
        int score = 2 * topics.size();
        for (String needle : PRIORITY_NEEDLES) {
            if (lower.contains(needle)) score += 12;
        }
        if (lower.contains("usage") || lower.contains("rfm cal") || lower.contains("rfm rffe")) score += 4;
        if (lower.contains("freq_khz") || lower.contains("powerdetectoradc")) score += 5;
        return score;
    }

    private static String compact(String text, int max) {
        String one = text.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ').trim();
        return one.length() <= max ? one : one.substring(0, max - 3) + "...";
    }

    private static String escapePipe(String s) { return escapeTicks(s).replace("|", "\\|"); }
    private static String escapeTicks(String s) { return s == null ? "" : s.replace("`", "'"); }
}
