package vnaolte.ghidra.analysis;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Converts Qualcomm modem debug-message source annotations into a focused RF
 * reverse-engineering worklist for VNAOLTE.
 *
 * QDig annotates Qualcomm debug descriptor constants with comments such as
 * "ftm_common_fbrx.c:123 ...".  Once ordinary reference analysis has run, this
 * analyzer follows code references to those descriptors, tags the containing
 * functions, and creates bookmarks at function entries.  It deliberately does
 * not rename functions: one function may reference messages from several
 * source modules and the evidence is useful without pretending it is a symbol.
 */
public final class VnaolteRfAnalyzer extends AbstractAnalyzer {
    private static final String TAG_ALL = "VNAOLTE:RF";
    private static final int MAX_EVIDENCE_PER_FUNCTION = 12;

    private record Topic(String key, String tag, String[] needles) {}

    private static final List<Topic> TOPICS = List.of(
        new Topic("FBRx", "VNAOLTE:FBRx", new String[] {
            "fbrx", "feedback receiver", "feedback_rx"
        }),
        new Topic("VSWR/S11", "VNAOLTE:VSWR", new String[] {
            "vswr", "s11", "return_loss", "return loss", "reflected meas",
            "incident meas"
        }),
        new Topic("IQ capture", "VNAOLTE:IQ", new String[] {
            "iq_capture", "iq capture", "iq samples", "iq_samples",
            "iq_processing", "sample_capture"
        }),
        new Topic("Coupler/RFFE", "VNAOLTE:RFFE", new String[] {
            "coupler", "rffe", "rfc_rffe"
        }),
        new Topic("XPT/DPD", "VNAOLTE:XPT", new String[] {
            "xpt", "dpd", "et_env", "et_enable"
        }),
        new Topic("WTR3925", "VNAOLTE:WTR3925", new String[] {
            "wtr3925"
        }),
        new Topic("RF test/FTM", "VNAOLTE:FTM-RF", new String[] {
            "ftm_rf", "rf_test", "ftm_common", "ftm_lte", "selftest"
        })
    );

    private static final class Hit {
        final Function function;
        final Set<String> topics = new LinkedHashSet<>();
        final List<String> evidence = new ArrayList<>();
        int descriptorReferences;

        Hit(Function function) {
            this.function = function;
        }
    }

    public VnaolteRfAnalyzer() {
        super("VNAOLTE Qualcomm RF Triage",
            "Tags and bookmarks modem functions that reference Qualcomm debug descriptors " +
            "for FBRx, VSWR/S11, IQ capture, couplers/RFFE, XPT/DPD, WTR3925, and RF FTM.",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        Processor processor = program.getLanguage().getProcessor();
        return processor != null && "Hexagon".equalsIgnoreCase(processor.toString());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        Listing listing = program.getListing();
        ReferenceManager references = program.getReferenceManager();
        FunctionManager functions = program.getFunctionManager();
        BookmarkManager bookmarks = program.getBookmarkManager();
        Map<Address, Hit> hits = new LinkedHashMap<>();
        int matchingDescriptors = 0;
        int unresolvedReferences = 0;

        AddressSetView memory = program.getMemory().getLoadedAndInitializedAddressSet();
        AddressIterator comments = listing.getCommentAddressIterator(CommentType.EOL, memory, true);
        while (comments.hasNext()) {
            monitor.checkCancelled();
            Address descriptor = comments.next();
            String text = listing.getComment(CommentType.EOL, descriptor);
            if (text == null || text.isBlank()) {
                continue;
            }

            List<Topic> matched = topicsFor(text);
            if (matched.isEmpty()) {
                continue;
            }
            matchingDescriptors++;

            ReferenceIterator refs = references.getReferencesTo(descriptor);
            while (refs.hasNext()) {
                Reference ref = refs.next();
                Address from = ref.getFromAddress();
                Function function = functions.getFunctionContaining(from);
                if (function == null) {
                    unresolvedReferences++;
                    continue;
                }

                Hit hit = hits.computeIfAbsent(function.getEntryPoint(), ignored -> new Hit(function));
                hit.descriptorReferences++;
                for (Topic topic : matched) {
                    hit.topics.add(topic.key());
                }
                String evidence = descriptor + " <- " + from + "  " + compact(text);
                if (hit.evidence.size() < MAX_EVIDENCE_PER_FUNCTION &&
                        !hit.evidence.contains(evidence)) {
                    hit.evidence.add(evidence);
                }
            }
        }

        for (Hit hit : hits.values()) {
            monitor.checkCancelled();
            hit.function.addTag(TAG_ALL);
            for (Topic topic : TOPICS) {
                if (hit.topics.contains(topic.key())) {
                    hit.function.addTag(topic.tag());
                }
            }

            String topicText = String.join(", ", hit.topics);
            String summary = topicText + " — " + hit.descriptorReferences +
                " debug-descriptor reference(s)";
            bookmarks.setBookmark(hit.function.getEntryPoint(), BookmarkType.ANALYSIS,
                "VNAOLTE/RF", summary);

            String marker = "[VNAOLTE RF triage]";
            StringBuilder evidence = new StringBuilder(marker).append(" " )
                .append(summary);
            for (String item : hit.evidence) {
                evidence.append("\n  ").append(item);
            }
            String old = hit.function.getRepeatableComment();
            if (old == null || old.isBlank()) {
                hit.function.setRepeatableComment(evidence.toString());
            }
            else if (!old.contains(marker)) {
                hit.function.setRepeatableComment(old + "\n" + evidence);
            }
        }

        log.appendMsg(getName(), String.format(Locale.ROOT,
            "%d RF-related debug descriptor(s), %d referenced function(s), %d reference(s) outside known functions",
            matchingDescriptors, hits.size(), unresolvedReferences));
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

    private static String compact(String text) {
        String oneLine = text.replace((char) 10, (char) 32).replace((char) 13, (char) 32).trim();
        if (oneLine.length() <= 220) {
            return oneLine;
        }
        return oneLine.substring(0, 217) + "...";
    }
}
