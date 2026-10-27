package vnaolte.ghidra.q6zip;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.Locale;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds old Qualcomm DLPager q6zip RX segments, infers their compression
 * parameters, reconstructs the executable virtual pages, and maps them at the
 * runtime addresses described by the modem's own DLPager descriptor.
 */
public final class QualcommQ6ZipAnalyzer extends AbstractAnalyzer {
    public QualcommQ6ZipAnalyzer() {
        super("VNAOLTE Qualcomm q6zip Decompressor",
            "Reconstructs Qualcomm DLPager q6zip-compressed Hexagon code into its runtime address range.",
            AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS.before());
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
        Memory memory = program.getMemory();
        MemoryBlock[] snapshot = Arrays.copyOf(memory.getBlocks(), memory.getBlocks().length);
        int mapped = 0;

        for (MemoryBlock block : snapshot) {
            monitor.checkCancelled();
            if (!Q6ZipDecoder.looksLikeQ6Zip(block)) {
                continue;
            }

            try {
                Q6ZipDecoder.Result result = Q6ZipDecoder.decompress(memory, block, monitor);
                Address runtimeStart = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(result.runtime().start());

                MemoryBlock existing = memory.getBlock(runtimeStart);
                if (existing != null) {
                    log.appendMsg(getName(), String.format(Locale.ROOT,
                        "%s: runtime range 0x%0.x already belongs to %s; not replacing it",
                        block.getName(), result.runtime().start(), existing.getName()));
                    continue;
                }

                String name = String.format(Locale.ROOT, "q6zip_rx_%08x",
                    result.runtime().start());
                MemoryBlock decoded = memory.createInitializedBlock(name, runtimeStart,
                    new ByteArrayInputStream(result.image()), result.image().length,
                    monitor, false);
                decoded.setPermissions(true, false, true);
                decoded.setArtificial(true);
                decoded.setSourceName("q6zip:" + block.getName());
                Q6ZipDecoder.Parameters p = result.parameters();
                decoded.setComment(String.format(Locale.ROOT,
                    "VNAOLTE q6zip decode of %s; version=0x%04x pages=%d " +
                    "dict1=%d-bit dict2=%d-bit lookback=%d-bit metadata=%s; " +
                    "%d exact pages, %d partial/short pages",
                    block.getName(), p.version(), p.pageCount(),
                    p.dict1Bits(), p.dict2Bits(), p.lookbackBits(),
                    p.metadataHeaders(), result.exactPages(), result.shortPages()));

                mapped++;
                log.appendMsg(getName(), String.format(Locale.ROOT,
                    "%s -> %s 0x%08x..0x%08x; q6zip v0x%04x, " +
                    "dict=%d/%d, lookback=%d, pages=%d (%d exact, %d short)",
                    block.getName(), name, result.runtime().start(), result.runtime().end(),
                    p.version(), p.dict1Bits(), p.dict2Bits(), p.lookbackBits(),
                    p.pageCount(), result.exactPages(), result.shortPages()));
            }
            catch (Exception e) {
                log.appendMsg(getName(), block.getName() + ": " + e.getMessage());
            }
        }

        if (mapped == 0) {
            log.appendMsg(getName(), "no new q6zip runtime blocks mapped");
        }
        return true;
    }
}
