// Dump VNAOLTE RF-tagged functions as TSV for external inspection.
// Args: output path
// @category VNAOLTE

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionTag;

public class DumpVnaolteRfReport extends GhidraScript {
    private record Row(Function function, String tags) {}

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: DumpVnaolteRfReport.java OUTPUT.tsv");
        }
        List<Row> rows = new ArrayList<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Function f = it.next();
            Set<FunctionTag> all = f.getTags();
            List<String> vna = all.stream().map(FunctionTag::getName)
                .filter(name -> name.startsWith("VNAOLTE:"))
                .sorted().toList();
            if (!vna.isEmpty()) {
                rows.add(new Row(f, String.join(",", vna)));
            }
        }
        rows.sort(Comparator.comparing(r -> r.function().getEntryPoint()));
        Path out = Path.of(args[0]);
        Files.createDirectories(out.toAbsolutePath().getParent());
        try (PrintWriter pw = new PrintWriter(Files.newBufferedWriter(out))) {
            pw.println("entry\tname\ttags\trepeatable_comment");
            for (Row row : rows) {
                Function f = row.function();
                String comment = f.getRepeatableComment();
                if (comment == null) comment = "";
                comment = comment.replace((char) 9, (char) 32)
                    .replace((char) 10, (char) 32).replace((char) 13, (char) 32);
                pw.printf("%s\t%s\t%s\t%s%n", f.getEntryPoint(), f.getName(),
                    row.tags(), comment);
            }
        }
        println("Wrote " + rows.size() + " VNAOLTE RF functions to " + out);
    }
}
