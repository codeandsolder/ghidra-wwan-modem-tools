package mtk_mddb.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.google.gson.FieldNamingPolicy;
import com.google.gson.GsonBuilder;
import mtk_mddb.core.EdbArchive;
import mtk_mddb.core.MddbDatabase;
import mtk_mddb.core.MddbSearchResult;
import org.rocksdb.RocksDBException;

/** Standalone entry point for the same decoder and database used by Ghidra. */
public final class Main {
    private static final String USAGE = """
        Usage:
          mtk-mddb extract <input.EDB> -o <new-output-directory> [--keep-datai]
          mtk-mddb query <input.EDB|extracted-db> <text> [--cf <name>]... [--limit N] [--context N]
        """;

    private Main() {}

    public static void main(String[] args) {
        int status = run(args, System.out, System.err);
        if (status != 0) {
            System.exit(status);
        }
    }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            out.print(USAGE);
            return args.length == 0 ? 2 : 0;
        }
        try {
            return switch (args[0]) {
                case "extract" -> extract(args, out);
                case "query" -> query(args, out);
                default -> throw new IllegalArgumentException("Unknown command: " + args[0]);
            };
        } catch (IllegalArgumentException e) {
            err.println(e.getMessage());
            err.print(USAGE);
            return 2;
        } catch (IOException | RocksDBException e) {
            err.println(e.getMessage());
            return 1;
        }
    }

    private static int extract(String[] args, PrintStream out) throws IOException {
        if (args.length < 2) {
            throw new IllegalArgumentException("Missing input EDB");
        }
        Path input = Path.of(args[1]);
        Path output = null;
        boolean keepDataI = false;
        int i = 2;
        while (i < args.length) {
            switch (args[i]) {
                case "-o", "--output" -> {
                    if (output != null) {
                        throw new IllegalArgumentException("Output specified more than once");
                    }
                    output = Path.of(value(args, i));
                    i++;
                }
                case "--keep-datai" -> keepDataI = true;
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
            i++;
        }
        if (output == null) {
            throw new IllegalArgumentException("Missing -o output directory");
        }
        EdbArchive.Manifest manifest = EdbArchive.extract(input, output, keepDataI);
        var gson = new GsonBuilder().setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
            .setPrettyPrinting().disableHtmlEscaping().create();
        Files.writeString(output.resolve("manifest.json"), gson.toJson(manifest) + System.lineSeparator(),
            StandardCharsets.UTF_8);
        out.println("extracted " + manifest.rocksdbFiles().size() + " RocksDB files to " + output.resolve("rocksdb"));
        for (EdbArchive.SectionManifest section : manifest.sections()) {
            out.printf(Locale.ROOT, "%s: %d -> %d bytes%n", section.name(), section.compressedSize(),
                section.uncompressedSize());
        }
        out.println("DATAA: " + manifest.dataaSize() + " bytes -> " + output.resolve(EdbArchive.DATAA_FILE));
        return 0;
    }

    private static int query(String[] args, PrintStream out) throws IOException, RocksDBException {
        if (args.length < 3 || args[2].isEmpty()) {
            throw new IllegalArgumentException("Missing source or nonempty query text");
        }
        List<String> families = new ArrayList<>();
        int limit = 50;
        int context = 96;
        int i = 3;
        while (i < args.length) {
            switch (args[i]) {
                case "--cf" -> families.add(value(args, i));
                case "--limit" -> limit = Integer.parseInt(value(args, i));
                case "--context" -> context = Integer.parseInt(value(args, i));
                default -> throw new IllegalArgumentException("Unknown option: " + args[i]);
            }
            i += 2;
        }
        if (limit <= 0 || context < 0) {
            throw new IllegalArgumentException("--limit must be positive and --context nonnegative");
        }
        int needleLength = args[2].getBytes(StandardCharsets.UTF_8).length;
        try (MddbDatabase db = MddbDatabase.open(Path.of(args[1]))) {
            List<MddbSearchResult> matches = db.search(args[2], families, limit);
            for (MddbSearchResult match : matches) {
                out.printf(Locale.ROOT, "cf=%s field=%s key=%s offset=0x%x len=%d%n",
                    match.columnFamily(), match.field(), match.keyHex(), match.offset(), match.value().length);
                out.println(MddbDatabase.renderContext(match, context, needleLength));
                out.println();
            }
            out.println("matches_shown=" + matches.size() + (matches.size() >= limit ? " (limit reached)" : ""));
        }
        return 0;
    }

    private static String value(String[] args, int index) {
        if (index >= args.length - 1) {
            throw new IllegalArgumentException("Missing value for " + args[index]);
        }
        return args[index + 1];
    }
}
