// Lists a Sierra CWE through the VnaolteFirmware filesystem plugin and recursively probes nested filesystems.
//@category VNAOLTE

import java.io.File;
import java.io.IOException;

import ghidra.app.script.GhidraScript;
import ghidra.formats.gfilesystem.*;

public class ListCweTree extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: ListCweTree <firmware.cwe>");
        }
        FileSystemService fss = FileSystemService.getInstance();
        FSRL local = fss.getLocalFSRL(new File(args[0]));
        try (FileSystemRef ref = fss.probeFileForFilesystem(local, monitor,
                FileSystemProbeConflictResolver.CHOOSEFIRST)) {
            if (ref == null) {
                throw new IOException("no filesystem recognized for " + args[0]);
            }
            println("ROOT " + ref.getFilesystem().getFSRL() + " type=" +
                ref.getFilesystem().getClass().getName());
            walk(fss, ref.getFilesystem(), ref.getFilesystem().getListing(null), "");
        }
    }

    private void walk(FileSystemService fss, GFileSystem fs, java.util.List<GFile> files,
            String indent) throws Exception {
        for (GFile file : files) {
            monitor.checkCancelled();
            println(indent + (file.isDirectory() ? "[D] " : "[F] ") + file.getPath() +
                " size=" + file.getLength() + " fsrl=" + file.getFSRL());
            if (file.isDirectory()) {
                walk(fss, fs, fs.getListing(file), indent + "  ");
                continue;
            }
            try (FileSystemRef nested = fss.probeFileForFilesystem(file.getFSRL(), monitor,
                    FileSystemProbeConflictResolver.CHOOSEFIRST)) {
                if (nested != null) {
                    println(indent + "  -> nested " + nested.getFilesystem().getClass().getName());
                    walk(fss, nested.getFilesystem(), nested.getFilesystem().getListing(null),
                        indent + "    ");
                }
            }
            catch (IOException e) {
                println(indent + "  ! nested probe: " + e.getMessage());
            }
        }
    }
}
