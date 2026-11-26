// Export the EM7455 DSP2 /image tree through the VNAOLTE Ghidra filesystem plugins.
//@category VNAOLTE

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;

public class ExportEm7455Dsp extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: ExportEm7455Dsp <firmware.cwe> <output-dir>");
        }
        FileSystemService fss = FileSystemService.getInstance();
        FSRL local = fss.getLocalFSRL(new File(args[0]));
        Path out = Paths.get(args[1]);
        Files.createDirectories(out);
        try (FileSystemRef cweRef = fss.probeFileForFilesystem(local, monitor,
                FileSystemProbeConflictResolver.CHOOSEFIRST)) {
            if (cweRef == null) throw new IOException("CWE filesystem not recognized");
            GFile dsp = cweRef.getFilesystem().lookup("/MODM/DSP2.yaffs2");
            if (dsp == null) throw new IOException("DSP2 leaf not found");
            try (FileSystemRef yaffsRef = fss.probeFileForFilesystem(dsp.getFSRL(), monitor,
                    FileSystemProbeConflictResolver.CHOOSEFIRST)) {
                if (yaffsRef == null) throw new IOException("DSP2 YAFFS filesystem not recognized");
                GFile image = yaffsRef.getFilesystem().lookup("/image");
                if (image == null) throw new IOException("/image directory not found");
                List<String> manifest = new ArrayList<>();
                for (GFile f : yaffsRef.getFilesystem().getListing(image)) {
                    monitor.checkCancelled();
                    if (f.isDirectory()) continue;
                    try (ByteProvider bp = yaffsRef.getFilesystem().getByteProvider(f, monitor)) {
                        if (bp == null) continue;
                        byte[] data = bp.readBytes(0, bp.length());
                        Path dest = out.resolve(f.getName());
                        Files.write(dest, data);
                        String sha = hex(MessageDigest.getInstance("SHA-256").digest(data));
                        String line = sha + "  " + data.length + "  " + f.getName();
                        manifest.add(line);
                        println(line);
                    }
                }
                Collections.sort(manifest, Comparator.comparing(s -> s.substring(s.lastIndexOf("  ") + 2)));
                Files.write(out.resolve("SHA256SUMS.with-size"), manifest);
            }
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder(b.length * 2);
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }
}
