// Verify real CWE payloads and enumerate readable files in embedded YAFFS images.
// @category VNAOLTE

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.HexFormat;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FileSystemProbeConflictResolver;
import ghidra.formats.gfilesystem.FileSystemRef;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;

public class VerifyCweFiles extends GhidraScript {
    private static final Map<String, String> PAYLOADS = Map.of(
        "BOOT/SBL1.mbn", "SBL1.bin",
        "APPL/APBL.mbn", "APBL.bin",
        "APPL/APPS.bootimg", "APPS.bin",
        "APPL/SYST.yaffs2", "SYST.bin",
        "APPL/USER.yaffs2", "USER.bin",
        "MODM/DSP2.yaffs2", "DSP2.bin",
        "MODM/QRPM.elf", "QRPM.elf",
        "MODM/TZON.elf", "TZON.elf");

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) {
            throw new IllegalArgumentException("usage: VerifyCweFiles <firmware.cwe> <reference-dir>");
        }
        Path reference = Path.of(args[1]);
        FileSystemService service = FileSystemService.getInstance();
        try (FileSystemRef root = service.probeFileForFilesystem(
                service.getLocalFSRL(new File(args[0])), monitor,
                FileSystemProbeConflictResolver.CHOOSEFIRST)) {
            if (root == null || !"sierracwe".equals(root.getFilesystem().getType())) {
                throw new IOException("CWE filesystem not recognized");
            }
            GFileSystem cwe = root.getFilesystem();
            for (Map.Entry<String, String> entry : new TreeMap<>(PAYLOADS).entrySet()) {
                monitor.checkCancelled();
                GFile file = cwe.lookup(entry.getKey());
                if (file == null || file.isDirectory()) {
                    throw new IOException("Missing CWE payload " + entry.getKey());
                }
                String actual = digestFile(cwe, file);
                String expected;
                try (InputStream stream = Files.newInputStream(reference.resolve(entry.getValue()))) {
                    expected = digest(stream);
                }
                if (!expected.equals(actual)) {
                    throw new IOException("CWE digest mismatch: " + entry.getKey());
                }
                println("CWE_PAYLOAD " + entry.getKey() + " " + actual);
                if (entry.getKey().endsWith(".yaffs2")) {
                    verifyYaffs(service, file);
                }
            }
        }
        println("CWE_PAYLOADS_VERIFIED=" + PAYLOADS.size());
    }

    private void verifyYaffs(FileSystemService service, GFile file) throws Exception {
        try (FileSystemRef nested = service.probeFileForFilesystem(file.getFSRL(), monitor,
                FileSystemProbeConflictResolver.CHOOSEFIRST)) {
            if (nested == null || !"yaffswide".equals(nested.getFilesystem().getType())) {
                throw new IOException("Wide YAFFS filesystem not recognized: " + file.getPath());
            }
            GFileSystem fs = nested.getFilesystem();
            ArrayDeque<GFile> pending = new ArrayDeque<>(fs.getListing(null));
            Map<String, String> files = new TreeMap<>();
            int failures = 0;
            while (!pending.isEmpty()) {
                monitor.checkCancelled();
                GFile child = pending.removeFirst();
                if (child.isDirectory()) {
                    pending.addAll(fs.getListing(child));
                }
                else {
                    try {
                        files.put(child.getPath(), digestFile(fs, child));
                    }
                    catch (IOException ex) {
                        files.put(child.getPath(), "UNREADABLE");
                        failures++;
                        println("YAFFS_READ_ERROR " + child.getPath() + " " + ex.getMessage());
                    }
                }
            }
            if (files.isEmpty()) {
                throw new IOException("Empty YAFFS file tree: " + file.getPath());
            }
            for (Map.Entry<String, String> entry : files.entrySet()) {
                println("YAFFS_FILE " + file.getPath() + ":" + entry.getKey() + " " + entry.getValue());
            }
            println("YAFFS_SUMMARY " + file.getPath() + " files=" + files.size() + " unreadable=" + failures);
        }
    }

    private String digestFile(GFileSystem fs, GFile file) throws Exception {
        try (ByteProvider provider = fs.getByteProvider(file, monitor)) {
            if (provider == null) {
                throw new IOException("Missing byte provider");
            }
            try (InputStream stream = provider.getInputStream(0)) {
                return digest(stream);
            }
        }
    }

    private static String digest(InputStream stream) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (DigestInputStream input = new DigestInputStream(stream, digest)) {
            input.transferTo(OutputStream.nullOutputStream());
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
