package vnaolte.ghidra.cwe;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.zip.InflaterInputStream;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

@FileSystemInfo(type = "sierracwe", description = "Sierra Wireless CWE firmware",
    priority = FileSystemInfo.PRIORITY_HIGH, factory = SierraCweFileSystemFactory.class)
public final class SierraCweFileSystem implements GFileSystem {
    private final FSRLRoot fsFSRL;
    private final FileSystemService fsService;
    private final FileSystemIndexHelper<Entry> fsIndex;
    private final FileSystemRefManager refManager = new FileSystemRefManager(this);
    private ByteProvider provider;
    private long nextIndex = 1;

    record Entry(String name, String type, String product, String version, String date,
            long payloadOffset, long storedSize, long checksum, boolean compressed,
            boolean directory) {
    }

    SierraCweFileSystem(FSRLRoot fsFSRL, ByteProvider provider, FileSystemService fsService) {
        this.fsFSRL = fsFSRL;
        this.provider = provider;
        this.fsService = fsService;
        this.fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);
    }

    void mount(TaskMonitor monitor) throws IOException, CancelledException {
        monitor.setMessage("Parsing Sierra Wireless CWE firmware...");
        SierraCweHeader root = SierraCweHeader.read(provider, 0);
        if (!root.type.equals("SPKG")) {
            addNode(root, "", monitor);
            return;
        }
        parseChildren(root, "", monitor);
    }

    private void addNode(SierraCweHeader header, String parent, TaskMonitor monitor)
            throws IOException, CancelledException {
        monitor.checkCancelled();
        if (header.isContainer()) {
            String path = parent.isEmpty() ? header.type : parent + "/" + header.type;
            Entry entry = new Entry(header.type, header.type, header.product, header.version,
                header.date, header.payloadOffset(), header.payloadSize, header.checksum,
                header.compressed, true);
            fsIndex.storeFile(path, nextIndex++, true, 0, entry);
            parseChildren(header, path, monitor);
            return;
        }

        String filename = header.type + extensionFor(header.type);
        String path = parent.isEmpty() ? filename : parent + "/" + filename;
        Entry entry = new Entry(filename, header.type, header.product, header.version, header.date,
            header.payloadOffset(), header.payloadSize, header.checksum, header.compressed, false);
        fsIndex.storeFile(path, nextIndex++, false, header.compressed ? -1 : header.payloadSize,
            entry);
    }

    private void parseChildren(SierraCweHeader container, String parent, TaskMonitor monitor)
            throws IOException, CancelledException {
        if (container.compressed) {
            throw new IOException("Compressed CWE container is not supported: " + container.type);
        }
        long pos = container.payloadOffset();
        long end = pos + container.payloadSize;
        while (pos < end) {
            monitor.checkCancelled();
            if (end - pos < SierraCweHeader.HEADER_SIZE) {
                throw new IOException("Trailing " + (end - pos) + " bytes in CWE container " +
                    container.type);
            }
            SierraCweHeader child = SierraCweHeader.read(provider, pos);
            if (child.totalSize() > end - pos) {
                throw new IOException("Child " + child.type + " exceeds " + container.type);
            }
            addNode(child, parent, monitor);
            pos += child.totalSize();
        }
        if (pos != end) {
            throw new IOException("CWE child alignment error in " + container.type);
        }
    }

    private static String extensionFor(String type) {
        return switch (type) {
            case "TZON", "QRPM" -> ".elf";
            case "DSP2", "SYST", "USER" -> ".yaffs2";
            case "APPS" -> ".bootimg";
            case "APBL", "SBL1" -> ".mbn";
            default -> ".bin";
        };
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
            throws IOException, CancelledException {
        Entry entry = fsIndex.getMetadata(file);
        if (entry == null || entry.directory) {
            return null;
        }
        if (!entry.compressed) {
            return new ByteProviderWrapper(provider, entry.payloadOffset, entry.storedSize,
                file.getFSRL());
        }
        String key = "cwe-zlib:" + file.getPath() + ":" + Long.toHexString(entry.checksum);
        return fsService.getDerivedByteProvider(provider.getFSRL(), file.getFSRL(), key, -1,
            () -> zlibStream(entry), monitor);
    }

    private InputStream zlibStream(Entry entry) throws IOException {
        return new InflaterInputStream(provider.getInputStream(entry.payloadOffset));
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        Entry entry = fsIndex.getMetadata(file);
        if (entry == null) {
            return FileAttributes.EMPTY;
        }
        FileAttributes attrs = FileAttributes.of(
            FileAttribute.create(NAME_ATTR, entry.name),
            FileAttribute.create(COMPRESSED_SIZE_ATTR, entry.storedSize),
            FileAttribute.create(COMMENT_ATTR, "CWE " + entry.type + " / " + entry.product +
                " / " + entry.version + (entry.compressed ? " / zlib" : "")));
        attrs.add("CWE type", entry.type);
        attrs.add("Product", entry.product);
        attrs.add("Version", entry.version);
        attrs.add("Build date", entry.date);
        attrs.add("Checksum", String.format("0x%08x", entry.checksum));
        return attrs;
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        fsIndex.clear();
        if (provider != null) {
            provider.close();
            provider = null;
        }
    }

    @Override public String getName() { return fsFSRL.getContainer().getName(); }
    @Override public FSRLRoot getFSRL() { return fsFSRL; }
    @Override public boolean isClosed() { return provider == null; }
    @Override public int getFileCount() { return fsIndex.getFileCount(); }
    @Override public FileSystemRefManager getRefManager() { return refManager; }
    @Override public GFile lookup(String path) { return fsIndex.lookup(path); }
    @Override public List<GFile> getListing(GFile directory) { return fsIndex.getListing(directory); }
}
