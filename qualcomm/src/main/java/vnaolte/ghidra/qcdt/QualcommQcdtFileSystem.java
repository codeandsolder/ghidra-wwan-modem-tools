package vnaolte.ghidra.qcdt;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderWrapper;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Qualcomm QCDT device-tree table, including the v2 six-u32 selector format. */
@FileSystemInfo(type = "qcdt", description = "Qualcomm QCDT device-tree table",
    priority = FileSystemInfo.PRIORITY_HIGH,
    factory = QualcommQcdtFileSystemFactory.class)
public final class QualcommQcdtFileSystem implements GFileSystem {
    private final FSRLRoot fsFSRL;
    private final FileSystemIndexHelper<Dtb> fsIndex;
    private final FileSystemRefManager refManager = new FileSystemRefManager(this);
    private ByteProvider provider;
    private long nextIndex = 1;

    private record Selector(long platform, long variant, long revision, long subtype) {
        @Override public String toString() {
            return String.format("platform=0x%x variant=0x%x revision=0x%x subtype=0x%x",
                platform, variant, revision, subtype);
        }
    }

    private static final class Dtb {
        final long offset;
        final long size;
        final List<Selector> selectors = new ArrayList<>();
        Dtb(long offset, long size) { this.offset = offset; this.size = size; }
    }

    QualcommQcdtFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        this.fsFSRL = fsFSRL;
        this.provider = provider;
        this.fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);
    }

    void mount(TaskMonitor monitor) throws IOException, CancelledException {
        monitor.setMessage("Parsing Qualcomm QCDT table...");
        byte[] head = provider.readBytes(0, 12);
        long version = u32(head, 4);
        long count = u32(head, 8);
        int entrySize = switch ((int) version) {
            case 1 -> 20;
            case 2, 3 -> 24;
            default -> throw new IOException("Unsupported QCDT version " + version);
        };
        long tableEnd = 12 + count * entrySize;
        if (count <= 0 || count > 4096 || tableEnd > provider.length()) {
            throw new IOException("Invalid QCDT entry table");
        }

        Map<String, Dtb> unique = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            monitor.checkCancelled();
            byte[] e = provider.readBytes(12L + (long) i * entrySize, entrySize);
            long platform = u32(e, 0);
            long variant = u32(e, 4);
            long revision = u32(e, 8);
            long subtype;
            long offset;
            long size;
            if (version == 1) {
                subtype = 0;
                offset = u32(e, 12);
                size = u32(e, 16);
            }
            else {
                subtype = u32(e, 12);
                offset = u32(e, 16);
                size = u32(e, 20);
            }
            if (size == 0 || offset < tableEnd || offset + size > provider.length()) {
                throw new IOException("QCDT entry " + i + " points outside image");
            }
            byte[] fdtHead = provider.readBytes(offset, 8);
            if ((fdtHead[0] & 0xff) != 0xd0 || (fdtHead[1] & 0xff) != 0x0d ||
                (fdtHead[2] & 0xff) != 0xfe || (fdtHead[3] & 0xff) != 0xed) {
                throw new IOException("QCDT entry " + i + " does not point at FDT magic");
            }
            long fdtSize = u32be(fdtHead, 4);
            if (fdtSize == 0 || fdtSize > size) {
                throw new IOException("QCDT entry " + i + " has invalid FDT size");
            }

            String key = offset + ":" + size;
            Dtb dtb = unique.computeIfAbsent(key, ignored -> new Dtb(offset, size));
            dtb.selectors.add(new Selector(platform, variant, revision, subtype));
        }

        int index = 0;
        for (Dtb dtb : unique.values()) {
            Selector first = dtb.selectors.get(0);
            String name = String.format("dtb/%02d_off%08x_p%04x_v%04x.dtb",
                index++, dtb.offset, first.platform(), first.variant());
            fsIndex.storeFile(name, nextIndex++, false, dtb.size, dtb);
        }
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
            throws IOException, CancelledException {
        Dtb dtb = fsIndex.getMetadata(file);
        return dtb == null ? null :
            new ByteProviderWrapper(provider, dtb.offset, dtb.size, file.getFSRL());
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        Dtb dtb = fsIndex.getMetadata(file);
        if (dtb == null) {
            return FileAttributes.EMPTY;
        }
        FileAttributes attrs = FileAttributes.of(
            FileAttribute.create(NAME_ATTR, file.getName()),
            FileAttribute.create(SIZE_ATTR, dtb.size),
            FileAttribute.create(COMMENT_ATTR,
                "QCDT DTB referenced by " + dtb.selectors.size() + " selector(s)"));
        attrs.add("Offset", String.format("0x%x", dtb.offset));
        for (int i = 0; i < dtb.selectors.size(); i++) {
            attrs.add("Selector " + i, dtb.selectors.get(i).toString());
        }
        return attrs;
    }

    private static long u32(byte[] b, int off) {
        return QualcommQcdtFileSystemFactory.u32le(b, off);
    }

    private static long u32be(byte[] b, int off) {
        return ((long) (b[off] & 0xff) << 24) |
            ((long) (b[off + 1] & 0xff) << 16) |
            ((long) (b[off + 2] & 0xff) << 8) |
            (long) (b[off + 3] & 0xff);
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
