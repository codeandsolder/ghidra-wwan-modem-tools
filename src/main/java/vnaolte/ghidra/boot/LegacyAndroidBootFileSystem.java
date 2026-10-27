package vnaolte.ghidra.boot;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import ghidra.app.util.bin.ByteArrayProvider;
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

/** Classic Android boot image (pre-v1 header_version field). */
@FileSystemInfo(type = "androidbootlegacy",
    description = "Legacy Android boot image (dt_size header)",
    priority = FileSystemInfo.PRIORITY_HIGH,
    factory = LegacyAndroidBootFileSystemFactory.class)
public final class LegacyAndroidBootFileSystem implements GFileSystem {
    private final FSRLRoot fsFSRL;
    private final FileSystemIndexHelper<Entry> fsIndex;
    private final FileSystemRefManager refManager = new FileSystemRefManager(this);
    private ByteProvider provider;
    private long nextIndex = 1;

    private record Entry(String name, long offset, long size, long loadAddress,
            String kind, byte[] virtualData) {
        boolean virtual() { return virtualData != null; }
    }

    LegacyAndroidBootFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
        this.fsFSRL = fsFSRL;
        this.provider = provider;
        this.fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);
    }

    void mount(TaskMonitor monitor) throws IOException, CancelledException {
        monitor.setMessage("Parsing legacy Android boot image...");
        byte[] h = provider.readBytes(0, (int) Math.min(provider.length(), 1632));
        if (h.length < 64) {
            throw new IOException("Truncated Android boot header");
        }

        long kernelSize = u32(h, 0x08);
        long kernelAddr = u32(h, 0x0c);
        long ramdiskSize = u32(h, 0x10);
        long ramdiskAddr = u32(h, 0x14);
        long secondSize = u32(h, 0x18);
        long secondAddr = u32(h, 0x1c);
        long tagsAddr = u32(h, 0x20);
        long pageSize = u32(h, 0x24);
        long dtSize = u32(h, 0x28);

        if (pageSize < 0x800 || pageSize > 0x10000 ||
            (pageSize & (pageSize - 1)) != 0) {
            throw new IOException("Implausible Android boot page size: " + pageSize);
        }

        long kernelOff = pageSize;
        long ramdiskOff = align(kernelOff + kernelSize, pageSize);
        long secondOff = align(ramdiskOff + ramdiskSize, pageSize);
        long dtOff = align(secondOff + secondSize, pageSize);
        long end = dtOff + dtSize;
        if (end > provider.length()) {
            throw new IOException("Android boot sections exceed container: end=0x" +
                Long.toHexString(end) + " length=0x" + Long.toHexString(provider.length()));
        }

        addRegion("kernel.bin", kernelOff, kernelSize, kernelAddr, "kernel");
        if (ramdiskSize != 0) {
            addRegion("ramdisk.bin", ramdiskOff, ramdiskSize, ramdiskAddr, "ramdisk");
        }
        if (secondSize != 0) {
            addRegion("second.bin", secondOff, secondSize, secondAddr, "second stage");
        }
        if (dtSize != 0) {
            addRegion("dt.img", dtOff, dtSize, 0, "device-tree table");
        }

        String board = stringZ(h, 0x30, 16);
        String cmdline = stringZ(h, 0x40, Math.min(512, Math.max(0, h.length - 0x40)));
        if (h.length >= 1632) {
            cmdline += stringZ(h, 608, 1024);
        }
        String info = "board=" + board + "\n" +
            "kernel_addr=0x" + Long.toHexString(kernelAddr) + "\n" +
            "ramdisk_addr=0x" + Long.toHexString(ramdiskAddr) + "\n" +
            "second_addr=0x" + Long.toHexString(secondAddr) + "\n" +
            "tags_addr=0x" + Long.toHexString(tagsAddr) + "\n" +
            "page_size=0x" + Long.toHexString(pageSize) + "\n" +
            "cmdline=" + cmdline.trim() + "\n";
        byte[] data = info.getBytes(StandardCharsets.UTF_8);
        fsIndex.storeFile("boot-header.txt", nextIndex++, false, data.length,
            new Entry("boot-header.txt", 0, data.length, 0, "metadata", data));
    }

    private void addRegion(String name, long offset, long size, long loadAddress, String kind) throws IOException {
        fsIndex.storeFile(name, nextIndex++, false, size,
            new Entry(name, offset, size, loadAddress, kind, null));
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
            throws IOException, CancelledException {
        Entry e = fsIndex.getMetadata(file);
        if (e == null) {
            return null;
        }
        if (e.virtual()) {
            return new ByteArrayProvider(e.virtualData(), file.getFSRL());
        }
        return new ByteProviderWrapper(provider, e.offset(), e.size(), file.getFSRL());
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        Entry e = fsIndex.getMetadata(file);
        if (e == null) {
            return FileAttributes.EMPTY;
        }
        FileAttributes attrs = FileAttributes.of(
            FileAttribute.create(NAME_ATTR, e.name()),
            FileAttribute.create(SIZE_ATTR, e.size()),
            FileAttribute.create(COMMENT_ATTR, "Android boot " + e.kind()));
        if (e.loadAddress() != 0) {
            attrs.add("Load address", String.format("0x%08x", e.loadAddress()));
        }
        return attrs;
    }

    private static long align(long value, long alignment) {
        return (value + alignment - 1) & -alignment;
    }

    private static long u32(byte[] b, int off) {
        return LegacyAndroidBootFileSystemFactory.u32le(b, off);
    }

    private static String stringZ(byte[] b, int off, int len) {
        int end = off;
        int limit = Math.min(b.length, off + len);
        while (end < limit && b[end] != 0) {
            end++;
        }
        return new String(b, off, end - off, StandardCharsets.ISO_8859_1);
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
