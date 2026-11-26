package vnaolte.ghidra.boot;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Detects the pre-header_version Android boot image layout used by SWI9X30C. */
public final class LegacyAndroidBootFileSystemFactory
        implements GFileSystemFactoryByteProvider<LegacyAndroidBootFileSystem>,
        GFileSystemProbeBytesOnly {
    private static final int PROBE_SIZE = 64;

    @Override
    public int getBytesRequired() {
        return PROBE_SIZE;
    }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] b) {
        if (b.length < PROBE_SIZE ||
            b[0] != 'A' || b[1] != 'N' || b[2] != 'D' || b[3] != 'R' ||
            b[4] != 'O' || b[5] != 'I' || b[6] != 'D' || b[7] != '!') {
            return false;
        }
        long pageSize = u32le(b, 0x24);
        long dtSize = u32le(b, 0x28);
        long unused = u32le(b, 0x2c);
        boolean plausiblePage = pageSize >= 0x800 && pageSize <= 0x10000 &&
            (pageSize & (pageSize - 1)) == 0;
        // Modern boot headers store header_version at 0x28.  A value far larger
        // than any header version is the old dt_size field instead.
        return plausiblePage && dtSize > 16 && dtSize < 64L * 1024 * 1024 && unused == 0;
    }

    @Override
    public LegacyAndroidBootFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
            FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {
        LegacyAndroidBootFileSystem fs =
            new LegacyAndroidBootFileSystem(targetFSRL, byteProvider);
        fs.mount(monitor);
        return fs;
    }

    static long u32le(byte[] b, int off) {
        return (long) (b[off] & 0xff) |
            ((long) (b[off + 1] & 0xff) << 8) |
            ((long) (b[off + 2] & 0xff) << 16) |
            ((long) (b[off + 3] & 0xff) << 24);
    }
}
