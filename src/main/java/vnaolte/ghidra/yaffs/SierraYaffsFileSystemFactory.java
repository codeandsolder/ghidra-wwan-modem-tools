package vnaolte.ghidra.yaffs;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Detects the YAFFS2 geometry used by Sierra Wireless SWI9X30C firmware:
 * 4096 bytes of data followed by 160 bytes of spare/OOB containing packed tags.
 */
public final class SierraYaffsFileSystemFactory
        implements GFileSystemFactoryByteProvider<SierraYaffsFileSystem>,
        GFileSystemProbeBytesOnly {

    @Override
    public int getBytesRequired() {
        return SierraYaffsFileSystem.RECORD_SIZE;
    }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] bytes) {
        if (bytes.length < SierraYaffsFileSystem.RECORD_SIZE) {
            return false;
        }

        long type = u32le(bytes, 0);
        long parent = u32le(bytes, 4);
        long seq = u32le(bytes, SierraYaffsFileSystem.DATA_SIZE);
        long objectId = u32le(bytes, SierraYaffsFileSystem.DATA_SIZE + 4);
        long chunkId = u32le(bytes, SierraYaffsFileSystem.DATA_SIZE + 8);
        return type == 3 && parent == 1 && bytes[10] == 0 &&
            seq != 0 && seq != 0xffffffffL && objectId == 1 && chunkId == 0;
    }

    @Override
    public SierraYaffsFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
            FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {
        SierraYaffsFileSystem fs =
            new SierraYaffsFileSystem(targetFSRL, byteProvider, fsService);
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
