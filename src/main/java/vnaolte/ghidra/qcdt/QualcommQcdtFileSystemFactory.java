package vnaolte.ghidra.qcdt;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class QualcommQcdtFileSystemFactory
        implements GFileSystemFactoryByteProvider<QualcommQcdtFileSystem>,
        GFileSystemProbeBytesOnly {
    @Override
    public int getBytesRequired() { return 16; }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] b) {
        if (b.length < 16 || b[0] != 'Q' || b[1] != 'C' || b[2] != 'D' || b[3] != 'T') {
            return false;
        }
        long version = u32le(b, 4);
        long count = u32le(b, 8);
        return version >= 1 && version <= 3 && count > 0 && count < 4096;
    }

    @Override
    public QualcommQcdtFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
            FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {
        QualcommQcdtFileSystem fs = new QualcommQcdtFileSystem(targetFSRL, byteProvider);
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
