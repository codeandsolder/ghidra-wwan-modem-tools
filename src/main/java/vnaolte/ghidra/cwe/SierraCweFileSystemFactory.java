package vnaolte.ghidra.cwe;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryByteProvider;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeBytesOnly;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public final class SierraCweFileSystemFactory
        implements GFileSystemFactoryByteProvider<SierraCweFileSystem>, GFileSystemProbeBytesOnly {

    @Override
    public int getBytesRequired() {
        return SierraCweHeader.HEADER_SIZE;
    }

    @Override
    public boolean probeStartBytes(FSRL containerFSRL, byte[] startBytes) {
        return SierraCweHeader.hasMagic(startBytes);
    }

    @Override
    public SierraCweFileSystem create(FSRLRoot targetFSRL, ByteProvider byteProvider,
            FileSystemService fsService, TaskMonitor monitor)
            throws IOException, CancelledException {
        SierraCweFileSystem fs = new SierraCweFileSystem(targetFSRL, byteProvider, fsService);
        fs.mount(monitor);
        return fs;
    }
}
