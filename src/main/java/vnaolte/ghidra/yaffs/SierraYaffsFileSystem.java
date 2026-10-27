package vnaolte.ghidra.yaffs;

import static ghidra.formats.gfilesystem.fileinfo.FileAttributeType.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.formats.gfilesystem.FSRLRoot;
import ghidra.formats.gfilesystem.FileSystemIndexHelper;
import ghidra.formats.gfilesystem.FileSystemRefManager;
import ghidra.formats.gfilesystem.FileSystemService;
import ghidra.formats.gfilesystem.GFile;
import ghidra.formats.gfilesystem.GFileSystem;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.fileinfo.FileAttribute;
import ghidra.formats.gfilesystem.fileinfo.FileAttributes;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * YAFFS2 reader for the raw-NAND images embedded in Sierra SWI9X30C CWE
 * firmware. Ghidra 11.1's stock YAFFS2 reader hard-codes 2048+64 byte NAND
 * geometry; these images use 4096+160 and otherwise get parsed half a page out
 * of phase.
 *
 * The implementation reconstructs the logical filesystem from packed OOB tags
 * instead of treating pages as a sequential archive. That is the YAFFS model
 * and also handles erased pages and historical object versions correctly.
 */
@FileSystemInfo(type = "yaffswide",
    description = "YAFFS2 (4096+160 Sierra/Qualcomm NAND geometry)",
    priority = FileSystemInfo.PRIORITY_HIGH,
    factory = SierraYaffsFileSystemFactory.class)
public final class SierraYaffsFileSystem implements GFileSystem {
    public static final int DATA_SIZE = 4096;
    public static final int SPARE_SIZE = 160;
    public static final int RECORD_SIZE = DATA_SIZE + SPARE_SIZE;

    private static final int TYPE_FILE = 1;
    private static final int TYPE_SYMLINK = 2;
    private static final int TYPE_DIRECTORY = 3;
    private static final int TYPE_HARDLINK = 4;

    private final FSRLRoot fsFSRL;
    @SuppressWarnings("unused")
    private final FileSystemService fsService;
    private final FileSystemIndexHelper<Node> fsIndex;
    private final FileSystemRefManager refManager = new FileSystemRefManager(this);
    private final Map<Long, GFile> filesByObjectId = new HashMap<>();
    private ByteProvider provider;
    private long nextIndex = 1;

    private static final class PageRef {
        final long sequence;
        final long recordIndex;
        final int byteCount;

        PageRef(long sequence, long recordIndex, int byteCount) {
            this.sequence = sequence;
            this.recordIndex = recordIndex;
            this.byteCount = byteCount;
        }
    }

    private static final class Node {
        long objectId;
        long parentId;
        int type;
        String name;
        long size;
        long sequence;
        long headerRecord;
        long equivalentId;
        String alias;
        long mode;
        long uid;
        long gid;
        final Map<Long, PageRef> pages = new HashMap<>();

        boolean isDirectory() {
            return type == TYPE_DIRECTORY;
        }
    }

    SierraYaffsFileSystem(FSRLRoot fsFSRL, ByteProvider provider,
            FileSystemService fsService) {
        this.fsFSRL = fsFSRL;
        this.provider = provider;
        this.fsService = fsService;
        this.fsIndex = new FileSystemIndexHelper<>(this, fsFSRL);
    }

    void mount(TaskMonitor monitor) throws IOException, CancelledException {
        monitor.setMessage("Scanning YAFFS2 4096+160 NAND pages...");
        long length = provider.length();
        if (length == 0 || length % RECORD_SIZE != 0) {
            throw new IOException("Image length " + length +
                " is not aligned to 4096+160-byte YAFFS records");
        }

        long recordCount = length / RECORD_SIZE;
        Map<Long, Node> nodes = new HashMap<>();
        Map<Long, Map<Long, PageRef>> dataPages = new HashMap<>();

        for (long rec = 0; rec < recordCount; rec++) {
            monitor.checkCancelled();
            long dataOff = rec * RECORD_SIZE;
            long tagOff = dataOff + DATA_SIZE;

            long sequence = u32(tagOff);
            long objectId = u32(tagOff + 4);
            long chunkId = u32(tagOff + 8);
            long byteCountRaw = u32(tagOff + 12);

            if (sequence == 0 || sequence == 0xffffffffL ||
                objectId == 0 || objectId == 0xffffffffL) {
                continue;
            }

            if (chunkId == 0) {
                int type = (int) u32(dataOff);
                if (type < 1 || type > 5) {
                    continue;
                }
                Node candidate = parseHeader(dataOff, rec, sequence, objectId, type);
                Node current = nodes.get(objectId);
                if (current == null ||
                    newer(candidate.sequence, candidate.headerRecord,
                        current.sequence, current.headerRecord)) {
                    nodes.put(objectId, candidate);
                }
                continue;
            }

            if (chunkId >= 0x100000L) {
                continue;
            }
            int byteCount =
                (byteCountRaw == 0xffffL || byteCountRaw == 0xffffffffL)
                    ? DATA_SIZE
                    : (int) Math.min(byteCountRaw, DATA_SIZE);
            Map<Long, PageRef> pages =
                dataPages.computeIfAbsent(objectId, ignored -> new HashMap<>());
            PageRef current = pages.get(chunkId);
            if (current == null ||
                newer(sequence, rec, current.sequence, current.recordIndex)) {
                pages.put(chunkId, new PageRef(sequence, rec, byteCount));
            }
        }

        for (Map.Entry<Long, Map<Long, PageRef>> e : dataPages.entrySet()) {
            Node node = nodes.get(e.getKey());
            if (node != null) {
                node.pages.putAll(e.getValue());
            }
        }

        Node root = nodes.get(1L);
        if (root == null || root.type != TYPE_DIRECTORY) {
            throw new IOException("No YAFFS root directory object found");
        }

        Map<Long, String> paths = new HashMap<>();
        paths.put(1L, "");
        for (Node node : nodes.values()) {
            if (node.objectId != 1) {
                resolvePath(node, nodes, paths, new HashSet<>());
            }
        }

        List<Node> ordered = new ArrayList<>(nodes.values());
        ordered.remove(root);
        ordered.removeIf(n -> !paths.containsKey(n.objectId));
        ordered.sort(Comparator
            .comparingInt((Node n) -> depth(paths.get(n.objectId)))
            .thenComparing(n -> paths.get(n.objectId)));

        for (Node node : ordered) {
            monitor.checkCancelled();
            String path = paths.get(node.objectId);
            GFile file = fsIndex.storeFile(path, nextIndex++, node.isDirectory(),
                node.isDirectory() ? 0 : node.size, node);
            filesByObjectId.put(node.objectId, file);
        }

        List<Node> orphans = new ArrayList<>();
        for (Node node : nodes.values()) {
            if (node.objectId != 1 && !paths.containsKey(node.objectId) &&
                node.name != null && !node.name.isBlank()) {
                orphans.add(node);
            }
        }
        if (!orphans.isEmpty()) {
            fsIndex.storeFile("_orphan", nextIndex++, true, 0, null);
            orphans.sort(Comparator.comparingLong(n -> n.objectId));
            for (Node node : orphans) {
                String path = "_orphan/obj_" + node.objectId + "_" + sanitize(node.name);
                GFile file = fsIndex.storeFile(path, nextIndex++, node.isDirectory(),
                    node.isDirectory() ? 0 : node.size, node);
                filesByObjectId.put(node.objectId, file);
            }
        }
    }

    private Node parseHeader(long dataOff, long record, long sequence, long objectId,
            int type) throws IOException {
        byte[] h = provider.readBytes(dataOff, 512);
        Node n = new Node();
        n.objectId = objectId;
        n.parentId = SierraYaffsFileSystemFactory.u32le(h, 4);
        n.type = type;
        n.name = stringZ(h, 10, 256);
        n.mode = SierraYaffsFileSystemFactory.u32le(h, 268);
        n.uid = SierraYaffsFileSystemFactory.u32le(h, 272);
        n.gid = SierraYaffsFileSystemFactory.u32le(h, 276);
        long low = SierraYaffsFileSystemFactory.u32le(h, 292);
        long high = SierraYaffsFileSystemFactory.u32le(h, 496);
        n.size = low == 0xffffffffL ? 0 : low;
        if (high != 0 && high != 0xffffffffL) {
            n.size |= high << 32;
        }
        n.equivalentId = SierraYaffsFileSystemFactory.u32le(h, 296);
        n.alias = stringZ(h, 300, 160);
        n.sequence = sequence;
        n.headerRecord = record;
        return n;
    }

    private static String resolvePath(Node node, Map<Long, Node> nodes,
            Map<Long, String> paths, Set<Long> visiting) {
        String cached = paths.get(node.objectId);
        if (cached != null) {
            return cached;
        }
        if (!visiting.add(node.objectId) || node.name == null || node.name.isBlank()) {
            return null;
        }

        String parent;
        if (node.parentId == 1) {
            parent = "";
        }
        else {
            Node parentNode = nodes.get(node.parentId);
            parent = parentNode == null ? null :
                resolvePath(parentNode, nodes, paths, visiting);
        }
        visiting.remove(node.objectId);
        if (parent == null) {
            return null;
        }

        String path = parent.isEmpty() ? sanitize(node.name) :
            parent + "/" + sanitize(node.name);
        paths.put(node.objectId, path);
        return path;
    }

    private static boolean newer(long seqA, long recA, long seqB, long recB) {
        return seqA > seqB || (seqA == seqB && recA > recB);
    }

    private static int depth(String path) {
        if (path == null || path.isEmpty()) {
            return 0;
        }
        int depth = 1;
        for (int i = 0; i < path.length(); i++) {
            if (path.charAt(i) == '/') {
                depth++;
            }
        }
        return depth;
    }

    @Override
    public ByteProvider getByteProvider(GFile file, TaskMonitor monitor)
            throws IOException, CancelledException {
        Node node = fsIndex.getMetadata(file);
        if (node == null || node.isDirectory()) {
            return null;
        }

        if (node.type == TYPE_SYMLINK) {
            return new ByteArrayProvider(
                node.alias.getBytes(StandardCharsets.UTF_8), file.getFSRL());
        }
        if (node.type == TYPE_HARDLINK) {
            GFile target = filesByObjectId.get(node.equivalentId);
            if (target == null) {
                throw new IOException("YAFFS hardlink target object " +
                    node.equivalentId + " not found");
            }
            return getByteProvider(target, monitor);
        }
        if (node.type != TYPE_FILE) {
            return new ByteArrayProvider(new byte[0], file.getFSRL());
        }
        if (node.size > Integer.MAX_VALUE) {
            throw new IOException("YAFFS file too large to materialize: " + file.getPath());
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream((int) node.size);
        long remaining = node.size;
        for (long chunk = 1; remaining > 0; chunk++) {
            monitor.checkCancelled();
            PageRef page = node.pages.get(chunk);
            if (page == null) {
                throw new IOException("Missing YAFFS chunk " + chunk + " for " +
                    file.getPath() + " (object " + node.objectId + ")");
            }
            int wanted = (int) Math.min(remaining, DATA_SIZE);
            int count = Math.min(wanted, page.byteCount == 0 ? DATA_SIZE : page.byteCount);
            byte[] data = provider.readBytes(page.recordIndex * RECORD_SIZE, count);
            out.write(data, 0, data.length);
            remaining -= count;
            if (count != wanted) {
                throw new IOException("Short YAFFS chunk " + chunk + " for " +
                    file.getPath());
            }
        }
        return new ByteArrayProvider(out.toByteArray(), file.getFSRL());
    }

    @Override
    public FileAttributes getFileAttributes(GFile file, TaskMonitor monitor) {
        Node n = fsIndex.getMetadata(file);
        if (n == null) {
            return FileAttributes.EMPTY;
        }

        String kind = switch (n.type) {
            case TYPE_FILE -> "file";
            case TYPE_SYMLINK -> "symlink";
            case TYPE_DIRECTORY -> "directory";
            case TYPE_HARDLINK -> "hardlink";
            default -> "special";
        };

        FileAttributes attrs = FileAttributes.of(
            FileAttribute.create(NAME_ATTR, n.name),
            FileAttribute.create(SIZE_ATTR, n.size),
            FileAttribute.create(COMMENT_ATTR,
                "YAFFS object " + n.objectId + " (" + kind + ")"));
        attrs.add("Object ID", n.objectId);
        attrs.add("Parent object ID", n.parentId);
        attrs.add("Object type", kind);
        attrs.add("Sequence", String.format("0x%x", n.sequence));
        attrs.add("Mode", String.format("0%o", n.mode));
        attrs.add("UID", n.uid);
        attrs.add("GID", n.gid);
        if (n.type == TYPE_SYMLINK) {
            attrs.add(SYMLINK_DEST_ATTR, n.alias);
        }
        if (n.type == TYPE_HARDLINK) {
            attrs.add("Equivalent object", n.equivalentId);
        }
        return attrs;
    }

    private long u32(long offset) throws IOException {
        return SierraYaffsFileSystemFactory.u32le(provider.readBytes(offset, 4), 0);
    }

    private static String stringZ(byte[] b, int off, int len) {
        int end = off;
        int limit = Math.min(b.length, off + len);
        while (end < limit && b[end] != 0 && (b[end] & 0xff) != 0xff) {
            end++;
        }
        return new String(b, off, end - off, StandardCharsets.ISO_8859_1);
    }

    private static String sanitize(String s) {
        return s.replace('/', '_').replace('\\', '_');
    }

    @Override
    public void close() throws IOException {
        refManager.onClose();
        filesByObjectId.clear();
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
    @Override public List<GFile> getListing(GFile directory) {
        return fsIndex.getListing(directory);
    }
}
