package mtk_mddb.ghidra;

import java.io.IOException;

import mtk_mddb.core.MddbDatabase;

/** Owns a database until both the UI and all background users have released it. */
final class DatabaseSession implements AutoCloseable {
    private final MddbDatabase database;
    private boolean retired;
    private int users;

    DatabaseSession(MddbDatabase database) {
        this.database = database;
    }

    synchronized Lease acquire() {
        if (retired) {
            throw new IllegalStateException("MDDB session has been replaced");
        }
        users++;
        return new Lease();
    }

    @Override
    public synchronized void close() throws IOException {
        if (retired) {
            return;
        }
        retired = true;
        if (users == 0) {
            database.close();
        }
    }

    final class Lease implements AutoCloseable {
        private boolean released;

        MddbDatabase database() {
            return database;
        }

        @Override
        public void close() throws IOException {
            synchronized (DatabaseSession.this) {
                if (released) {
                    return;
                }
                released = true;
                users--;
                if (retired && users == 0) {
                    database.close();
                }
            }
        }
    }
}
