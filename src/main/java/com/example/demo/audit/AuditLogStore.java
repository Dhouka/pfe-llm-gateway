package com.example.demo.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory log (capped at 100, oldest evicted — used for the /audit endpoint's
 * "recent activity" view) plus a real on-disk SQLite database, so a restart no
 * longer loses audit history (AUDIT_AND_REFACTOR_PLAN.md issue #5).
 *
 * This used to append JSON lines to a flat file (audit-log.jsonl) — that was a
 * pragmatic stopgap, not a real persistence layer: no querying, no indices, no
 * concurrent-write guarantees beyond "don't interleave writes." Replaced with a
 * single-table SQLite database (plain JDBC, no JPA needed for one table) so the
 * audit trail can actually be queried/retained for a compliance use case, not just
 * "not lost on restart." Inserts are synchronized on the single shared JDBC
 * Connection — SQLite itself serializes writers at the file level regardless, so
 * this just avoids two threads issuing statements on the same Connection object
 * concurrently (not SQLite-safe).
 *
 * Hardened 2026-06-25 against concurrent-write contention (e.g. another process — a
 * "sqlite3 audit.db ..." compliance query mentioned in CLAUDE.md, or a future
 * second gateway instance — touching the same file while this JVM is writing):
 * (1) PRAGMA busy_timeout tells SQLite's own engine to retry internally for up to
 * BUSY_TIMEOUT_MS before giving up and raising SQLITE_BUSY/SQLITE_LOCKED, instead of
 * failing immediately on the first lock contention; (2) persist() additionally retries
 * at the JDBC level with a short backoff if a SQLITE_BUSY/SQLITE_LOCKED SQLException
 * still gets through (e.g. a WAL checkpoint blocking briefly longer than the pragma
 * budget). Both layers fail open the same way the rest of this codebase does
 * (PiiServiceClient being the one deliberate exception, see its Javadoc) — after
 * retries are exhausted, the entry stays in the in-memory log (still visible via
 * /audit) but is logged as not persisted to disk, rather than blocking the request.
 */
@Component
public class AuditLogStore {

    private static final Logger log = LoggerFactory.getLogger(AuditLogStore.class);

    private static final String CREATE_TABLE_SQL = """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT,
                timestamp TEXT,
                user TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                latency TEXT,
                event TEXT,
                prompt_tokens INTEGER,
                completion_tokens INTEGER,
                total_tokens INTEGER,
                toxicity_score REAL,
                pii_detected INTEGER,
                pii_count INTEGER,
                matched_category TEXT,
                matched_pattern TEXT
            )
            """;

    private static final String INSERT_SQL = """
            INSERT INTO audit_log (correlation_id, timestamp, user, method, path, status_code,
                latency, event, prompt_tokens, completion_tokens, total_tokens, toxicity_score,
                pii_detected, pii_count, matched_category, matched_pattern)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    /** Budget given to SQLite's own internal busy-retry loop (PRAGMA busy_timeout), in ms. */
    private static final int BUSY_TIMEOUT_MS = 5000;

    /** JDBC-level retries attempted if a SQLITE_BUSY/SQLITE_LOCKED error still surfaces
     * after the busy_timeout budget is exhausted (e.g. a slow WAL checkpoint). */
    private static final int MAX_PERSIST_RETRIES = 3;
    private static final long RETRY_BACKOFF_MS = 100;

    private final CopyOnWriteArrayList<AuditEntry> logs = new CopyOnWriteArrayList<>();
    private final String jdbcUrl;
    private Connection connection;

    public AuditLogStore(@Value("${audit.db.file:audit.db}") String dbFilePath) {
        this.jdbcUrl = "jdbc:sqlite:" + dbFilePath;
        initSchema();
    }

    private synchronized void initSchema() {
        try {
            connection = DriverManager.getConnection(jdbcUrl);
            try (Statement stmt = connection.createStatement()) {
                stmt.execute("PRAGMA journal_mode=WAL");
                stmt.execute("PRAGMA busy_timeout=" + BUSY_TIMEOUT_MS);
                stmt.execute(CREATE_TABLE_SQL);
            }
        } catch (SQLException e) {
            log.error("Failed to initialize SQLite audit database at {} — audit history will " +
                    "not survive a restart until this is fixed: {}", jdbcUrl, e.toString());
            connection = null;
        }
    }

    public void add(AuditEntry entry) {
        logs.add(entry);
        if (logs.size() > 100) {
            logs.remove(0);
        }
        persist(entry);
    }

    private synchronized void persist(AuditEntry entry) {
        if (connection == null) {
            log.warn("SQLite connection unavailable — entry remains in the in-memory log but " +
                    "will be lost on restart");
            return;
        }

        for (int attempt = 1; attempt <= MAX_PERSIST_RETRIES; attempt++) {
            try (PreparedStatement ps = connection.prepareStatement(INSERT_SQL)) {
                ps.setString(1, entry.getCorrelationId());
                ps.setString(2, entry.getTimestamp());
                ps.setString(3, entry.getUser());
                ps.setString(4, entry.getMethod());
                ps.setString(5, entry.getPath());
                ps.setInt(6, entry.getStatusCode());
                ps.setString(7, entry.getLatency());
                ps.setString(8, entry.getEvent());
                ps.setInt(9, entry.getPromptTokens());
                ps.setInt(10, entry.getCompletionTokens());
                ps.setInt(11, entry.getTotalTokens());
                ps.setDouble(12, entry.getToxicityScore());
                ps.setInt(13, entry.isPiiDetected() ? 1 : 0);
                ps.setInt(14, entry.getPiiCount());
                ps.setString(15, entry.getMatchedCategory());
                ps.setString(16, entry.getMatchedPattern());
                ps.executeUpdate();
                return;
            } catch (SQLException e) {
                if (isBusyOrLocked(e) && attempt < MAX_PERSIST_RETRIES) {
                    log.warn("SQLite busy/locked persisting audit entry (attempt {}/{}) — " +
                            "retrying after {}ms backoff: {}", attempt, MAX_PERSIST_RETRIES,
                            RETRY_BACKOFF_MS, e.toString());
                    sleepBackoff(attempt);
                    continue;
                }
                log.warn("Failed to persist audit entry to SQLite ({}) — entry remains in the " +
                        "in-memory log but will be lost on restart: {}", jdbcUrl, e.toString());
                return;
            }
        }
    }

    /** SQLITE_BUSY=5, SQLITE_LOCKED=6 — the two transient-contention codes worth retrying.
     * Falls back to a message check since not every JDBC driver/wrapper surfaces the raw
     * SQLite result code via getErrorCode() consistently. */
    private boolean isBusyOrLocked(SQLException e) {
        if (e.getErrorCode() == 5 || e.getErrorCode() == 6) {
            return true;
        }
        String msg = e.getMessage();
        return msg != null && (msg.contains("SQLITE_BUSY") || msg.contains("SQLITE_LOCKED")
                || msg.contains("database is locked"));
    }

    private void sleepBackoff(int attempt) {
        try {
            Thread.sleep(RETRY_BACKOFF_MS * attempt);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    public List<AuditEntry> getLogs() {
        List<AuditEntry> reversed = new ArrayList<>(logs);
        Collections.reverse(reversed);
        return reversed;
    }

    public int getTotal() { return logs.size(); }
}
