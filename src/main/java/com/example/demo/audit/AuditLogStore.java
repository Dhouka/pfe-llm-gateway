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
        } catch (SQLException e) {
            log.warn("Failed to persist audit entry to SQLite ({}) — entry remains in the " +
                    "in-memory log but will be lost on restart: {}", jdbcUrl, e.toString());
        }
    }

    public List<AuditEntry> getLogs() {
        List<AuditEntry> reversed = new ArrayList<>(logs);
        Collections.reverse(reversed);
        return reversed;
    }

    public int getTotal() { return logs.size(); }
}
