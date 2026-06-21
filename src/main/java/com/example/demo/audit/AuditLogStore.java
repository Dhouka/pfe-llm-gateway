package com.example.demo.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory log (capped at 100, oldest evicted — used for the /audit endpoint's
 * "recent activity" view) plus an append-only JSONL file on disk, so a restart no
 * longer loses audit history outright (AUDIT_AND_REFACTOR_PLAN.md issue #5).
 *
 * This is a pragmatic middle ground, not a full persistence layer: a real Postgres/
 * SQLite-backed store (as the plan suggests) would give querying, retention policy,
 * and concurrent-write guarantees that a flat file doesn't. Appends here are
 * synchronized to avoid interleaved writes under concurrent requests; if this needs to
 * survive real production load or be queried at all (vs. just "not lost"), replace
 * this file-backed log with a Spring Data repository.
 */
@Component
public class AuditLogStore {

    private static final Logger log = LoggerFactory.getLogger(AuditLogStore.class);

    private final CopyOnWriteArrayList<AuditEntry> logs = new CopyOnWriteArrayList<>();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Path logFile;

    public AuditLogStore(@Value("${audit.log.file:audit-log.jsonl}") String logFilePath) {
        this.logFile = Paths.get(logFilePath);
    }

    public void add(AuditEntry entry) {
        logs.add(entry);
        if (logs.size() > 100) {
            logs.remove(0);
        }
        persist(entry);
    }

    private synchronized void persist(AuditEntry entry) {
        try {
            String line = objectMapper.writeValueAsString(entry) + System.lineSeparator();
            Files.writeString(logFile, line, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException e) {
            log.warn("Failed to persist audit entry to {} — entry remains in the in-memory " +
                    "log but will be lost on restart: {}", logFile, e.toString());
        }
    }

    public List<AuditEntry> getLogs() {
        List<AuditEntry> reversed = new ArrayList<>(logs);
        Collections.reverse(reversed);
        return reversed;
    }

    public int getTotal() { return logs.size(); }
}
