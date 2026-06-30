package com.example.demo.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;

public class AuditLogStoreTest {

    private AuditLogStore store;

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        // Use a throwaway file in JUnit's per-test temp dir so test runs never write
        // an audit.db into the repo working directory.
        store = new AuditLogStore(tempDir.resolve("audit-test.db").toString());
    }

    private AuditEntry makeEntry(String event) {
        return new AuditEntry(
            "test-correlation-id", "2026-01-01 00:00:00", "testuser", "POST", "/llm/chat",
            200, "100ms", event, 10, 50, 60, 0.0
        );
    }

    @Test
    void testAddEntry() {
        store.add(makeEntry("ALLOWED"));
        assertEquals(1, store.getLogs().size());
    }

    @Test
    void testLogsReturnedNewestFirst() {
        store.add(makeEntry("ALLOWED"));
        store.add(makeEntry("BLOCKED_GUARDRAIL"));
        assertEquals("BLOCKED_GUARDRAIL", store.getLogs().get(0).getEvent());
    }

    @Test
    void testMaxCapacity() {
        for (int i = 0; i < 110; i++) {
            store.add(makeEntry("ALLOWED"));
        }
        assertTrue(store.getLogs().size() <= 100);
    }

    @Test
    void testEmptyStoreReturnsEmptyList() {
        assertTrue(store.getLogs().isEmpty());
    }

    @Test
    void testAuditEntryFields() {
        AuditEntry entry = makeEntry("ALLOWED");
        assertEquals("testuser", entry.getUser());
        assertEquals("POST", entry.getMethod());
        assertEquals(200, entry.getStatusCode());
        assertEquals(60, entry.getTotalTokens());
        assertEquals(0.0, entry.getToxicityScore());
    }
}
