package com.example.demo.filter;

import com.example.demo.audit.AuditEntry;
import com.example.demo.audit.AuditLogStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the real AuditFilter (now a WebFilter — see GlobalFilter-never-ran bug fix
 * in AUDIT_AND_REFACTOR_PLAN.md section 2/4), including the new behavior of reading
 * exchange attributes set by LlmController instead of only deriving the event from the
 * HTTP status code.
 */
class AuditFilterTest {

    @TempDir
    Path tempDir;

    private final AtomicInteger fileCounter = new AtomicInteger();

    /** Throwaway per-test log file so AuditLogStore's disk persistence never touches the repo. */
    private AuditLogStore newStore() {
        return new AuditLogStore(tempDir.resolve("audit-log-test-" + fileCounter.incrementAndGet() + ".jsonl").toString());
    }

    @Test
    void fallsBackToStatusCodeWhenNoAttributesSet() throws InterruptedException {
        AuditLogStore store = newStore();
        AuditFilter filter = new AuditFilter(store);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/audit").build());

        filter.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return Mono.empty();
        }).block();

        // doAfterTerminate runs after the returned Mono completes, but is itself async
        // relative to .block() returning in some edge cases; give it a brief moment.
        waitForLog(store);

        assertEquals(1, store.getLogs().size());
        AuditEntry entry = store.getLogs().get(0);
        assertEquals("BLOCKED_NO_AUTH", entry.getEvent());
        assertEquals(401, entry.getStatusCode());
    }

    @Test
    void usesEventAttributeWhenSetByController() throws InterruptedException {
        AuditLogStore store = newStore();
        AuditFilter filter = new AuditFilter(store);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/llm/chat").build());

        filter.filter(exchange, ex -> {
            ex.getAttributes().put(AuditFilter.ATTR_EVENT, "BLOCKED_TOXIC");
            ex.getAttributes().put(AuditFilter.ATTR_PROMPT_TOKENS, 12);
            ex.getAttributes().put(AuditFilter.ATTR_COMPLETION_TOKENS, 34);
            ex.getAttributes().put(AuditFilter.ATTR_TOTAL_TOKENS, 46);
            ex.getAttributes().put(AuditFilter.ATTR_TOXICITY_SCORE, 0.8);
            ex.getResponse().setStatusCode(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS);
            return Mono.empty();
        }).block();

        waitForLog(store);

        AuditEntry entry = store.getLogs().get(0);
        assertEquals("BLOCKED_TOXIC", entry.getEvent());
        assertEquals(46, entry.getTotalTokens());
        assertEquals(0.8, entry.getToxicityScore());
    }

    @Test
    void allowedRequestIsLoggedAsAllowed() throws InterruptedException {
        AuditLogStore store = newStore();
        AuditFilter filter = new AuditFilter(store);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/audit").build());

        filter.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        }).block();

        waitForLog(store);

        assertEquals("ALLOWED", store.getLogs().get(0).getEvent());
    }

    @Test
    void persistsPiiAttributesIntoAuditEntry() throws InterruptedException {
        AuditLogStore store = newStore();
        AuditFilter filter = new AuditFilter(store);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/llm/chat").build());

        filter.filter(exchange, ex -> {
            ex.getAttributes().put(AuditFilter.ATTR_PII_DETECTED, true);
            ex.getAttributes().put(AuditFilter.ATTR_PII_COUNT, 3);
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        }).block();

        waitForLog(store);

        AuditEntry entry = store.getLogs().get(0);
        assertTrue(entry.isPiiDetected());
        assertEquals(3, entry.getPiiCount());
    }

    @Test
    void defaultsPiiAttributesWhenNotSet() throws InterruptedException {
        AuditLogStore store = newStore();
        AuditFilter filter = new AuditFilter(store);
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/audit").build());

        filter.filter(exchange, ex -> {
            ex.getResponse().setStatusCode(HttpStatus.OK);
            return Mono.empty();
        }).block();

        waitForLog(store);

        AuditEntry entry = store.getLogs().get(0);
        assertFalse(entry.isPiiDetected());
        assertEquals(0, entry.getPiiCount());
    }

    private void waitForLog(AuditLogStore store) throws InterruptedException {
        for (int i = 0; i < 50 && store.getLogs().isEmpty(); i++) {
            Thread.sleep(10);
        }
    }
}
