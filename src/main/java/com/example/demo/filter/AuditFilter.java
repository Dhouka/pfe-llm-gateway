package com.example.demo.filter;

import com.example.demo.audit.AuditEntry;
import com.example.demo.audit.AuditLogStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

/**
 * Records one AuditEntry per request into the in-memory AuditLogStore.
 *
 * Originally implemented as a Spring Cloud Gateway GlobalFilter (order Integer.MIN_VALUE),
 * which only runs for requests matched by a configured route — with
 * spring.cloud.gateway.routes empty, audit logging never actually executed against real
 * traffic via this filter. Converted to a plain WebFlux WebFilter so it runs for every
 * request regardless of gateway routing (see AUDIT_AND_REFACTOR_PLAN.md section 2/4).
 *
 * LlmController previously wrote its OWN AuditEntry directly into AuditLogStore, which
 * combined with this filter meant a single /llm/chat call produced two divergent audit
 * entries. LlmController now sets exchange attributes (llm.event, llm.promptTokens,
 * llm.completionTokens, llm.totalTokens, llm.toxicityScore) instead of writing directly;
 * this filter is the single place that actually calls auditLogStore.add(), and it reads
 * those attributes when present to enrich the entry with token/toxicity data.
 *
 * PiiFilter (order -1, runs before this filter's doFinally fires, since it's
 * earlier in the chain wrapping the same exchange) sets llm.piiDetected/llm.piiCount
 * after redaction, so PII handling is visible per-request in the audit trail instead of
 * only ever reaching a debug log line — see GET /audit and dashboard.html.
 *
 * The "user" recorded on each AuditEntry comes from exchange.getPrincipal() (the
 * authenticated JWT principal's name — the "sub" claim by default, set by Spring
 * Security's reactive resource-server support once a token passes validation),
 * falling back to "anonymous" for unauthenticated requests (e.g. a 401 on /audit before
 * a token is even checked). Until 2026-06-25 this was hardcoded to the literal string
 * "anonymous" for every request, including authenticated ones — a real gap for a
 * banking-context audit trail, where per-user traceability is the point of the
 * exercise, not just request counts. Fixed by resolving the principal reactively before
 * building the AuditEntry, rather than reading a synchronous/non-existent field.
 *
 * doFinally (not doAfterTerminate) wraps the chain so an audit entry is still written
 * if the client cancels the connection mid-request (e.g. closes the socket before a
 * slow /llm/chat completes) — doAfterTerminate only fires on normal completion or
 * error, silently dropping the audit entry for a cancelled request, which is not
 * acceptable for a compliance-oriented audit trail.
 */
@Component
@Order(Integer.MIN_VALUE)
public class AuditFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(AuditFilter.class);

    public static final String ATTR_EVENT = "llm.event";
    public static final String ATTR_PROMPT_TOKENS = "llm.promptTokens";
    public static final String ATTR_COMPLETION_TOKENS = "llm.completionTokens";
    public static final String ATTR_TOTAL_TOKENS = "llm.totalTokens";
    public static final String ATTR_TOXICITY_SCORE = "llm.toxicityScore";
    public static final String ATTR_CORRELATION_ID = "llm.correlationId";
    public static final String ATTR_PII_DETECTED = "llm.piiDetected";
    public static final String ATTR_PII_COUNT = "llm.piiCount";
    public static final String ATTR_MATCHED_CATEGORY = "llm.matchedCategory";
    public static final String ATTR_MATCHED_PATTERN = "llm.matchedPattern";
    public static final String MDC_CORRELATION_ID = "correlationId";

    private final AuditLogStore auditLogStore;

    public AuditFilter(AuditLogStore auditLogStore) {
        this.auditLogStore = auditLogStore;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String requestPath = exchange.getRequest().getPath().value();

        // Found 2026-06-30: this filter used to log every single request unconditionally,
        // including requests to /audit, /audit/summary, /audit/detail/{id} and
        // /actuator/health themselves. The dashboard (llm-flask-service) polls /audit and
        // /audit/summary every ~3s, so each poll wrote its own audit entry — a
        // self-amplifying feedback loop where watching the audit log pollutes the audit
        // log. Combined with AuditLogStore.persist()'s synchronized, blocking SQLite write,
        // concurrent polling traffic queued up behind that single lock, producing latencies
        // of 5-190+ seconds on requests that do no real work (observed directly: /audit and
        // /audit/summary entries clustering at ~5000ms, the SQLite busy_timeout budget, and
        // /actuator/health entries up to 190s from queuing behind many such waits). Excluding
        // these monitoring/meta paths from the audit trail itself stops both the noise (100
        // "recent" log entries being nothing but dashboard self-polling, zero real /llm/chat
        // traffic) and the contention it was causing.
        if (requestPath.startsWith("/audit") || requestPath.startsWith("/actuator")) {
            return chain.filter(exchange);
        }

        long startTime = System.currentTimeMillis();
        String path = requestPath;
        String method = exchange.getRequest().getMethod().name();
        String timestamp = LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // One correlation ID per request, exposed as an exchange attribute so
        // LlmController (and any other downstream component) can log it too, tying
        // together log lines and the eventual audit row for the same request. MDC is
        // set on a best-effort basis here — in a WebFlux app MDC doesn't reliably
        // propagate across async/thread boundaries, so it covers the synchronous part
        // of the chain (this filter's own log lines); the value on the AuditEntry
        // itself is the reliable way to correlate the full request end-to-end.
        String correlationId = UUID.randomUUID().toString();
        exchange.getAttributes().put(ATTR_CORRELATION_ID, correlationId);
        MDC.put(MDC_CORRELATION_ID, correlationId);

        return exchange.getPrincipal()
                .map(Principal::getName)
                .defaultIfEmpty("anonymous")
                .onErrorReturn("anonymous")
                .flatMap(user -> chain.filter(exchange).doFinally(signalType -> {
                    try {
                        MDC.put(MDC_CORRELATION_ID, correlationId);
                        long latency = System.currentTimeMillis() - startTime;

                        int statusCode = 0;
                        try {
                            statusCode = exchange.getResponse().getStatusCode().value();
                        } catch (Exception e) {
                            statusCode = 0;
                        }

                        String event = exchange.getAttributeOrDefault(ATTR_EVENT, null);
                        if (event == null) {
                            event = "ALLOWED";
                            if (statusCode == 401) event = "BLOCKED_NO_AUTH";
                            else if (statusCode == 429) event = "BLOCKED_RATE_LIMIT";
                            else if (statusCode == 451) event = "BLOCKED_GUARDRAIL";
                            else if (statusCode == 403) event = "BLOCKED_FORBIDDEN";
                        }

                        int promptTokens = exchange.getAttributeOrDefault(ATTR_PROMPT_TOKENS, 0);
                        int completionTokens = exchange.getAttributeOrDefault(ATTR_COMPLETION_TOKENS, 0);
                        int totalTokens = exchange.getAttributeOrDefault(ATTR_TOTAL_TOKENS, 0);
                        double toxicityScore = exchange.getAttributeOrDefault(ATTR_TOXICITY_SCORE, 0.0);
                        boolean piiDetected = exchange.getAttributeOrDefault(ATTR_PII_DETECTED, false);
                        int piiCount = exchange.getAttributeOrDefault(ATTR_PII_COUNT, 0);
                        String matchedCategory = exchange.getAttributeOrDefault(ATTR_MATCHED_CATEGORY, null);
                        String matchedPattern = exchange.getAttributeOrDefault(ATTR_MATCHED_PATTERN, null);

                        AuditEntry entry = new AuditEntry(
                                correlationId, timestamp, user, method, path,
                                statusCode, latency + "ms", event,
                                promptTokens, completionTokens, totalTokens, toxicityScore,
                                piiDetected, piiCount, matchedCategory, matchedPattern
                        );

                        auditLogStore.add(entry);
                        log.info("AUDIT: {}", entry);
                    } finally {
                        MDC.remove(MDC_CORRELATION_ID);
                    }
                }));
    }

    @Override
    public int getOrder() {
        return Integer.MIN_VALUE;
    }
}
