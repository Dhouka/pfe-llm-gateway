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
 * PiiFilter (order -1, runs before this filter's doAfterTerminate fires, since it's
 * earlier in the chain wrapping the same exchange) sets llm.piiDetected/llm.piiCount
 * after redaction, so PII handling is visible per-request in the audit trail instead of
 * only ever reaching a debug log line — see GET /audit and dashboard.html.
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

        long startTime = System.currentTimeMillis();
        String path = exchange.getRequest().getPath().toString();
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

        return chain.filter(exchange).doAfterTerminate(() -> {
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
                        correlationId, timestamp, "anonymous", method, path,
                        statusCode, latency + "ms", event,
                        promptTokens, completionTokens, totalTokens, toxicityScore,
                        piiDetected, piiCount, matchedCategory, matchedPattern
                );

                auditLogStore.add(entry);
                log.info("AUDIT: {}", entry);
            } finally {
                MDC.remove(MDC_CORRELATION_ID);
            }
        });
    }

    @Override
    public int getOrder() {
        return Integer.MIN_VALUE;
    }
}
