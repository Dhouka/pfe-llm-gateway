package com.example.demo.filter;

import com.example.demo.pii.PiiServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Redacts PII from request bodies before they reach LlmController/Ollama.
 *
 * Originally implemented as a Spring Cloud Gateway GlobalFilter, which only runs for
 * requests matched by a configured route (spring.cloud.gateway.routes). Since this
 * project defines no routes, that meant PII redaction never actually executed against
 * real traffic. Converted to a plain WebFlux WebFilter, which registers against the
 * universal reactive filter chain and runs for every request regardless of gateway
 * routing — see AUDIT_AND_REFACTOR_PLAN.md section 2/4.
 *
 * Two-pass redaction: hand-written regexes catch structured PII (email, card, CIN,
 * phone) first; the result is then sent to pii-service (Presidio) for unstructured PII
 * (names, addresses, etc.). The second pass is fail-CLOSED by default (changed
 * 2026-06-25) — see PiiServiceClient's class Javadoc for the rationale. When
 * PiiServiceClient.Result.failed() is true, this filter short-circuits with HTTP 503
 * instead of forwarding a request whose unstructured-PII status couldn't be verified.
 * Configurable via pii.service.fail-closed (default true).
 *
 * Sets AuditFilter.ATTR_PII_DETECTED / ATTR_PII_COUNT (sum of regex matches + Presidio
 * entity count) on the exchange so AuditFilter can persist PII-handling visibility into
 * the audit trail — previously this only ever reached a debug log line, invisible to
 * compliance/audit consumers despite the PFE subject's audit requirement implying PII
 * tracing, not just token/latency/toxicity.
 */
@Component
@Order(-1)
public class PiiFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(PiiFilter.class);

    private static final Pattern EMAIL =
            Pattern.compile("[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
    private static final Pattern CIN =
            Pattern.compile("\\b\\d{8}\\b");
    private static final Pattern CREDIT_CARD =
            Pattern.compile("\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b");
    private static final Pattern PHONE =
            Pattern.compile("\\b(\\+216)?[2-9]\\d{7}\\b");

    private final PiiServiceClient piiServiceClient;
    private final boolean failClosed;

    public PiiFilter(PiiServiceClient piiServiceClient,
                      @Value("${pii.service.fail-closed:true}") boolean failClosed) {
        this.piiServiceClient = piiServiceClient;
        this.failClosed = failClosed;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        HttpMethod method = exchange.getRequest().getMethod();
        if (method != HttpMethod.POST && method != HttpMethod.PUT) {
            return chain.filter(exchange);
        }

        // NOTE: DataBufferUtils.join(...) yields a Mono<DataBuffer>, but everything downstream
        // of it (including forwardWithSanitizedBody) is typed Mono<Void> — and a Mono<Void>
        // structurally never emits an element (there's nothing to emit for Void), regardless
        // of whether the redaction/forwarding work actually ran. Attaching .switchIfEmpty(...)
        // *after* a flatMap that returns Mono<Void> therefore always sees "empty" and fires a
        // *second* chain.filter(exchange) call with the original, unmutated exchange — i.e.
        // every POST/PUT request was forwarded twice: once correctly redacted, then again with
        // raw, unredacted PII. Emptiness must be checked on the DataBuffer itself, before the
        // flatMap, so chain.filter() runs exactly once per request.
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .map(Optional::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(maybeBuffer -> {
                    if (maybeBuffer.isEmpty()) {
                        return chain.filter(exchange);
                    }

                    DataBuffer dataBuffer = maybeBuffer.get();
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    String originalBody = new String(bytes, StandardCharsets.UTF_8);

                    log.debug("PiiFilter — original body: {}", originalBody);

                    RegexRedactionResult regexResult = applyRegexRedaction(originalBody);

                    // Second pass: pii-service (Presidio), fail-closed on error by default.
                    return piiServiceClient.anonymize(regexResult.text())
                            .defaultIfEmpty(new PiiServiceClient.Result(regexResult.text(), 0, false))
                            .flatMap(presidioResult -> {
                                if (presidioResult.failed() && failClosed) {
                                    log.warn("PiiFilter — pii-service pass failed and fail-closed is " +
                                            "enabled; blocking request rather than forwarding text whose " +
                                            "unstructured-PII status could not be verified");
                                    exchange.getAttributes().put(AuditFilter.ATTR_EVENT, "BLOCKED_PII_SERVICE_DOWN");
                                    return rejectRequest(exchange);
                                }

                                String finalSanitized = presidioResult.text();
                                int totalPiiCount = regexResult.matchCount() + presidioResult.entityCount();
                                log.debug("PiiFilter — sanitized body: {} (piiCount={})",
                                        finalSanitized, totalPiiCount);

                                exchange.getAttributes().put(AuditFilter.ATTR_PII_DETECTED, totalPiiCount > 0);
                                exchange.getAttributes().put(AuditFilter.ATTR_PII_COUNT, totalPiiCount);

                                return forwardWithSanitizedBody(exchange, chain, finalSanitized);
                            });
                });
    }

    /**
     * Regex redaction's outcome: the sanitized text, and the true number of PII
     * occurrences redacted across all 4 patterns combined.
     *
     * Until 2026-06-25, matchCount was incremented by exactly 1 per pattern *type* that
     * matched at least once (i.e. "did this pattern fire", capped at 4 regardless of how
     * many actual matches it had) rather than the real occurrence count — so a body with
     * three emails and one phone number was reported as piiCount=2, not 4. That's wrong
     * for a compliance/audit trail, where the count is meant to reflect how much PII was
     * actually found and redacted. Fixed by counting Matcher.find() iterations per
     * pattern before replacing.
     */
    private record RegexRedactionResult(String text, int matchCount) {
    }

    private RegexRedactionResult applyRegexRedaction(String body) {
        String sanitized = body;
        int matchCount = 0;

        int emailMatches = countMatches(EMAIL, sanitized);
        if (emailMatches > 0) {
            sanitized = EMAIL.matcher(sanitized).replaceAll("[EMAIL_REDACTED]");
            matchCount += emailMatches;
        }

        int cardMatches = countMatches(CREDIT_CARD, sanitized);
        if (cardMatches > 0) {
            sanitized = CREDIT_CARD.matcher(sanitized).replaceAll("[CARD_REDACTED]");
            matchCount += cardMatches;
        }

        int cinMatches = countMatches(CIN, sanitized);
        if (cinMatches > 0) {
            sanitized = CIN.matcher(sanitized).replaceAll("[CIN_REDACTED]");
            matchCount += cinMatches;
        }

        int phoneMatches = countMatches(PHONE, sanitized);
        if (phoneMatches > 0) {
            sanitized = PHONE.matcher(sanitized).replaceAll("[PHONE_REDACTED]");
            matchCount += phoneMatches;
        }

        return new RegexRedactionResult(sanitized, matchCount);
    }

    /** Counts how many non-overlapping occurrences of pattern appear in text. */
    private static int countMatches(Pattern pattern, String text) {
        java.util.regex.Matcher matcher = pattern.matcher(text);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    /**
     * Short-circuits the chain with HTTP 503 when the secondary PII detection pass
     * (pii-service) failed and fail-closed mode is enabled — the request never reaches
     * LlmController/Ollama. Mirrors RateLimiterWebFilter's/OutputGuardrailFilter's
     * existing pattern of writing a stable JSON error body directly onto the response.
     */
    private Mono<Void> rejectRequest(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = ("{\"error\":\"PII detection service unavailable - request blocked " +
                "for security (fail-closed)\"}").getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

    private Mono<Void> forwardWithSanitizedBody(ServerWebExchange exchange, WebFilterChain chain, String sanitized) {
        byte[] sanitizedBytes = sanitized.getBytes(StandardCharsets.UTF_8);
        DataBuffer sanitizedBuffer = exchange.getResponse().bufferFactory().wrap(sanitizedBytes);

        ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                return Flux.just(sanitizedBuffer);
            }

            @Override
            public HttpHeaders getHeaders() {
                HttpHeaders headers = new HttpHeaders();
                headers.putAll(super.getHeaders());
                headers.setContentLength(sanitizedBytes.length);
                return headers;
            }
        };

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
