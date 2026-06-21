package com.example.demo.filter;

import com.example.demo.pii.PiiServiceClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
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
 * (names, addresses, etc.). The second pass is fail-open — see PiiServiceClient.
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

    public PiiFilter(PiiServiceClient piiServiceClient) {
        this.piiServiceClient = piiServiceClient;
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

                    // Second pass: pii-service (Presidio), fail-open on error.
                    return piiServiceClient.anonymize(regexResult.text())
                            .defaultIfEmpty(new PiiServiceClient.Result(regexResult.text(), 0))
                            .flatMap(presidioResult -> {
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

    /** Regex redaction's outcome: the sanitized text, and how many of the 4 patterns fired. */
    private record RegexRedactionResult(String text, int matchCount) {
    }

    private RegexRedactionResult applyRegexRedaction(String body) {
        String sanitized = body;
        int matchCount = 0;
        if (EMAIL.matcher(sanitized).find()) {
            sanitized = EMAIL.matcher(sanitized).replaceAll("[EMAIL_REDACTED]");
            matchCount++;
        }
        if (CREDIT_CARD.matcher(sanitized).find()) {
            sanitized = CREDIT_CARD.matcher(sanitized).replaceAll("[CARD_REDACTED]");
            matchCount++;
        }
        if (CIN.matcher(sanitized).find()) {
            sanitized = CIN.matcher(sanitized).replaceAll("[CIN_REDACTED]");
            matchCount++;
        }
        if (PHONE.matcher(sanitized).find()) {
            sanitized = PHONE.matcher(sanitized).replaceAll("[PHONE_REDACTED]");
            matchCount++;
        }
        return new RegexRedactionResult(sanitized, matchCount);
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
