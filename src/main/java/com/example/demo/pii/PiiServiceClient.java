package com.example.demo.pii;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Calls the standalone pii-service (Microsoft Presidio, see pii-service/app.py) as a
 * second PII detection pass after PiiFilter's regex redaction, to catch unstructured
 * PII (names, addresses, locations) the regexes don't attempt.
 *
 * Fail-open by design: per AUDIT_AND_REFACTOR_PLAN.md section 4, availability of the
 * chat feature must not depend on this secondary service. Any failure (timeout,
 * connection refused, 5xx) is logged as a warning and the original/regex-redacted text
 * is returned unchanged rather than blocking the request.
 */
@Component
public class PiiServiceClient {

    private static final Logger log = LoggerFactory.getLogger(PiiServiceClient.class);

    private final WebClient webClient;

    public PiiServiceClient(WebClient.Builder webClientBuilder,
                             @Value("${pii.service.url:http://localhost:5001}") String piiServiceUrl) {
        this.webClient = webClientBuilder.baseUrl(piiServiceUrl).build();
    }

    /**
     * Sends text to pii-service's /analyze endpoint. On success, returns the
     * Presidio-anonymized text plus how many entities it found (surfaced so PiiFilter
     * can report PII-detection counts into the audit trail — see
     * AuditFilter.ATTR_PII_COUNT — instead of this only ever reaching a debug log line).
     * On any failure or timeout, fails open: logs a warning and returns the original
     * text unchanged, with a count of 0, via the onErrorResume fallback.
     */
    public Mono<Result> anonymize(String text) {
        if (text == null || text.isEmpty()) {
            return Mono.just(new Result(text == null ? "" : text, 0));
        }

        return webClient.post()
                .uri("/analyze")
                .bodyValue(Map.of("text", text))
                .retrieve()
                .bodyToMono(AnalyzeResponse.class)
                .timeout(Duration.ofSeconds(2))
                .retryWhen(Retry.backoff(1, Duration.ofMillis(200)))
                .map(resp -> {
                    if (resp.entitiesDetected != null && !resp.entitiesDetected.isEmpty()) {
                        log.warn("pii-service detected additional entities: {}", resp.entitiesDetected);
                    }
                    String anonymized = resp.anonymized != null ? resp.anonymized : text;
                    int count = resp.entitiesDetected != null ? resp.entitiesDetected.size() : resp.count;
                    return new Result(anonymized, count);
                })
                .onErrorResume(ex -> {
                    log.warn("pii-service unreachable or failed ({}) — failing open, " +
                            "forwarding text without secondary PII pass", ex.toString());
                    return Mono.just(new Result(text, 0));
                });
    }

    /** Mirrors pii-service's /analyze JSON response shape. */
    public static class AnalyzeResponse {
        public String original;
        public String anonymized;

        @JsonProperty("entities_detected")
        public List<String> entitiesDetected;

        public int count;
    }

    /**
     * anonymize()'s result: the (possibly anonymized) text, and how many entities
     * pii-service's Presidio pass found — 0 both for "found nothing" and for "service
     * was unreachable, failed open" (PiiFilter doesn't need to distinguish those two
     * cases for audit purposes; either way no second-pass redaction count applies).
     */
    public record Result(String text, int entityCount) {
    }
}
