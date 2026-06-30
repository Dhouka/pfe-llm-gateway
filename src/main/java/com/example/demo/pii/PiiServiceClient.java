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
 * Fail-closed by design (changed 2026-06-25 — see PFE_TODO.md task "PII fail-closed"):
 * for a banking-client-facing PII gateway, silently forwarding unanalyzed text when the
 * secondary detection pass is down is a worse outcome than briefly refusing requests, so
 * a failure (timeout, connection refused, 5xx) is surfaced as Result.failed()=true instead
 * of being swallowed. The original text is still attached to the Result (regex-redacted
 * text, never raw) so a caller that explicitly wants fail-open behavior could still choose
 * to use it, but PiiFilter — the only current caller — short-circuits the request with an
 * error response when failed() is true, rather than forwarding. This is configurable via
 * pii.service.fail-closed (default true); set to false to restore the old fail-open
 * behavior if PII-pass availability turns out to be an unacceptable bottleneck in practice.
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
     * On any failure or timeout, the onErrorResume fallback logs a warning and returns a
     * Result with failed()=true (text is the original/regex-redacted input, unchanged,
     * for callers that want it, but PiiFilter treats failed()=true as a signal to block
     * the request rather than forward it — see class Javadoc).
     */
    public Mono<Result> anonymize(String text) {
        if (text == null || text.isEmpty()) {
            return Mono.just(new Result(text == null ? "" : text, 0, false));
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
                    // Found 2026-06-30: this used to prefer entitiesDetected.size() over
                    // resp.count. entitiesDetected (pii-service's "entities_detected" field)
                    // is a deduplicated list of distinct entity *types* ("PERSON",
                    // "EMAIL_ADDRESS", ...), not one entry per occurrence — see
                    // pii-service/app.py's detected_types = sorted({r.entity_type for r in
                    // results}). resp.count (len(results)) is the real occurrence count.
                    // Same class of bug as the regex matchCount fix from 2026-06-25
                    // (PiiFilter#countMatches) — 3 person names + 2 emails were being
                    // reported as piiCount=2 instead of 5 here. Always use resp.count.
                    int count = resp.count;
                    return new Result(anonymized, count, false);
                })
                .onErrorResume(ex -> {
                    log.warn("pii-service unreachable or failed ({}) — failing CLOSED, " +
                            "request will be blocked rather than forwarded with an unverified " +
                            "secondary PII pass", ex.toString());
                    return Mono.just(new Result(text, 0, true));
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
     * anonymize()'s result: the (possibly anonymized) text, how many entities
     * pii-service's Presidio pass found (0 if none, or if failed() is true), and whether
     * the call to pii-service itself failed (timeout/connection error/5xx). Callers that
     * want fail-closed behavior (the current default — see class Javadoc) should check
     * failed() and block the request rather than use text()/entityCount() when it's true.
     */
    public record Result(String text, int entityCount, boolean failed) {
    }
}
