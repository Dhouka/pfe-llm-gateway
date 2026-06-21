package com.example.demo.filter;

import com.example.demo.pii.PiiServiceClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.*;

/**
 * Exercises the real PiiFilter (now a WebFilter — see GlobalFilter-never-ran bug fix)
 * with PiiServiceClient mocked as a pass-through, instead of testing regexes copy-pasted
 * inline in the test class (AUDIT_AND_REFACTOR_PLAN.md issue #12).
 */
class PiiFilterTest {

    private PiiServiceClient piiServiceClient;
    private PiiFilter filter;

    @BeforeEach
    void setUp() {
        piiServiceClient = mock(PiiServiceClient.class);
        // Pass-through: simulate pii-service finding nothing extra / being unreachable.
        when(piiServiceClient.anonymize(any()))
                .thenAnswer(inv -> Mono.just(new PiiServiceClient.Result(inv.getArgument(0), 0)));
        filter = new PiiFilter(piiServiceClient);
    }

    private String captureForwardedBody(String requestBody) {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").body(requestBody));

        AtomicReference<String> forwardedBody = new AtomicReference<>();
        filter.filter(exchange, ex -> DataBufferUtils.join(ex.getRequest().getBody())
                .map(buf -> {
                    byte[] bytes = new byte[buf.readableByteCount()];
                    buf.read(bytes);
                    DataBufferUtils.release(buf);
                    forwardedBody.set(new String(bytes, StandardCharsets.UTF_8));
                    return buf;
                })
                .then()
        ).block();

        return forwardedBody.get();
    }

    @Test
    void redactsEmail() {
        String forwarded = captureForwardedBody("{\"message\":\"My email is yassine@gmail.com\"}");
        assertTrue(forwarded.contains("[EMAIL_REDACTED]"));
        assertFalse(forwarded.contains("yassine@gmail.com"));
    }

    @Test
    void redactsCreditCard() {
        String forwarded = captureForwardedBody("{\"message\":\"My card is 4532 1234 5678 9010\"}");
        assertTrue(forwarded.contains("[CARD_REDACTED]"));
    }

    @Test
    void redactsCin() {
        String forwarded = captureForwardedBody("{\"message\":\"My CIN is 12345678\"}");
        assertTrue(forwarded.contains("[CIN_REDACTED]"));
    }

    @Test
    void cleanRequestPassesThroughUnchanged() {
        String body = "{\"message\":\"What is artificial intelligence?\"}";
        String forwarded = captureForwardedBody(body);
        assertEquals(body, forwarded);
    }

    @Test
    void getRequestsAreNotScanned() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/audit").build());

        AtomicReference<Boolean> chainCalled = new AtomicReference<>(false);
        filter.filter(exchange, ex -> {
            chainCalled.set(true);
            return Mono.empty();
        }).block();

        assertTrue(chainCalled.get());
        verifyNoInteractions(piiServiceClient);
    }

    @Test
    void callsPiiServiceWithRegexRedactedText() {
        captureForwardedBody("{\"message\":\"My email is yassine@gmail.com\"}");
        verify(piiServiceClient).anonymize(contains("[EMAIL_REDACTED]"));
    }

    @Test
    void setsPiiAttributesWhenRegexMatchFound() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat")
                        .body("{\"message\":\"My email is yassine@gmail.com\"}"));

        filter.filter(exchange, ex -> Mono.empty()).block();

        assertEquals(true, exchange.getAttribute(AuditFilter.ATTR_PII_DETECTED));
        assertEquals(1, (int) exchange.getAttribute(AuditFilter.ATTR_PII_COUNT));
    }

    @Test
    void setsPiiAttributesToFalseZeroWhenNothingDetected() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat")
                        .body("{\"message\":\"What is artificial intelligence?\"}"));

        filter.filter(exchange, ex -> Mono.empty()).block();

        assertEquals(false, exchange.getAttribute(AuditFilter.ATTR_PII_DETECTED));
        assertEquals(0, (int) exchange.getAttribute(AuditFilter.ATTR_PII_COUNT));
    }

    @Test
    void piiCountIncludesPresidioSecondPassEntities() {
        when(piiServiceClient.anonymize(any()))
                .thenAnswer(inv -> Mono.just(new PiiServiceClient.Result(inv.getArgument(0), 2)));

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat")
                        .body("{\"message\":\"My email is yassine@gmail.com, I'm John Smith\"}"));

        filter.filter(exchange, ex -> Mono.empty()).block();

        // 1 regex match (email) + 2 presidio entities = 3
        assertEquals(3, (int) exchange.getAttribute(AuditFilter.ATTR_PII_COUNT));
    }
}
