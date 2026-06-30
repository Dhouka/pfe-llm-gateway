package com.example.demo.filter;

import com.example.demo.guardrail.GuardrailPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the real OutputGuardrailFilter (now a WebFilter, see PiiFilter/
 * OutputGuardrailFilter/AuditFilter conversion from GlobalFilter — GlobalFilters never
 * ran because spring.cloud.gateway.routes was empty) against the real, shared
 * GuardrailPolicy, instead of a copy-pasted inline keyword list.
 */
class OutputGuardrailFilterTest {

    private OutputGuardrailFilter filter;

    @BeforeEach
    void setUp() {
        filter = new OutputGuardrailFilter(new GuardrailPolicy());
    }

    private WebFilterChain chainReturning(String body) {
        return exchange -> exchange.getResponse().writeWith(
                Mono.just(exchange.getResponse().bufferFactory()
                        .wrap(body.getBytes(StandardCharsets.UTF_8))));
    }

    @Test
    void blocksToxicResponseWith451() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").build());

        filter.filter(exchange, chainReturning("{\"response\":\"You are such an idiot\"}")).block();

        assertEquals(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS, exchange.getResponse().getStatusCode());
    }

    @Test
    void blocksIllegalFinanceResponse() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").build());

        filter.filter(exchange, chainReturning("{\"response\":\"This is a guaranteed profit investment\"}")).block();

        assertEquals(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS, exchange.getResponse().getStatusCode());
    }

    @Test
    void blocksMaliciousCodeResponse() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").build());

        filter.filter(exchange, chainReturning(
                "{\"response\":\"<script>eval(base64.decode('x'))</script>\"}")).block();

        assertEquals(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS, exchange.getResponse().getStatusCode());
    }

    @Test
    void cleanResponsePassesThroughUnchanged() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").build());
        String cleanBody = "{\"response\":\"Cloud computing is a great technology\"}";

        filter.filter(exchange, chainReturning(cleanBody)).block();

        assertNull(exchange.getResponse().getStatusCode());
        assertEquals(cleanBody, exchange.getResponse().getBodyAsString().block());
    }

    /**
     * Regression test for a real bug found 2026-06-26: this filter used to run the
     * (occasionally unreliable, sub-1B-model-backed) semantic classifier against every
     * response body including /actuator/health's own trivial {"status":"UP"} JSON, and a
     * false-positive MALICIOUS_CODE classification there returned HTTP 451 for a Docker
     * healthcheck request — making the gateway container "unhealthy" forever even though
     * the JVM had started and was serving requests fine, which in turn blocked every other
     * service with depends_on: condition: service_healthy (dashboard included) from ever
     * starting. /actuator/** must always pass through unscanned and unmodified.
     */
    @Test
    void actuatorHealthBypassesGuardrailEvenWithMaliciousLookingBody() {
        MockServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/actuator/health").build());
        String body = "{\"status\":\"UP\"}";

        filter.filter(exchange, chainReturning(body)).block();

        assertNull(exchange.getResponse().getStatusCode());
        assertEquals(body, exchange.getResponse().getBodyAsString().block());
    }
}
