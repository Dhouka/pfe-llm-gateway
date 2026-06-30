package com.example.demo.filter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RateLimiter;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Exercises the real RateLimiterWebFilter, which is the fix for the rate-limit
 * equivalent of the GlobalFilter-never-ran bug already fixed for AuditFilter/PiiFilter/
 * OutputGuardrailFilter: RedisRateLimiter/KeyResolver beans existed in RateLimiterConfig
 * but nothing ever called RedisRateLimiter.isAllowed(...) before this filter was added.
 * RedisRateLimiter and KeyResolver are mocked here (true I/O/Redis boundary); the
 * filter's own routing/short-circuit logic is what's under test.
 */
class RateLimiterWebFilterTest {

    private RedisRateLimiter redisRateLimiter;
    private KeyResolver keyResolver;
    private RateLimiterWebFilter filter;

    @BeforeEach
    void setUp() {
        redisRateLimiter = mock(RedisRateLimiter.class);
        keyResolver = mock(KeyResolver.class);
        when(keyResolver.resolve(any())).thenReturn(Mono.just("127.0.0.1"));
        filter = new RateLimiterWebFilter(redisRateLimiter, keyResolver);
    }

    @Test
    void allowsRequestWithinLimit() {
        when(redisRateLimiter.isAllowed(eq("llm-chat"), eq("127.0.0.1")))
                .thenReturn(Mono.just(new RateLimiter.Response(true, Map.of())));

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").body("{}"));

        AtomicReference<Boolean> chainCalled = new AtomicReference<>(false);
        filter.filter(exchange, ex -> {
            chainCalled.set(true);
            return Mono.empty();
        }).block();

        assertTrue(chainCalled.get());
    }

    @Test
    void blocksRequestOverLimitWith429() {
        when(redisRateLimiter.isAllowed(eq("llm-chat"), eq("127.0.0.1")))
                .thenReturn(Mono.just(new RateLimiter.Response(false, Map.of())));

        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.post("/llm/chat").body("{}"));

        AtomicReference<Boolean> chainCalled = new AtomicReference<>(false);
        filter.filter(exchange, ex -> {
            chainCalled.set(true);
            return Mono.empty();
        }).block();

        assertFalse(chainCalled.get());
        assertEquals(HttpStatus.TOO_MANY_REQUESTS, exchange.getResponse().getStatusCode());
        assertEquals("BLOCKED_RATE_LIMIT", exchange.getAttribute(AuditFilter.ATTR_EVENT));
    }

    @Test
    void pathsOutsideLlmAreNotRateLimited() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/audit"));

        AtomicReference<Boolean> chainCalled = new AtomicReference<>(false);
        filter.filter(exchange, ex -> {
            chainCalled.set(true);
            return Mono.empty();
        }).block();

        assertTrue(chainCalled.get());
        verifyNoInteractions(redisRateLimiter, keyResolver);
    }
}
