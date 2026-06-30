package com.example.demo.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Actually enforces the RedisRateLimiter/KeyResolver beans declared in
 * RateLimiterConfig — those beans existed since the original implementation but were
 * never invoked by anything: RequestRateLimiterGatewayFilterFactory (the Spring Cloud
 * Gateway component that normally calls a RateLimiter bean) only attaches to a
 * configured *route*, and spring.cloud.gateway.routes is intentionally empty here. This
 * is the exact same root cause already fixed for AuditFilter/PiiFilter/
 * OutputGuardrailFilter (GlobalFilters that never ran without a matched route) — same
 * fix shape: call the underlying logic directly from a plain WebFlux WebFilter instead
 * of relying on Spring Cloud Gateway's route-filter machinery.
 *
 * Scoped to /llm/** — the expensive, abusable endpoint the subject's "Redis (Rate
 * Limiting)" requirement is aimed at. /audit and /actuator/** are left unlimited.
 *
 * Ordered to run before PiiFilter/OutputGuardrailFilter (both negative orders) so an
 * over-quota caller is rejected before the gateway does any PII-redaction or guardrail
 * work on their request — but still inside AuditFilter (Integer.MIN_VALUE), so a
 * rejected request still gets a BLOCKED_RATE_LIMIT audit entry with real latency.
 */
@Component
@Order(-3)
public class RateLimiterWebFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterWebFilter.class);

    // Identifies this filter's calls to RedisRateLimiter — RedisRateLimiter keys its
    // Redis state by (routeId, resolvedKey), and there's no real "route" here, so a
    // fixed logical name is used instead.
    private static final String ROUTE_ID = "llm-chat";
    private static final String LIMITED_PATH_PREFIX = "/llm/";

    private final RedisRateLimiter redisRateLimiter;
    private final KeyResolver keyResolver;

    public RateLimiterWebFilter(RedisRateLimiter redisRateLimiter, KeyResolver ipKeyResolver) {
        this.redisRateLimiter = redisRateLimiter;
        this.keyResolver = ipKeyResolver;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        String path = exchange.getRequest().getPath().value();
        if (!path.startsWith(LIMITED_PATH_PREFIX)) {
            return chain.filter(exchange);
        }

        return keyResolver.resolve(exchange)
                .flatMap(key -> redisRateLimiter.isAllowed(ROUTE_ID, key))
                .flatMap(response -> {
                    if (response.isAllowed()) {
                        return chain.filter(exchange);
                    }
                    log.warn("RateLimiterWebFilter — rate limit exceeded for path {}", path);
                    exchange.getAttributes().put(AuditFilter.ATTR_EVENT, "BLOCKED_RATE_LIMIT");

                    exchange.getResponse().setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
                    byte[] body = "{\"error\":\"rate limit exceeded, slow down\"}"
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
                    exchange.getResponse().getHeaders().setContentLength(body.length);
                    DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
                    return exchange.getResponse().writeWith(Mono.just(bufferFactory.wrap(body)));
                });
    }

    @Override
    public int getOrder() {
        return -3;
    }
}
