package com.example.demo.filter;

import com.example.demo.guardrail.GuardrailPolicy;
import org.reactivestreams.Publisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;

/**
 * Scans response bodies for toxic, illegal-finance, prompt-injection, and malicious-code
 * content and short-circuits with HTTP 451 if matched.
 *
 * Originally implemented as a Spring Cloud Gateway GlobalFilter, which only runs for
 * requests matched by a configured route — with spring.cloud.gateway.routes empty, this
 * never executed against real traffic. Converted to a plain WebFlux WebFilter (see
 * AUDIT_AND_REFACTOR_PLAN.md section 2/4), and the keyword lists now live in the shared
 * GuardrailPolicy instead of a private copy (previously this filter lacked the
 * malicious-code patterns that only existed in LlmController).
 */
@Component
@Order(-2)
public class OutputGuardrailFilter implements WebFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(OutputGuardrailFilter.class);

    private final GuardrailPolicy guardrailPolicy;

    public OutputGuardrailFilter(GuardrailPolicy guardrailPolicy) {
        this.guardrailPolicy = guardrailPolicy;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {

        ServerHttpResponse originalResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = originalResponse.bufferFactory();

        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {

                Flux<? extends DataBuffer> fluxBody = Flux.from(body);

                return DataBufferUtils.join(fluxBody)
                        .flatMap(dataBuffer -> {

                            byte[] bytes = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(bytes);
                            DataBufferUtils.release(dataBuffer);

                            String responseBody = new String(bytes, StandardCharsets.UTF_8);
                            log.debug("OutputGuardrailFilter — checking response body");

                            GuardrailPolicy.Verdict verdict = guardrailPolicy.classify(responseBody);

                            if (verdict.isBlocked()) {
                                log.warn("OutputGuardrailFilter — BLOCKED ({}): {}",
                                        verdict.category(), verdict.matchedPattern());
                                exchange.getAttributes().put(AuditFilter.ATTR_EVENT,
                                        "BLOCKED_" + verdict.category().name());
                                exchange.getAttributes().put(AuditFilter.ATTR_MATCHED_CATEGORY,
                                        verdict.category().name());
                                exchange.getAttributes().put(AuditFilter.ATTR_MATCHED_PATTERN,
                                        verdict.matchedPattern());
                                originalResponse.setStatusCode(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS);
                                byte[] blocked = ("{\"error\":\"Response blocked: " +
                                        verdict.category().name().toLowerCase().replace('_', ' ') +
                                        " content detected\"}").getBytes(StandardCharsets.UTF_8);
                                originalResponse.getHeaders().setContentLength(blocked.length);
                                return super.writeWith(Mono.just(bufferFactory.wrap(blocked)));
                            }

                            log.debug("OutputGuardrailFilter — response is clean, passing through");
                            byte[] cleanBytes = responseBody.getBytes(StandardCharsets.UTF_8);
                            originalResponse.getHeaders().setContentLength(cleanBytes.length);
                            return super.writeWith(Mono.just(bufferFactory.wrap(cleanBytes)));
                        });
            }
        };

        return chain.filter(exchange.mutate().response(decoratedResponse).build());
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
