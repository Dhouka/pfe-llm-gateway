package com.example.demo.filter;

import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class OutputGuardrailFilter implements GlobalFilter, Ordered {

    private static final List<String> TOXIC_WORDS = List.of(
            "idiot", "stupid", "kill yourself", "you are worthless",
            "hate you", "loser", "moron", "shut up"
    );

    private static final List<String> ILLEGAL_FINANCE = List.of(
            "guaranteed profit", "guaranteed return", "100% profit",
            "insider trading", "pump and dump", "ponzi",
            "illegal investment", "tax evasion"
    );

    private static final List<String> INJECTION_PATTERNS = List.of(
            "ignore previous instructions",
            "ignore all instructions",
            "disregard your instructions",
            "you are now",
            "forget your training",
            "new instructions:"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpResponse originalResponse = exchange.getResponse();
        DataBufferFactory bufferFactory = originalResponse.bufferFactory();

        ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {

            @Override
            public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {

                // Collect ALL body chunks into one, works for both Mono and Flux
                Flux<? extends DataBuffer> fluxBody = Flux.from(body);

                return DataBufferUtils.join(fluxBody)
                        .flatMap(dataBuffer -> {

                            byte[] bytes = new byte[dataBuffer.readableByteCount()];
                            dataBuffer.read(bytes);
                            DataBufferUtils.release(dataBuffer);

                            String responseBody = new String(bytes, StandardCharsets.UTF_8);
                            String lowerBody = responseBody.toLowerCase();

                            System.out.println("\n==================================");
                            System.out.println("🛡️  Output Guardrail — Checking response...");
                            System.out.println("Body: " + responseBody);

                            // Check toxic words
                            for (String word : TOXIC_WORDS) {
                                if (lowerBody.contains(word.toLowerCase())) {
                                    System.out.println("🚨 BLOCKED — Toxic: " + word);
                                    System.out.println("==================================\n");
                                    originalResponse.setStatusCode(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS);
                                    byte[] blocked = "{\"error\":\"Response blocked: toxic content detected\"}"
                                            .getBytes(StandardCharsets.UTF_8);
                                    originalResponse.getHeaders().setContentLength(blocked.length);
                                    return super.writeWith(Mono.just(bufferFactory.wrap(blocked)));
                                }
                            }

                            // Check illegal financial advice
                            for (String phrase : ILLEGAL_FINANCE) {
                                if (lowerBody.contains(phrase.toLowerCase())) {
                                    System.out.println("🚨 BLOCKED — Finance: " + phrase);
                                    System.out.println("==================================\n");
                                    originalResponse.setStatusCode(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS);
                                    byte[] blocked = "{\"error\":\"Response blocked: illegal financial content detected\"}"
                                            .getBytes(StandardCharsets.UTF_8);
                                    originalResponse.getHeaders().setContentLength(blocked.length);
                                    return super.writeWith(Mono.just(bufferFactory.wrap(blocked)));
                                }
                            }

                            // Check prompt injection
                            for (String pattern : INJECTION_PATTERNS) {
                                if (lowerBody.contains(pattern.toLowerCase())) {
                                    System.out.println("🚨 BLOCKED — Injection: " + pattern);
                                    System.out.println("==================================\n");
                                    originalResponse.setStatusCode(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS);
                                    byte[] blocked = "{\"error\":\"Response blocked: prompt injection detected\"}"
                                            .getBytes(StandardCharsets.UTF_8);
                                    originalResponse.getHeaders().setContentLength(blocked.length);
                                    return super.writeWith(Mono.just(bufferFactory.wrap(blocked)));
                                }
                            }

                            // All clean
                            System.out.println("✅ Response is clean — passing through");
                            System.out.println("==================================\n");
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