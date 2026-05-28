package com.example.demo.filter;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

@Component
public class PiiFilter implements GlobalFilter, Ordered {

    // ─── Patterns ────────────────────────────────────────────────
    // Matches emails like yassine@gmail.com
    private static final Pattern EMAIL =
            Pattern.compile("[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");

    // Matches Tunisian CIN (exactly 8 digits)
    private static final Pattern CIN =
            Pattern.compile("\\b\\d{8}\\b");

    // Matches credit card numbers (16 digits, optionally separated by spaces or dashes)
    private static final Pattern CREDIT_CARD =
            Pattern.compile("\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b");

    // Matches phone numbers (8 digits for Tunisia, or international format)
    private static final Pattern PHONE =
            Pattern.compile("\\b(\\+216)?[2-9]\\d{7}\\b");

    // ─── Filter logic ─────────────────────────────────────────────
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        // Only scan POST and PUT requests (they have a body with the prompt)
        HttpMethod method = exchange.getRequest().getMethod();
        if (method != HttpMethod.POST && method != HttpMethod.PUT) {
            return chain.filter(exchange);
        }

        // Read the full request body
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {

                    // Convert bytes to text
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    String originalBody = new String(bytes, StandardCharsets.UTF_8);

                    System.out.println("\n==================================");
                    System.out.println("🔐 PII Filter — Original body:");
                    System.out.println(originalBody);

                    // ── Sanitize ──────────────────────────────────────
                    String sanitized = originalBody;
                    boolean piiFound = false;

                    if (EMAIL.matcher(sanitized).find()) {
                        System.out.println("⚠️  Email detected — masking...");
                        sanitized = EMAIL.matcher(sanitized).replaceAll("[EMAIL_REDACTED]");
                        piiFound = true;
                    }

                    if (CREDIT_CARD.matcher(sanitized).find()) {
                        System.out.println("⚠️  Credit card detected — masking...");
                        sanitized = CREDIT_CARD.matcher(sanitized).replaceAll("[CARD_REDACTED]");
                        piiFound = true;
                    }

                    if (CIN.matcher(sanitized).find()) {
                        System.out.println("⚠️  CIN detected — masking...");
                        sanitized = CIN.matcher(sanitized).replaceAll("[CIN_REDACTED]");
                        piiFound = true;
                    }

                    if (PHONE.matcher(sanitized).find()) {
                        System.out.println("⚠️  Phone detected — masking...");
                        sanitized = PHONE.matcher(sanitized).replaceAll("[PHONE_REDACTED]");
                        piiFound = true;
                    }

                    if (piiFound) {
                        System.out.println("✅ Sanitized body:");
                        System.out.println(sanitized);
                    } else {
                        System.out.println("✅ No PII detected — request clean");
                    }
                    System.out.println("==================================\n");

                    // ── Rebuild the request with the sanitized body ───
                    byte[] sanitizedBytes = sanitized.getBytes(StandardCharsets.UTF_8);
                    DataBuffer sanitizedBuffer = exchange.getResponse()
                            .bufferFactory()
                            .wrap(sanitizedBytes);

                    // We need to override the request so the gateway forwards
                    // the sanitized body instead of the original one
                    ServerHttpRequest mutatedRequest = new ServerHttpRequestDecorator(
                            exchange.getRequest()) {

                        @Override
                        public Flux<DataBuffer> getBody() {
                            return Flux.just(sanitizedBuffer);
                        }

                        @Override
                        public HttpHeaders getHeaders() {
                            HttpHeaders headers = new HttpHeaders();
                            headers.putAll(super.getHeaders());
                            // Update Content-Length to match new body size
                            headers.setContentLength(sanitizedBytes.length);
                            return headers;
                        }
                    };

                    // Forward the mutated request down the filter chain
                    return chain.filter(exchange.mutate().request(mutatedRequest).build());
                });
    }

    // Run this filter first, before anything else
    @Override
    public int getOrder() {
        return -1;
    }
}