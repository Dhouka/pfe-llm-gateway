package com.example.demo.filter;

import com.example.demo.audit.AuditLogStore;
import com.example.demo.audit.AuditEntry;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class AuditFilter implements GlobalFilter, Ordered {

    private final AuditLogStore auditLogStore;

    public AuditFilter(AuditLogStore auditLogStore) {
        this.auditLogStore = auditLogStore;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        long startTime = System.currentTimeMillis();
        String path = exchange.getRequest().getPath().toString();
        String method = exchange.getRequest().getMethod().name();
        String timestamp = LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        System.out.println("📋 AUDIT FILTER TRIGGERED: " + method + " " + path);

        return chain.filter(exchange).doAfterTerminate(() -> {
            long latency = System.currentTimeMillis() - startTime;

            int statusCode = 0;
            try {
                statusCode = exchange.getResponse().getStatusCode().value();
            } catch (Exception e) {
                statusCode = 0;
            }

            String event = "ALLOWED";
            if (statusCode == 401) event = "BLOCKED_NO_AUTH";
            else if (statusCode == 429) event = "BLOCKED_RATE_LIMIT";
            else if (statusCode == 451) event = "BLOCKED_GUARDRAIL";
            else if (statusCode == 403) event = "BLOCKED_FORBIDDEN";

            AuditEntry entry = new AuditEntry(
                timestamp, "anonymous", method, path,
                statusCode, latency + "ms", event,
                0, 0, 0, 0.0
            );

            auditLogStore.add(entry);
            System.out.println("📋 AUDIT LOGGED: " + entry);
        });
    }

    @Override
    public int getOrder() {
        return Integer.MIN_VALUE;
    }
}
