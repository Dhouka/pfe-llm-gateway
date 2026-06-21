package com.example.demo.controller;

import com.example.demo.audit.AuditEntry;
import com.example.demo.audit.AuditLogStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AuditController {

    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final AuditLogStore auditLogStore;

    public AuditController(AuditLogStore auditLogStore) {
        this.auditLogStore = auditLogStore;
    }

    @GetMapping("/audit")
    public Map<String, Object> getAuditLogs() {
        List<AuditEntry> logs = auditLogStore.getLogs();

        long blocked = logs.stream()
            .filter(e -> e.getEvent().startsWith("BLOCKED"))
            .count();
        long allowed = logs.stream()
            .filter(e -> e.getEvent().equals("ALLOWED"))
            .count();
        long piiDetections = logs.stream()
            .filter(AuditEntry::isPiiDetected)
            .count();
        int piiEntitiesRedacted = logs.stream()
            .mapToInt(AuditEntry::getPiiCount)
            .sum();

        Map<String, Object> response = new HashMap<>();
        response.put("total_requests", logs.size());
        response.put("allowed", allowed);
        response.put("blocked", blocked);
        response.put("pii_detections", piiDetections);
        response.put("pii_entities_redacted", piiEntitiesRedacted);
        response.put("logs", logs);

        return response;
    }

    @GetMapping("/audit/summary")
    public Map<String, Object> getAuditSummary() {
        List<AuditEntry> logs = auditLogStore.getLogs();

        long total = logs.size();
        long blocked = logs.stream().filter(e -> e.getEvent().startsWith("BLOCKED")).count();
        long allowed = logs.stream().filter(e -> e.getEvent().equals("ALLOWED")).count();

        // Unique users
        Set<String> users = logs.stream()
                .map(AuditEntry::getUser)
                .filter(u -> u != null && !u.isEmpty() && !u.equals("anonymous"))
                .collect(Collectors.toSet());

        // Average latency in ms
        OptionalDouble avgLatency = logs.stream()
                .mapToInt(e -> parseLatencyMs(e.getLatency()))
                .average();

        // Category breakdown for blocked events
        Map<String, Long> categoryBreakdown = logs.stream()
                .filter(e -> e.getEvent().startsWith("BLOCKED"))
                .map(e -> e.getEvent().replace("BLOCKED_", ""))
                .collect(Collectors.groupingBy(s -> s, Collectors.counting()));

        // Method breakdown
        Map<String, Long> methodBreakdown = logs.stream()
                .collect(Collectors.groupingBy(AuditEntry::getMethod, Collectors.counting()));

        // PII rate
        long piiDetections = logs.stream().filter(AuditEntry::isPiiDetected).count();

        // Toxicity stats
        OptionalDouble avgToxicity = logs.stream()
                .mapToDouble(AuditEntry::getToxicityScore)
                .average();

        // Time range
        String firstTimestamp = logs.isEmpty() ? null : logs.get(logs.size() - 1).getTimestamp();
        String lastTimestamp = logs.isEmpty() ? null : logs.get(0).getTimestamp();

        // Requests per minute (over the time range)
        double requestsPerMinute = 0;
        if (logs.size() >= 2) {
            try {
                LocalDateTime first = LocalDateTime.parse(firstTimestamp, FORMATTER);
                LocalDateTime last = LocalDateTime.parse(lastTimestamp, FORMATTER);
                long minutes = Duration.between(first, last).toMinutes();
                if (minutes > 0) {
                    requestsPerMinute = (double) total / minutes;
                }
            } catch (Exception ignored) {}
        }

        // Top blocked category
        String topBlockedCategory = categoryBreakdown.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(null);

        Map<String, Object> summary = new HashMap<>();
        summary.put("total_requests", total);
        summary.put("allowed", allowed);
        summary.put("blocked", blocked);
        summary.put("block_rate", total > 0 ? Math.round((double) blocked / total * 100.0) : 0);
        summary.put("unique_users", users.size());
        summary.put("avg_latency_ms", avgLatency.isPresent() ? Math.round(avgLatency.getAsDouble()) : 0);
        summary.put("category_breakdown", categoryBreakdown);
        summary.put("method_breakdown", methodBreakdown);
        summary.put("pii_detections", piiDetections);
        summary.put("pii_rate", total > 0 ? Math.round((double) piiDetections / total * 100.0) : 0);
        summary.put("avg_toxicity_score", avgToxicity.isPresent() ? Math.round(avgToxicity.getAsDouble() * 100.0) / 100.0 : 0);
        summary.put("requests_per_minute", Math.round(requestsPerMinute * 10.0) / 10.0);
        summary.put("top_blocked_category", topBlockedCategory);
        summary.put("first_timestamp", firstTimestamp);
        summary.put("last_timestamp", lastTimestamp);

        return summary;
    }

    @GetMapping("/audit/detail/{correlationId}")
    public ResponseEntity<?> getAuditDetail(@PathVariable String correlationId) {
        AuditEntry entry = auditLogStore.getLogs().stream()
                .filter(e -> e.getCorrelationId().equals(correlationId))
                .findFirst()
                .orElse(null);

        if (entry == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "audit entry not found");
            return ResponseEntity.status(404).body(err);
        }

        return ResponseEntity.ok(entry);
    }

    private static int parseLatencyMs(String latency) {
        if (latency == null) return 0;
        try {
            return Integer.parseInt(latency.replace("ms", "").trim());
        } catch (NumberFormatException e) {
            return 0;
        }
    }
}
