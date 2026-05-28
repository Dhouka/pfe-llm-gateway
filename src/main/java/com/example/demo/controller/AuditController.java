package com.example.demo.controller;

import com.example.demo.audit.AuditEntry;
import com.example.demo.audit.AuditLogStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

@RestController
public class AuditController {

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

        Map<String, Object> response = new HashMap<>();
        response.put("total_requests", logs.size());
        response.put("allowed", allowed);
        response.put("blocked", blocked);
        response.put("logs", logs);

        return response;
    }
}
