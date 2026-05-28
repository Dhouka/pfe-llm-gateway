package com.example.demo.audit;

import org.springframework.stereotype.Component;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class AuditLogStore {

    private final CopyOnWriteArrayList<AuditEntry> logs = new CopyOnWriteArrayList<>();

    public void add(AuditEntry entry) {
        logs.add(entry);
        if (logs.size() > 100) {
            logs.remove(0);
        }
    }

    public List<AuditEntry> getLogs() {
        List<AuditEntry> reversed = new ArrayList<>(logs);
        Collections.reverse(reversed);
        return reversed;
    }

    public int getTotal() { return logs.size(); }
}
