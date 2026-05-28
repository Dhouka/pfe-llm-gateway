package com.example.demo.controller;

import com.example.demo.audit.AuditEntry;
import com.example.demo.audit.AuditLogStore;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/llm")
public class LlmController {

    private final ChatClient chatClient;
    private final AuditLogStore auditLogStore;

    // ── Toxic keywords ─────────────────────────────────────────────
    private static final List<String> TOXIC_KEYWORDS = List.of(
        "idiot", "stupid", "kill yourself", "hate you",
        "moron", "loser", "shut up", "you are worthless"
    );

    // ── Illegal financial advice ────────────────────────────────────
    private static final List<String> FINANCE_KEYWORDS = List.of(
        "guaranteed profit", "guaranteed return", "100% profit",
        "insider trading", "pump and dump", "ponzi",
        "illegal investment", "tax evasion"
    );

    // ── Prompt injection patterns ───────────────────────────────────
    private static final List<String> INJECTION_KEYWORDS = List.of(
        "ignore previous instructions",
        "ignore all instructions",
        "disregard your instructions",
        "you are now",
        "forget your training",
        "new instructions:"
    );

    // ── Malicious code patterns ─────────────────────────────────────
    private static final List<String> MALICIOUS_CODE_PATTERNS = List.of(
        "<script>",
        "</script>",
        "eval(",
        "exec(",
        "system(",
        "rm -rf",
        "drop table",
        "delete from",
        "insert into",
        "select * from",
        "__import__",
        "subprocess",
        "os.system",
        "base64.decode",
        "powershell",
        "cmd.exe",
        "wget http",
        "curl http",
        "chmod 777",
        "sudo rm"
    );

    public LlmController(OllamaChatModel ollamaChatModel, AuditLogStore auditLogStore) {
        this.chatClient = ChatClient.builder(ollamaChatModel).build();
        this.auditLogStore = auditLogStore;
    }

    @PostMapping("/chat")
    public Map<String, Object> chat(@RequestBody Map<String, String> body) {

        String userMessage = body.getOrDefault("message", "");
        long startTime = System.currentTimeMillis();
        String timestamp = LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));

        // ── Call Ollama via Spring AI ───────────────────────────────
        ChatResponse response = chatClient.prompt()
            .user(userMessage)
            .call()
            .chatResponse();

        long latency = System.currentTimeMillis() - startTime;
        String responseText = response.getResult().getOutput().getContent();

        // ── Token usage ────────────────────────────────────────────
        int promptTokens = 0;
        int completionTokens = 0;
        int totalTokens = 0;
        try {
            promptTokens = response.getMetadata().getUsage().getPromptTokens().intValue();
            completionTokens = response.getMetadata().getUsage().getGenerationTokens().intValue();
            totalTokens = promptTokens + completionTokens;
        } catch (Exception e) {
            totalTokens = userMessage.split(" ").length + responseText.split(" ").length;
        }

        // ── Toxicity score ─────────────────────────────────────────
        double toxicityScore = calculateToxicityScore(responseText);
        String lowerResponse = responseText.toLowerCase();

        // ── Check 1: Toxic content ─────────────────────────────────
        for (String keyword : TOXIC_KEYWORDS) {
            if (lowerResponse.contains(keyword.toLowerCase())) {
                System.out.println("BLOCKED - Toxic: " + keyword);
                auditLogStore.add(new AuditEntry(timestamp, "user", "POST",
                    "/llm/chat", 451, latency + "ms", "BLOCKED_TOXIC",
                    promptTokens, completionTokens, totalTokens, toxicityScore));
                return Map.of(
                    "error", "Response blocked: toxic content detected",
                    "toxicity_score", toxicityScore
                );
            }
        }

        // ── Check 2: Illegal financial advice ──────────────────────
        for (String keyword : FINANCE_KEYWORDS) {
            if (lowerResponse.contains(keyword.toLowerCase())) {
                System.out.println("BLOCKED - Finance: " + keyword);
                auditLogStore.add(new AuditEntry(timestamp, "user", "POST",
                    "/llm/chat", 451, latency + "ms", "BLOCKED_FINANCE",
                    promptTokens, completionTokens, totalTokens, toxicityScore));
                return Map.of(
                    "error", "Response blocked: illegal financial content detected",
                    "toxicity_score", toxicityScore
                );
            }
        }

        // ── Check 3: Prompt injection ──────────────────────────────
        for (String keyword : INJECTION_KEYWORDS) {
            if (lowerResponse.contains(keyword.toLowerCase())) {
                System.out.println("BLOCKED - Injection: " + keyword);
                auditLogStore.add(new AuditEntry(timestamp, "user", "POST",
                    "/llm/chat", 451, latency + "ms", "BLOCKED_INJECTION",
                    promptTokens, completionTokens, totalTokens, toxicityScore));
                return Map.of(
                    "error", "Response blocked: prompt injection detected",
                    "toxicity_score", toxicityScore
                );
            }
        }

        // ── Check 4: Malicious code ────────────────────────────────
        for (String pattern : MALICIOUS_CODE_PATTERNS) {
            if (lowerResponse.contains(pattern.toLowerCase())) {
                System.out.println("BLOCKED - Malicious code: " + pattern);
                auditLogStore.add(new AuditEntry(timestamp, "user", "POST",
                    "/llm/chat", 451, latency + "ms", "BLOCKED_MALICIOUS_CODE",
                    promptTokens, completionTokens, totalTokens, toxicityScore));
                return Map.of(
                    "error", "Response blocked: malicious code detected",
                    "blocked_pattern", pattern,
                    "toxicity_score", toxicityScore
                );
            }
        }

        // ── All checks passed ──────────────────────────────────────
        System.out.println("ALLOWED - Clean response, tokens: " + totalTokens);
        auditLogStore.add(new AuditEntry(timestamp, "user", "POST",
            "/llm/chat", 200, latency + "ms", "ALLOWED",
            promptTokens, completionTokens, totalTokens, toxicityScore));

        Map<String, Object> result = new HashMap<>();
        result.put("input", userMessage);
        result.put("response", responseText);
        result.put("tokens", Map.of(
            "prompt", promptTokens,
            "completion", completionTokens,
            "total", totalTokens
        ));
        result.put("latency_ms", latency);
        result.put("toxicity_score", toxicityScore);
        return result;
    }

    private double calculateToxicityScore(String text) {
        String lower = text.toLowerCase();
        long matches = TOXIC_KEYWORDS.stream()
            .filter(k -> lower.contains(k.toLowerCase()))
            .count();
        return Math.min(1.0, matches * 0.2);
    }
}
