package com.example.demo.controller;

import com.example.demo.filter.AuditFilter;
import com.example.demo.guardrail.GuardrailPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.HashMap;
import java.util.Map;

/**
 * The gateway's only consumer-facing AI endpoint. Calls Ollama via Spring AI's
 * ChatClient, then runs the model's raw output through the shared GuardrailPolicy as a
 * defense-in-depth check (in addition to OutputGuardrailFilter, which scans the same
 * response further down the filter chain).
 *
 * This used to always return HTTP 200 (a bare Map) even when blocking content, and wrote
 * its own AuditEntry directly into AuditLogStore — duplicating AuditFilter's logging and
 * making status-code-based audit classification wrong for blocked responses. It now
 * returns a proper ResponseEntity (451 when blocked) and sets exchange attributes that
 * AuditFilter reads, instead of writing to the audit store itself — see AuditFilter for
 * the attribute contract.
 *
 * Fixed 2026-06-25 (see CLAUDE.md "known limitation, not fixed" note from the external
 * audit): chatClient.prompt().call().chatResponse() is a blocking call —
 * application.yml/CLAUDE.md document real observed latencies of 78-195s for a single
 * completion on this machine's CPU-only Ollama. This whole app runs on Spring WebFlux's
 * small, fixed-size Netty event-loop thread pool; previously this method returned a plain
 * ResponseEntity directly, which Spring WebFlux executes ON that event-loop thread, so one
 * slow chat request could occupy an event-loop thread for the entire ~78-195s call,
 * starving every other concurrent request (including unrelated ones like /audit) sharing
 * that thread. The fix: the blocking portion (everything from the actual model call
 * onward) now runs inside Mono.fromCallable(...).subscribeOn(Schedulers.boundedElastic()),
 * which moves it onto Reactor's dedicated blocking-task thread pool, freeing the event
 * loop immediately. The fast, synchronous input-guardrail check still runs inline (no
 * point offloading microseconds of keyword matching).
 */
@RestController
@RequestMapping("/llm")
public class LlmController {

    private static final Logger log = LoggerFactory.getLogger(LlmController.class);

    private final ChatClient chatClient;
    private final GuardrailPolicy guardrailPolicy;

    @Autowired
    public LlmController(OllamaChatModel ollamaChatModel, GuardrailPolicy guardrailPolicy) {
        this(ChatClient.builder(ollamaChatModel).build(), guardrailPolicy);
    }

    /**
     * Package-private constructor used by tests to inject a fully mocked ChatClient,
     * bypassing the need for a real/mocked OllamaChatModel + Spring AI builder chain.
     */
    LlmController(ChatClient chatClient, GuardrailPolicy guardrailPolicy) {
        this.chatClient = chatClient;
        this.guardrailPolicy = guardrailPolicy;
    }

    @PostMapping("/chat")
    public Mono<ResponseEntity<Map<String, Object>>> chat(@RequestBody Map<String, String> body,
                                                            ServerWebExchange exchange) {

        String userMessage = body.getOrDefault("message", "");

        GuardrailPolicy.Verdict inputVerdict = guardrailPolicy.classify(userMessage);
        if (inputVerdict.isBlocked()) {
            String event = "BLOCKED_" + inputVerdict.category().name();
            exchange.getAttributes().put(AuditFilter.ATTR_EVENT, event);
            exchange.getAttributes().put(AuditFilter.ATTR_MATCHED_CATEGORY, inputVerdict.category().name());
            exchange.getAttributes().put(AuditFilter.ATTR_MATCHED_PATTERN, inputVerdict.matchedPattern());

            Map<String, Object> errorBody = new HashMap<>();
            errorBody.put("error", "Input blocked: " +
                    inputVerdict.category().name().toLowerCase().replace('_', ' ') + " content detected");
            return Mono.just(ResponseEntity.status(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS).body(errorBody));
        }

        // The actual model call (and everything downstream of it: token accounting,
        // output-guardrail classification) is blocking I/O that can take tens to hundreds
        // of seconds against this project's CPU-only Ollama backend — see class Javadoc.
        // subscribeOn(boundedElastic) moves all of that off the Netty event-loop thread.
        return Mono.fromCallable(() -> callModelAndBuildResponse(userMessage, exchange))
                .subscribeOn(Schedulers.boundedElastic());
    }

    /**
     * The blocking portion of chat(): calls the model, computes tokens/toxicity, applies
     * the output guardrail, and builds the final ResponseEntity. Runs on a
     * boundedElastic thread, never on the WebFlux event loop — see chat()'s call site.
     */
    private ResponseEntity<Map<String, Object>> callModelAndBuildResponse(String userMessage,
                                                                            ServerWebExchange exchange) {
        long startTime = System.currentTimeMillis();

        ChatResponse response = chatClient.prompt()
                .user(userMessage)
                .call()
                .chatResponse();

        long latency = System.currentTimeMillis() - startTime;
        String responseText = response.getResult().getOutput().getText();

        int promptTokens = 0;
        int completionTokens = 0;
        int totalTokens;
        try {
            promptTokens = response.getMetadata().getUsage().getPromptTokens().intValue();
            completionTokens = response.getMetadata().getUsage().getCompletionTokens().intValue();
            totalTokens = promptTokens + completionTokens;
        } catch (Exception e) {
            totalTokens = userMessage.split(" ").length + responseText.split(" ").length;
        }

        double toxicityScore = guardrailPolicy.toxicityScore(responseText);
        GuardrailPolicy.Verdict verdict = guardrailPolicy.classify(responseText);

        exchange.getAttributes().put(AuditFilter.ATTR_PROMPT_TOKENS, promptTokens);
        exchange.getAttributes().put(AuditFilter.ATTR_COMPLETION_TOKENS, completionTokens);
        exchange.getAttributes().put(AuditFilter.ATTR_TOTAL_TOKENS, totalTokens);
        exchange.getAttributes().put(AuditFilter.ATTR_TOXICITY_SCORE, toxicityScore);

        String correlationId = exchange.getAttributeOrDefault(AuditFilter.ATTR_CORRELATION_ID, "unknown");

        if (verdict.isBlocked()) {
            String event = "BLOCKED_" + verdict.category().name();
            exchange.getAttributes().put(AuditFilter.ATTR_EVENT, event);
            exchange.getAttributes().put(AuditFilter.ATTR_MATCHED_CATEGORY, verdict.category().name());
            exchange.getAttributes().put(AuditFilter.ATTR_MATCHED_PATTERN, verdict.matchedPattern());
            log.warn("LlmController [{}] — BLOCKED ({}): {}", correlationId, verdict.category(), verdict.matchedPattern());

            Map<String, Object> errorBody = new HashMap<>();
            errorBody.put("error", "Response blocked: " +
                    verdict.category().name().toLowerCase().replace('_', ' ') + " content detected");
            errorBody.put("toxicity_score", toxicityScore);
            if (verdict.category() == GuardrailPolicy.Category.MALICIOUS_CODE) {
                errorBody.put("blocked_pattern", verdict.matchedPattern());
            }
            return ResponseEntity.status(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS).body(errorBody);
        }

        exchange.getAttributes().put(AuditFilter.ATTR_EVENT, "ALLOWED");
        log.info("LlmController [{}] — ALLOWED, tokens: {}", correlationId, totalTokens);

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
        return ResponseEntity.ok(result);
    }
}
