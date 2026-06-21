package com.example.demo.guardrail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaOptions;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Real semantic validator: runs a second, cheap classification prompt through the same
 * local Ollama model the gateway already uses for chat, asking it to reason about
 * *meaning* rather than matching substrings. This is what lets the gateway catch
 * paraphrased toxicity, illegal-finance advice, prompt injection, or malicious-code
 * requests that GuardrailPolicy's keyword pass would miss entirely (e.g. "you're a
 * complete waste of space" vs. the literal keyword "idiot").
 *
 * Deliberately the smallest viable "semantic" implementation for this PFE's scope —
 * see PFE_TODO.md task 3 for the embeddings-based alternative considered and not used
 * (more infra, not clearly more defensible for a school-project defense than "the model
 * itself reasons about the text's meaning").
 *
 * Fails open (returns Category.NONE) on any error/timeout/unparseable output — the
 * keyword pass in GuardrailPolicy already runs first and unconditionally, so this is a
 * second line of defense, not the only one; an outage here must not become an outage of
 * the whole gateway.
 */
@Component
public class OllamaSemanticGuardrailClassifier implements SemanticGuardrailClassifier {

    private static final Logger log = LoggerFactory.getLogger(OllamaSemanticGuardrailClassifier.class);

    // Bounded so a slow/hung model call can't hang every request indefinitely — falls
    // open (Category.NONE) past this, same fail-open contract as PiiServiceClient's
    // 2s-timeout-plus-retry against pii-service.
    private static final Duration TIMEOUT = Duration.ofSeconds(3);

    private static final String SYSTEM_PROMPT = """
            Classify the text into one category: NONE, TOXIC, ILLEGAL_FINANCE, PROMPT_INJECTION, MALICIOUS_CODE.
            Reply with only the category word.
            """;

    private final ChatClient chatClient;

    public OllamaSemanticGuardrailClassifier(OllamaChatModel ollamaChatModel) {
        this.chatClient = ChatClient.builder(ollamaChatModel).build();
    }

    @Override
    public GuardrailPolicy.Category classifySemantic(String text) {
        if (text == null || text.isBlank()) {
            return GuardrailPolicy.Category.NONE;
        }

        try {
            return CompletableFuture.supplyAsync(() -> callModel(text))
                    .get(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            log.warn("OllamaSemanticGuardrailClassifier — falling open (NONE) after error/timeout: {}",
                    e.toString());
            return GuardrailPolicy.Category.NONE;
        }
    }

    private GuardrailPolicy.Category callModel(String text) {
        String raw = chatClient.prompt()
                .system(SYSTEM_PROMPT)
                .user(text)
                .options(OllamaOptions.builder().temperature(0.0).build())
                .call()
                .content();

        return parseCategory(raw);
    }

    private GuardrailPolicy.Category parseCategory(String raw) {
        if (raw == null) {
            return GuardrailPolicy.Category.NONE;
        }
        String upper = raw.trim().toUpperCase();
        for (GuardrailPolicy.Category cat : GuardrailPolicy.Category.values()) {
            if (upper.contains(cat.name())) {
                return cat;
            }
        }
        log.warn("OllamaSemanticGuardrailClassifier — unparseable model output, falling open (NONE): \"{}\"", raw);
        return GuardrailPolicy.Category.NONE;
    }
}
