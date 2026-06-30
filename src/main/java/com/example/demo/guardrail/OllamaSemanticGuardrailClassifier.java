package com.example.demo.guardrail;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaOptions;
import org.springframework.beans.factory.annotation.Value;
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

    private static final String SYSTEM_PROMPT = """
            Classify the text into one category: NONE, TOXIC, ILLEGAL_FINANCE, PROMPT_INJECTION, MALICIOUS_CODE.
            Reply with only the category word.
            """;

    private final ChatClient chatClient;

    // Configurable via guardrail.semantic.timeout-seconds (default 200s) — see
    // application.yml for why this isn't a small hardcoded constant anymore. Bounded so a
    // slow/hung model call can't hang a request indefinitely — falls open (Category.NONE)
    // past this, same fail-open contract as PiiServiceClient's 2s-timeout-plus-retry
    // against pii-service. 200s is a demo-safe default for this CPU-only Ollama setup, NOT
    // a production value — a real deployment should lower this drastically once paired
    // with a fast dedicated classification model (see PFE_TODO.md task 3).
    private final Duration timeout;

    // Configurable via guardrail.semantic.model (default "qwen2.5:0.5b") — deliberately a
    // DIFFERENT, smaller model than the one used for chat (tinyllama). Root cause found
    // 2026-06-24: tinyllama does not reliably follow system-role instructions at all, so it
    // never returns a clean category word for a classification prompt regardless of timeout
    // budget (see PFE_TODO.md task 3). A small instruction-tuned model is far more likely to
    // actually obey "reply with only the category word." Overridden per-call via
    // OllamaOptions rather than swapping the injected OllamaChatModel bean, so the main chat
    // path (LlmController) is completely unaffected by this change.
    private final String classificationModel;

    // Found 2026-06-30, same root cause as the main chat path (see application.yml): no
    // token limit was set on this call either, so a model that doesn't reliably emit a
    // stop token (see class Javadoc — tinyllama; qwen2.5:0.5b can do the same when it
    // rambles instead of returning a bare category word) runs to its full context window
    // (2048 tokens observed in practice) before returning, costing tens of minutes per
    // classification instead of the few seconds a one-word answer needs. The classifier
    // only ever needs to reply with one category word, so this is bounded tightly.
    private final int numPredict;

    public OllamaSemanticGuardrailClassifier(
            OllamaChatModel ollamaChatModel,
            @Value("${guardrail.semantic.timeout-seconds:200}") long timeoutSeconds,
            @Value("${guardrail.semantic.model:qwen2.5:0.5b}") String classificationModel,
            @Value("${guardrail.semantic.num-predict:16}") int numPredict) {
        this.chatClient = ChatClient.builder(ollamaChatModel).build();
        this.timeout = Duration.ofSeconds(timeoutSeconds);
        this.classificationModel = classificationModel;
        this.numPredict = numPredict;
    }

    @Override
    public GuardrailPolicy.Category classifySemantic(String text) {
        if (text == null || text.isBlank()) {
            return GuardrailPolicy.Category.NONE;
        }

        try {
            return CompletableFuture.supplyAsync(() -> callModel(text))
                    .get(timeout.toMillis(), TimeUnit.MILLISECONDS);
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
                .options(OllamaOptions.builder()
                        .model(classificationModel)
                        .temperature(0.0)
                        .numPredict(numPredict)
                        .build())
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
