package com.example.demo.guardrail;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Single source of truth for the gateway's threat taxonomy (toxic language, illegal
 * financial advice, prompt injection, malicious code). Both {@code OutputGuardrailFilter}
 * (response-side WebFilter) and {@code LlmController} (defense-in-depth check on the
 * model's raw output before it's wrapped in a response) call into this class instead of
 * each keeping their own copy of the keyword lists.
 *
 * Previously these lists existed independently in two Java classes (and again as
 * hardcoded fixtures in llm-flask-service) and had already drifted: the malicious-code
 * patterns only existed in LlmController. Consolidating here means there is exactly one
 * place to update when the threat taxonomy changes.
 *
 * classify() is now two-pass: the original keyword/substring match runs first (cheap,
 * catches the obvious cases instantly), and if that finds nothing, a second,
 * model-based SemanticGuardrailClassifier pass runs (catches paraphrases, typos, and
 * non-English phrasing the keyword pass can't) — this is the PFE subject's explicit
 * "validateurs sémantiques" requirement. See OllamaSemanticGuardrailClassifier for the
 * real implementation; NoOpSemanticGuardrailClassifier is the default used when no
 * Spring context wires a real one (e.g. existing tests constructing
 * `new GuardrailPolicy()` directly keep working unchanged, with semantic checking
 * effectively disabled).
 */
@Component
public class GuardrailPolicy {

    private final SemanticGuardrailClassifier semanticClassifier;

    @Autowired
    public GuardrailPolicy(SemanticGuardrailClassifier semanticClassifier) {
        this.semanticClassifier = semanticClassifier;
    }

    public GuardrailPolicy() {
        this(new NoOpSemanticGuardrailClassifier());
    }

    public enum Category {
        NONE,
        TOXIC,
        ILLEGAL_FINANCE,
        PROMPT_INJECTION,
        MALICIOUS_CODE
    }

    public record Verdict(Category category, String matchedPattern) {
        public boolean isBlocked() {
            return category != Category.NONE;
        }
    }

    private static final List<String> TOXIC_KEYWORDS = List.of(
            "idiot", "stupid", "kill yourself", "hate you",
            "moron", "loser", "shut up", "you are worthless"
    );

    private static final List<String> ILLEGAL_FINANCE_KEYWORDS = List.of(
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

    /**
     * Classifies the given text against the full threat taxonomy. First pass: keyword/
     * substring matching, in priority order (toxic -> illegal finance -> prompt
     * injection -> malicious code) — cheap, catches the obvious cases instantly.
     * Second pass: only runs if the first pass found nothing, and only calls into the
     * (possibly model-backed, possibly network-bound) SemanticGuardrailClassifier —
     * never on the hot path of an already-blocked request.
     */
    public Verdict classify(String text) {
        if (text == null || text.isEmpty()) {
            return new Verdict(Category.NONE, null);
        }
        String lower = text.toLowerCase();

        for (String keyword : TOXIC_KEYWORDS) {
            if (lower.contains(keyword)) {
                return new Verdict(Category.TOXIC, keyword);
            }
        }
        for (String keyword : ILLEGAL_FINANCE_KEYWORDS) {
            if (lower.contains(keyword)) {
                return new Verdict(Category.ILLEGAL_FINANCE, keyword);
            }
        }
        for (String pattern : INJECTION_PATTERNS) {
            if (lower.contains(pattern)) {
                return new Verdict(Category.PROMPT_INJECTION, pattern);
            }
        }
        for (String pattern : MALICIOUS_CODE_PATTERNS) {
            if (lower.contains(pattern)) {
                return new Verdict(Category.MALICIOUS_CODE, pattern);
            }
        }

        Category semanticCategory = semanticClassifier.classifySemantic(text);
        if (semanticCategory != Category.NONE) {
            return new Verdict(semanticCategory, "[semantic-detection]");
        }

        return new Verdict(Category.NONE, null);
    }

    /**
     * Crude toxicity score in [0.0, 1.0] based on how many distinct toxic keywords
     * appear in the text. Kept simple intentionally — this is a heuristic signal for
     * the audit log, not a moderation decision by itself (classify() drives blocking).
     */
    public double toxicityScore(String text) {
        if (text == null || text.isEmpty()) {
            return 0.0;
        }
        String lower = text.toLowerCase();
        long matches = TOXIC_KEYWORDS.stream().filter(lower::contains).count();
        return Math.min(1.0, matches * 0.2);
    }

    public List<String> toxicKeywords() {
        return TOXIC_KEYWORDS;
    }

    public List<String> illegalFinanceKeywords() {
        return ILLEGAL_FINANCE_KEYWORDS;
    }

    public List<String> injectionPatterns() {
        return INJECTION_PATTERNS;
    }

    public List<String> maliciousCodePatterns() {
        return MALICIOUS_CODE_PATTERNS;
    }
}
