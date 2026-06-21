package com.example.demo.guardrail;

/**
 * Second-pass, model-based classifier for output guardrails — the "validateurs
 * sémantiques" the PFE subject explicitly asks for, as opposed to GuardrailPolicy's
 * first-pass keyword/substring matching (cheap, but trivially bypassed by paraphrase,
 * typos, or non-English phrasing).
 *
 * Implementations MUST fail open (return Category.NONE) on any error, timeout, or
 * unparseable model output — a guardrail check should never itself become an outage,
 * and the keyword pass already provides a fast first line of defense. This mirrors
 * PiiServiceClient's fail-open contract for the same reason.
 */
public interface SemanticGuardrailClassifier {

    GuardrailPolicy.Category classifySemantic(String text);
}
