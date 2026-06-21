package com.example.demo.guardrail;

/**
 * Default semantic classifier used by GuardrailPolicy's no-arg constructor (existing
 * tests/call sites that construct `new GuardrailPolicy()` directly, without a Spring
 * context to inject the real OllamaSemanticGuardrailClassifier bean). Always reports
 * NONE — i.e. behaves exactly like the pre-semantic-validator GuardrailPolicy did,
 * relying solely on the keyword pass. Production wiring (the @Component-scanned
 * GuardrailPolicy bean) uses OllamaSemanticGuardrailClassifier instead — see
 * GuardrailPolicy's @Autowired constructor.
 */
public class NoOpSemanticGuardrailClassifier implements SemanticGuardrailClassifier {

    @Override
    public GuardrailPolicy.Category classifySemantic(String text) {
        return GuardrailPolicy.Category.NONE;
    }
}
