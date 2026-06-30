"""
Standalone PII detection/anonymization microservice, built on Microsoft Presidio.

Called by the gateway's PiiFilter (Java) as a second pass after regex redaction,
to catch unstructured PII (names, addresses, locations, etc.) that the gateway's
hand-written regexes don't attempt. See PiiFilter.java and
AUDIT_AND_REFACTOR_PLAN.md section 4/5 for the integration contract.

Runs on port 5001 by default (llm-flask-service uses 5000 — keep them distinct
so both can run at once under docker-compose).

Language coverage: English + French.
Presidio's AnalyzerEngine is invoked once per supported language and the
per-language results are merged with de-duplication on character span (see
SUPPORTED_LANGUAGES / analyze() below). French is included because this
gateway's target clients are Tunisian banks where end users predominantly
write in French.

Arabic is intentionally NOT added here. Presidio's NLP backend (spaCy)
requires a separate Arabic language model that isn't bundled in this
service's image, and adding one would mean shipping/maintaining a third
spaCy model just for this microservice. Arabic PII is instead covered
upstream by the gateway's own regex pass (PiiFilter.java: CIN, phone,
card number) — those patterns are digit/symbol based and are therefore
language-agnostic by construction, so they catch Arabic-script prompts
just as well as French or English ones. Only the *contextual* ML-based
detection (names, addresses, free-text entities) is unavailable for
Arabic text in this second pass; the structured-PII safety net from the
regex pass still applies regardless of language.
"""

import os
from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine

app = Flask(__name__)

# AnalyzerEngine() with no arguments only loads the English spaCy model, so
# analyze(language="fr") would silently fail (caught by the per-language
# except below) without this explicit multi-language NLP engine config.
# Matching spaCy models must be downloaded in the Dockerfile/requirements.
_nlp_configuration = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "en", "model_name": "en_core_web_lg"},
        {"lang_code": "fr", "model_name": "fr_core_news_lg"},
    ],
}
_nlp_engine = NlpEngineProvider(nlp_configuration=_nlp_configuration).create_engine()

analyzer = AnalyzerEngine(nlp_engine=_nlp_engine, supported_languages=["en", "fr"])
anonymizer = AnonymizerEngine()

# English + French — see module docstring for why Arabic is not included here.
SUPPORTED_LANGUAGES = ["en", "fr"]


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not text:
        return jsonify({"error": "missing 'text' field"}), 400

    # Multi-language pass: analyze once per supported language, then merge
    # results by de-duplicating on character span (start, end, entity_type).
    # When the same span is detected under more than one language model,
    # the highest-confidence result is kept.
    seen_spans = {}
    for lang in SUPPORTED_LANGUAGES:
        try:
            for result in analyzer.analyze(text=text, language=lang):
                key = (result.start, result.end, result.entity_type)
                if key not in seen_spans or result.score > seen_spans[key].score:
                    seen_spans[key] = result
        except Exception:
            # Fail-open per language: if a language model is unavailable,
            # skip it rather than failing the whole /analyze call.
            pass

    results = list(seen_spans.values())
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)
    detected_types = sorted({r.entity_type for r in results})

    return jsonify({
        "original": text,
        "anonymized": anonymized.text,
        "entities_detected": detected_types,
        "count": len(results)
    })


if __name__ == "__main__":
    port = int(os.environ.get("PII_SERVICE_PORT", 5001))
    app.run(host="0.0.0.0", port=port)
