"""
Standalone PII detection/anonymization microservice, built on Microsoft Presidio.

Called by the gateway's PiiFilter (Java) as a second pass after regex redaction,
to catch unstructured PII (names, addresses, locations, etc.) that the gateway's
hand-written regexes don't attempt. See PiiFilter.java and
AUDIT_AND_REFACTOR_PLAN.md section 4/5 for the integration contract.

Runs on port 5001 by default (llm-flask-service uses 5000 — keep them distinct
so both can run at once under docker-compose).
"""

import os
from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

app = Flask(__name__)

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")

    if not text:
        return jsonify({"error": "missing 'text' field"}), 400

    results = analyzer.analyze(text=text, language="en")
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
