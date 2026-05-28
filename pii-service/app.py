from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine

app = Flask(__name__)

analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()

@app.route("/analyze", methods=["POST"])
def analyze():
    text = request.json["text"]

    results = analyzer.analyze(text=text, language="en")
    anonymized = anonymizer.anonymize(text=text, analyzer_results=results)

    return jsonify({
        "original": text,
        "anonymized": anonymized.text
    })

if __name__ == "__main__":
    app.run(port=5000)
