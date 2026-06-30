# Dashboard-only Flask app (see app.py's module docstring — this no longer duplicates
# the gateway's chat/PII/guardrail logic, it only renders dashboard.html and proxies
# GET requests to the Java gateway's /audit* endpoints with the logged-in user's
# Keycloak bearer token attached).
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY templates ./templates
COPY static ./static
EXPOSE 5000
# debug=True (set in app.py's __main__ block) is fine for this PFE's local/demo
# scope, matching the rest of this repo's "documented dev-mode defaults" pattern
# (e.g. Keycloak's start-dev, FLASK_SECRET_KEY's dev fallback) — not hardened for a
# real production deployment.
CMD ["python3", "app.py"]
