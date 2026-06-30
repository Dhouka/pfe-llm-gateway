"""
Dashboard-only Flask app for the LLM Secure Gateway.

This used to be a full duplicate reimplementation of the chat + guardrail + PII +
audit flow (calling Ollama directly, bypassing the Java gateway entirely). Per
AUDIT_AND_REFACTOR_PLAN.md sections 4/5, the Java Spring Cloud Gateway
(gateway/LlmController + filters) is now the single source of truth for that flow.
This app's only remaining job is to serve the dashboard UI and proxy its data from the
gateway's real /audit endpoint, so the same audit log is shown everywhere instead of a
second, independent in-memory log.

Auth: the dashboard used to have a fake, hardcoded client-side JS login
(admin/satoripop2026) that wasn't connected to anything. The gateway's /audit now
requires a real Keycloak `audit-viewer` role, so this app does a real Keycloak
Resource Owner Password Credentials (direct access grant) login against the same
`llm-gateway` realm/`gateway-client` client the gateway itself trusts, stores the
resulting access token server-side in the Flask session (signed cookie), and attaches
it as a Bearer token when proxying /audit. No credentials are ever checked in
JavaScript.
"""

import os
import time

import requests
from flask import Flask, jsonify, render_template, request, session
from flask_cors import CORS

app = Flask(__name__)
# Required for Flask's signed session cookie. Must be set to a real secret outside of
# local dev — falls back to a fixed dev value so `python3 app.py` works out of the box,
# matching this repo's existing "local dev has sane defaults, prod must override" pattern
# (see KEYCLOAK_ADMIN_PASSWORD in docker-compose.yml for the same idea applied stricter).
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-insecure-secret-change-me")
CORS(app, supports_credentials=True)

GATEWAY_URL = os.environ.get("GATEWAY_URL", "http://localhost:8080")
KEYCLOAK_TOKEN_URL = os.environ.get(
    "KEYCLOAK_TOKEN_URL",
    "http://localhost:8180/realms/llm-gateway/protocol/openid-connect/token",
)
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "gateway-client")

# Refresh the access token slightly before it actually expires.
TOKEN_EXPIRY_SKEW_SECONDS = 30


@app.route("/login", methods=["POST"])
def login():
    """Real Keycloak login: exchanges username/password for an access token via the
    realm's direct access grant (gateway-client is a public client with
    directAccessGrantsEnabled=true, so no client secret is needed). The token is kept
    server-side in the session cookie — the browser never sees it directly and no
    credential comparison happens in JavaScript."""
    body = request.get_json(silent=True) or {}
    username = body.get("username", "")
    password = body.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    try:
        resp = requests.post(
            KEYCLOAK_TOKEN_URL,
            data={
                "client_id": KEYCLOAK_CLIENT_ID,
                "grant_type": "password",
                "username": username,
                "password": password,
            },
            timeout=5,
        )
    except requests.RequestException as e:
        return jsonify({"error": f"keycloak unreachable: {e}"}), 502

    if resp.status_code != 200:
        return jsonify({"error": "invalid username or password"}), 401

    token_data = resp.json()
    session["access_token"] = token_data["access_token"]
    session["token_expires_at"] = time.time() + token_data.get("expires_in", 60)
    session["username"] = username
    return jsonify({"ok": True, "username": username})


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok": True})


@app.route("/session")
def session_status():
    """Lets the dashboard check on page load whether it already has a valid session
    (e.g. after a browser refresh) without re-prompting for credentials."""
    token = session.get("access_token")
    expires_at = session.get("token_expires_at", 0)
    if token and time.time() < expires_at - TOKEN_EXPIRY_SKEW_SECONDS:
        return jsonify({"authenticated": True, "username": session.get("username")})
    return jsonify({"authenticated": False})


@app.route("/audit")
def audit():
    """Proxies the gateway's real /audit endpoint instead of keeping a second,
    independent in-memory audit log that would drift from what the gateway recorded.
    Requires a valid Keycloak session (see /login) — the gateway's /audit endpoint
    requires the audit-viewer role, so this forwards the session's bearer token rather
    than calling the gateway unauthenticated."""
    token = session.get("access_token")
    expires_at = session.get("token_expires_at", 0)
    if not token or time.time() >= expires_at - TOKEN_EXPIRY_SKEW_SECONDS:
        return jsonify({"error": "not authenticated"}), 401

    try:
        response = requests.get(
            f"{GATEWAY_URL}/audit",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"gateway unreachable: {e}"}), 502


@app.route("/audit/summary")
def audit_summary():
    """Proxies the gateway's /audit/summary endpoint."""
    token = session.get("access_token")
    expires_at = session.get("token_expires_at", 0)
    if not token or time.time() >= expires_at - TOKEN_EXPIRY_SKEW_SECONDS:
        return jsonify({"error": "not authenticated"}), 401

    try:
        response = requests.get(
            f"{GATEWAY_URL}/audit/summary",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"gateway unreachable: {e}"}), 502


@app.route("/audit/detail/<correlation_id>")
def audit_detail(correlation_id):
    """Proxies the gateway's /audit/detail/{correlationId} endpoint."""
    token = session.get("access_token")
    expires_at = session.get("token_expires_at", 0)
    if not token or time.time() >= expires_at - TOKEN_EXPIRY_SKEW_SECONDS:
        return jsonify({"error": "not authenticated"}), 401

    try:
        response = requests.get(
            f"{GATEWAY_URL}/audit/detail/{correlation_id}",
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({"error": f"gateway unreachable: {e}"}), 502


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


if __name__ == "__main__":
    port = int(os.environ.get("DASHBOARD_PORT", 5000))
    # host must be 0.0.0.0, not Flask's default of 127.0.0.1 (loopback-only). Real bug
    # found 2026-06-26: with the default, this app was only reachable from inside its
    # own container's network namespace -- the Docker healthcheck (which execs into the
    # container and hits localhost:5000 directly) passed and reported "healthy", but
    # every external request through the published host port (e.g. curl/browser against
    # 127.0.0.1:5050 on the host) got TCP-accepted by Docker's port-forwarding proxy and
    # then RST the moment Docker tried to hand the connection to the container's actual
    # (non-loopback) interface, where nothing was listening. Symptom was identical for
    # every route, including the trivial /session -- this was never about /dashboard's
    # template or any app logic, purely the bind address.
    app.run(debug=True, port=port, host="0.0.0.0")
