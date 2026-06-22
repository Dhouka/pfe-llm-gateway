# LLM Secure Gateway - PFE Satoripop

A secured REST API in front of a local Ollama LLM, built for banking-style deployments:
JWT auth, role-based authorization, PII redaction, output guardrails, rate limiting, and
audit logging. See `CLAUDE.md` for the full architecture writeup and
`AUDIT_AND_REFACTOR_PLAN.md` for the history of issues found and fixed in this repo.

Despite the name, this is **not** a reverse proxy — `spring.cloud.gateway.routes` is
intentionally empty. `LlmController` (`POST /llm/chat`) is a normal secured endpoint that
calls Ollama directly via Spring AI; the security stack (auth, rate limiting, PII
redaction, guardrails, audit logging) is what "gateway" refers to here, not request
proxying.

## Components

- **gateway** (root, Java/Spring) — the security stack: JWT auth via Keycloak, Redis
  rate limiting, regex + Presidio PII redaction, output guardrails, audit logging.
  `LlmController` is the only consumer-facing AI endpoint.
- **pii-service** (`pii-service/`, Flask + Presidio) — ML-based PII detection, called by
  the gateway as a second redaction pass. Fails open if unreachable.
- **llm-flask-service** (`llm-flask-service/`, Flask) — dashboard UI only. Reads audit
  data by proxying `GET /audit` from the gateway; it has no chat or guardrail logic of
  its own.

## Credentials

| Interface | Username | Password | Roles | Notes |
|---|---|---|---|---|
| [Dashboard](http://127.0.0.1:5000/dashboard) | `dev-user` | `dev-user` | `llm-user`, `audit-viewer` | Pre-provisioned test account |
| [Keycloak Admin Console](http://localhost:8180) | `admin` | set in `.env` (`KEYCLOAK_ADMIN_PASSWORD`) | Keycloak admin | Manage users, roles, realm config |

The `dev-user` account is auto-created when Keycloak starts with `--import-realm` (as
configured in `docker-compose.yml`). It holds both `llm-user` (needed for `POST /llm/chat`)
and `audit-viewer` (needed for `GET /audit` and the dashboard).

## Quick start (Docker Compose — recommended)

1. Copy `.env.example` to `.env` and set `KEYCLOAK_ADMIN_PASSWORD` (required, no default).
2. `docker compose up -d --build` — starts Redis, Keycloak (auto-imports the
   `llm-gateway` realm from `keycloak/llm-gateway-realm.json`, including the `llm-user`
   and `audit-viewer` roles the gateway requires, plus a `dev-user`/`dev-user` test
   account holding both), Ollama, `pii-service`, and the gateway itself.
3. `docker exec gateway-ollama ollama pull tinyllama` (the `tinyllama` model isn't baked
   into the Ollama image).
4. Get a token for the dev test user:
   ```
   curl -X POST http://localhost:8180/realms/llm-gateway/protocol/openid-connect/token \
     -d 'client_id=gateway-client' -d 'grant_type=password' \
     -d 'username=dev-user' -d 'password=dev-user'
   ```
5. Call the gateway: `curl -X POST http://localhost:8080/llm/chat -H "Authorization: Bearer <access_token>" -H 'Content-Type: application/json' -d '{"message":"hello"}'`
6. Audit data: `curl http://localhost:8080/audit -H "Authorization: Bearer <access_token>"` (requires the `audit-viewer` role; `dev-user` has it).
7. Dashboard (optional): `cd llm-flask-service && source venv/bin/activate && python3 app.py`, then open http://127.0.0.1:5000/dashboard.

## Running components individually (without Compose)

```
docker compose up -d redis keycloak ollama pii-service   # backing services only
ollama pull tinyllama
./mvnw spring-boot:run                                     # gateway on :8080
```

Requires the same `llm-gateway` Keycloak realm/roles — either let Keycloak's
`--import-realm` (already configured in `docker-compose.yml`) create them, or set them
up manually in the admin console (http://localhost:8180, login from `.env`).

## Tests

```
./mvnw test
```

Tests exercise the real production classes (`GuardrailPolicy`, `PiiFilter`,
`OutputGuardrailFilter`, `AuditFilter`, `AuditLogStore`, `LlmController`,
`GlobalExceptionHandler`), mocking only true I/O boundaries (`PiiServiceClient`,
`ChatClient`).

## Notes

- Spring AI is on `1.0.3` (GA, via `spring-ai-bom`) — was previously pinned to the
  `1.0.0-M5` pre-release milestone; the artifact also changed name at GA from
  `spring-ai-ollama-spring-boot-starter` to `spring-ai-starter-model-ollama`.
- The audit log is persisted to a real SQLite database (`audit.db`, path configurable
  via `AUDIT_DB_FILE`) in addition to the in-memory, 100-entry-capped view `/audit`
  serves — replaces the previous flat-file JSONL stopgap, so the full history can
  actually be queried (e.g. `sqlite3 audit.db "select * from audit_log"`), not just
  "not lost on restart."

## Author

Yassine Kooli - PFE Satoripop 2026
