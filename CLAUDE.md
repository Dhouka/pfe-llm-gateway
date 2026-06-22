# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

LLM Secure Gateway (PFE Satoripop, sujet "Sécurisation des LLM d'Entreprise : Implémentation
de Guardrails avec Spring Cloud Gateway") — a security layer in front of a local Ollama LLM:
PII redaction, output guardrails, rate limiting, JWT auth, audit logging, for banking-style
LLM deployments (target clients: Zitouna Bank, BNA-style institutions). See "PFE subject
mapping" below for exactly what the official subject requires vs. what's implemented.

Three independently runnable components:

- **gateway** (root, Java/Spring) — the security stack: Spring Cloud Gateway dependency +
  Spring AI, Keycloak JWT auth + role-based authorization, Redis rate limiting (**declared
  but not actually wired — see gaps below**), regex + Presidio (via pii-service) PII
  redaction, output guardrails, audit logging (in-memory view + SQLite-backed persistence). This is the
  single source of truth for the chat/security flow — `LlmController` is the only
  consumer-facing AI endpoint. Despite the name, there are no proxied Spring Cloud Gateway
  routes (`spring.cloud.gateway.routes` is intentionally empty) — "gateway" here means the
  security stack, not a reverse proxy.
- **pii-service** (`pii-service/app.py`) — Flask microservice exposing `/analyze`, using
  Microsoft Presidio for ML-based PII detection/anonymization. Wired into the gateway via
  `PiiServiceClient`, called as a second redaction pass after `PiiFilter`'s regexes, with
  fail-open semantics (timeout/error → original text passes through unchanged). Runs via
  `docker-compose.yml` on :5001.
- **llm-flask-service** (`llm-flask-service/app.py`) — dashboard UI only. Serves
  `/dashboard`, a real Keycloak-backed `/login`/`/logout`/`/session`, and a `/audit` route
  that proxies `GET {GATEWAY_URL}/audit` (default `http://localhost:8080`) from the Java
  gateway with the logged-in user's Bearer token attached. The login does a real Keycloak
  password-grant exchange server-side (`gateway-client`, public + `directAccessGrantsEnabled`)
  and keeps the access token in a signed Flask session cookie — no credentials are checked in
  JavaScript, and `/audit` now correctly authenticates against the gateway's
  `audit-viewer`-role-gated endpoint instead of getting 401/403.

The Java gateway owns all `/llm/chat` logic. `llm-flask-service` is a thin dashboard/proxy in
front of the gateway's `/audit` endpoint, not an alternative implementation.

## PFE subject mapping (what the official subject asks for vs. what's here)

The subject's "Spécifications Techniques de la Mission" has three numbered requirements.
File pointers are given so you don't have to re-discover the relevant code.

**1. Filtres de détection et anonymisation PII** (numéros de carte, identifiants nationaux,
emails, anonymisés avant envoi au LLM) — **done**.
- `src/main/java/com/example/demo/filter/PiiFilter.java` — regex pass (email, 16-digit card,
  8-digit Tunisian CIN, Tunisian/intl phone), order `-1`, runs before the request reaches
  `LlmController`/Ollama.
- `src/main/java/com/example/demo/pii/PiiServiceClient.java` — calls `pii-service` for a
  second, ML-based (Presidio) pass on names/addresses/etc. the regexes can't catch. Fail-open
  on timeout/error.
- `pii-service/app.py` — the standalone Presidio `/analyze` endpoint.
- PII detection is now surfaced in the audit trail: `PiiFilter` sets
  `AuditFilter.ATTR_PII_DETECTED`/`ATTR_PII_COUNT` (regex match count + Presidio entity
  count) on the exchange, `AuditFilter` persists them onto `AuditEntry`
  (`piiDetected`/`piiCount`), `AuditController`'s `/audit` response aggregates
  `pii_detections`/`pii_entities_redacted`, and `dashboard.html` shows a "PII Redactions"
  stat card plus a per-row PII column. **Not yet compiled/verified** — same no-Maven-Central
  sandbox caveat as the rate-limiting/semantic-guardrail work below; run `./mvnw clean test`
  locally before trusting this.

**2. Guardrails de sortie avec validateurs sémantiques** (pas de conseils financiers
illégaux, langage toxique, code malveillant) — **now has a real semantic pass, not yet
compile-verified.**
- `src/main/java/com/example/demo/guardrail/GuardrailPolicy.java` — single source of truth
  for the threat taxonomy (`TOXIC`, `ILLEGAL_FINANCE`, `PROMPT_INJECTION`, `MALICIOUS_CODE`).
  `classify(text)` is now two-pass: keyword/substring matching first (fast, catches the
  obvious cases), then — only if that finds nothing — a model-based
  `SemanticGuardrailClassifier` second pass. `toxicityScore(text)` is unchanged, still a
  keyword-count heuristic (it's a signal for the audit log, not the blocking decision).
- `src/main/java/com/example/demo/guardrail/SemanticGuardrailClassifier.java` — the
  semantic-validator interface; `OllamaSemanticGuardrailClassifier.java` is the real
  implementation (a second classification prompt through the same local Ollama model,
  temperature 0, fails open on error/timeout/unparseable output);
  `NoOpSemanticGuardrailClassifier.java` is what `GuardrailPolicy()`'s no-arg constructor
  defaults to (used by existing tests with no Spring context — semantic checking is
  effectively a no-op there, intentionally, so old tests didn't need to change).
- `src/main/java/com/example/demo/filter/OutputGuardrailFilter.java` (order `-2`) — applies
  `GuardrailPolicy` to response bodies, blocks with HTTP 451. Unchanged — still just calls
  `classify()`, which now does more work internally.
- `src/main/java/com/example/demo/controller/LlmController.java` — applies the same policy
  to the model's raw output as defense-in-depth. Unchanged for the same reason.
- This satisfies the subject's explicit "validateurs sémantiques" requirement in the
  smallest viable way for this PFE's scope — see `PFE_TODO.md` task 3 for the
  embeddings-based alternative considered and not used, and for what's still unverified
  (no Maven access in this sandbox to actually compile/run this).

**3. Observabilité et audit (dashboard centralisé)** — **mostly done, with one real bug.**
- `src/main/java/com/example/demo/filter/AuditFilter.java` — one audit entry per request
  (latency, status, event, tokens, toxicity score, UUID correlation ID).
- `src/main/java/com/example/demo/audit/AuditLogStore.java` — in-memory (capped 100, used by
  `/audit`) **plus** a real SQLite database (`audit.db`, path via `AUDIT_DB_FILE`) so history
  survives restarts and can actually be queried (e.g. `sqlite3 audit.db "select * from
  audit_log"`), not just preserved as an opaque flat file.
- `src/main/java/com/example/demo/controller/AuditController.java` (`GET /audit`) — counts +
  raw log list. Now requires the `audit-viewer` Keycloak role (see Phase 3 security
  hardening below).
- `llm-flask-service/templates/dashboard.html` — the actual "dashboard centralisé" UI (charts,
  table, auto-refresh every 3s).
- **Fixed**: the dashboard's login now does a real Keycloak password-grant exchange via
  Flask's `/login` (server-side, token kept in a signed session cookie), and `/audit` attaches
  that token as a Bearer header when proxying to the gateway, so it authenticates correctly
  against the role-gated endpoint. See `llm-flask-service/app.py`.
- Injection attempts ARE visible in the audit trail as `BLOCKED_PROMPT_INJECTION` events
  (handled by the same `GuardrailPolicy`/`OutputGuardrailFilter` path as the other guardrail
  categories) — the subject explicitly calls out tracing "tentatives d'injection."

**Technologies ciblées — coverage:**
- Spring Cloud Gateway: dependency present, used for its `RedisRateLimiter`/`KeyResolver`
  types only — **no actual gateway routes, and see the rate-limiting gap below.**
- Spring AI: wired (`LlmController` → `ChatClient` → `OllamaChatModel`), on GA release
  `1.0.3` via `spring-ai-bom` (previously pinned to the `1.0.0-M5` pre-release milestone;
  the Ollama starter artifact was renamed at GA from `spring-ai-ollama-spring-boot-starter`
  to `spring-ai-starter-model-ollama`). **Not yet compiled/tested in this sandbox** — run
  `./mvnw clean test` locally before trusting this.
- Presidio / regex PII: done (see #1 above).
- Keycloak: done — JWT auth, role-based authorization (`llm-user` for `/llm/**`,
  `audit-viewer` for `/audit`), realm auto-provisioned via
  `keycloak/llm-gateway-realm.json` + Compose `--import-realm`.
- **Redis Rate Limiting: now wired end-to-end (was dead code).**
  `src/main/java/com/example/demo/config/RateLimiterConfig.java` defines the `RedisRateLimiter`
  bean (burst 2, replenish 3) and `ipKeyResolver` `KeyResolver`. Previously nothing ever
  invoked them — the exact same class of bug already fixed for `AuditFilter`/`PiiFilter`/
  `OutputGuardrailFilter` (`GlobalFilter`s only run on a matched route, and
  `spring.cloud.gateway.routes` is empty). Now fixed the same way: a plain `WebFilter`,
  `src/main/java/com/example/demo/filter/RateLimiterWebFilter.java` (order `-3`, scoped to
  `/llm/**`), calls `redisRateLimiter.isAllowed("llm-chat", key)` directly per request and
  returns HTTP 429 on denial. **Not yet compiled/verified** — see `PFE_TODO.md` task 2 and
  `CLAUDE.md`'s "no Maven Central access in this sandbox" caveat below; run `./mvnw clean
  test` locally and a real-Redis manual check before trusting this end-to-end.

## Commands

### Gateway (Java/Spring, root directory)

```
./mvnw clean install          # build
./mvnw spring-boot:run        # run on :8080 (or: java -jar target/gateway-0.0.1-SNAPSHOT.jar)
./mvnw test                   # run all tests
./mvnw test -Dtest=PiiFilterTest                      # run a single test class
./mvnw test -Dtest=PiiFilterTest#testEmailDetection    # run a single test method
```

Or run the whole stack at once: `docker compose up -d --build` (see `README.md` for the full
walkthrough, including getting a Keycloak token for the auto-provisioned `dev-user`).

Backing services from `docker-compose.yml`: Redis (:6379), Keycloak (:8180, auto-imports the
`llm-gateway` realm — see `keycloak/llm-gateway-realm.json`), Ollama (:11434), `pii-service`
(:5001), and the `gateway` service itself (:8080) if you build via Compose.

`/llm/**` requires a JWT with the `llm-user` realm role; `/audit` requires `audit-viewer`;
`/actuator/**` is open.

### llm-flask-service

```
cd llm-flask-service
source venv/bin/activate      # venv is already checked into the repo
python3 app.py                # runs on :5000 (debug=True)
```
Dashboard: http://127.0.0.1:5000/dashboard. Reads audit data by proxying `GET {GATEWAY_URL}/audit`
— currently broken against the role-gated endpoint, see gaps above and `PFE_TODO.md`.

### pii-service

```
cd pii-service
python3 app.py                # runs on :5001 (see docker-compose.yml — PII_SERVICE_PORT)
```

`pii-service/requirements.txt`: `flask`, `flask-cors`, `requests`, `presidio-analyzer`,
`presidio-anonymizer`. `llm-flask-service/requirements.txt` is just `flask`, `flask-cors`,
`requests` (no chat/PII logic left there to need Presidio).

## Architecture (gateway module)

Request flow through Spring WebFlux `WebFilter`s, ordered via `@Order`/`Ordered.getOrder()`
(lower runs first). These used to be Spring Cloud Gateway `GlobalFilter`s, which only execute
for requests matched by a configured route; since `spring.cloud.gateway.routes` is empty,
none of them ever ran. They were converted to plain `WebFilter`s, which register against the
universal reactive filter chain regardless of routing. **Rate limiting now has this same fix
applied (`RateLimiterWebFilter`) — see below.**

1. `AuditFilter` (order `Integer.MIN_VALUE`) — wraps the whole chain, generates a UUID
   correlation ID per request (exposed as an exchange attribute and via MDC), and records
   timestamp/method/path/latency/status/correlationId into `AuditLogStore` in a
   `doAfterTerminate` callback. Reads exchange attributes set by `LlmController`
   (`ATTR_EVENT`, `ATTR_PROMPT_TOKENS`, `ATTR_COMPLETION_TOKENS`, `ATTR_TOTAL_TOKENS`,
   `ATTR_TOXICITY_SCORE`, `ATTR_CORRELATION_ID`); if `ATTR_EVENT` isn't set, falls back to
   status-code mapping (401→`BLOCKED_NO_AUTH`, 429→`BLOCKED_RATE_LIMIT`, 451→`BLOCKED_GUARDRAIL`,
   403→`BLOCKED_FORBIDDEN`, else `ALLOWED`). The only place that writes to `AuditLogStore`.
2. `RateLimiterWebFilter` (order `-3`) — scoped to `/llm/**`, resolves a key via
   `ipKeyResolver` and calls `redisRateLimiter.isAllowed("llm-chat", key)` directly; on
   denial, sets `ATTR_EVENT=BLOCKED_RATE_LIMIT` and returns HTTP 429 + JSON error before
   PII/guardrail filters do any work on the request.
3. `OutputGuardrailFilter` (order `-2`) — decorates the **response**, buffers the full body,
   classifies it via the shared `GuardrailPolicy` (keyword/substring matching — see gap
   above), short-circuits with HTTP 451 + JSON error if blocked.
4. `PiiFilter` (order `-1`) — decorates the **request**, buffers the full body, regex-redacts
   email/credit-card/Tunisian-CIN/phone, then sends the result through `PiiServiceClient`
   (pii-service's Presidio `/analyze`, 2s timeout + one retry, fails open) before forwarding.
5. `RateLimiterConfig` registers the `RedisRateLimiter` bean and `KeyResolver` that
   `RateLimiterWebFilter` consumes, plus the security filter chain below.
6. `RateLimiterConfig.securityWebFilterChain` — CSRF disabled, `/actuator/**` open, `/audit`
   requires `hasRole("audit-viewer")`, `/llm/**` requires `hasRole("llm-user")`, everything
   else permitted. JWT roles come from Keycloak's `realm_access.roles` claim, mapped to
   `ROLE_`-prefixed authorities by the custom `jwtAuthenticationConverter()` bean (Spring
   Security's default converter only reads `scope`/`scp`, which Keycloak doesn't populate the
   way this app needs). `issuer-uri` and `jwk-set-uri` are configured separately in
   `application.yml` so a containerized gateway can validate a token's `iss` claim against
   the address a human/client used to reach Keycloak, while fetching JWKS over the internal
   Docker network — see the comments there and in `docker-compose.yml`'s `gateway`/`keycloak`
   services if you touch this.

`LlmController` (`POST /llm/chat`) is the only consumer-facing AI endpoint. Builds a
`ChatClient` from the injected `OllamaChatModel` (a package-private constructor also accepts
a `ChatClient` directly, for tests), classifies the model's raw output via the shared
`GuardrailPolicy` as defense-in-depth, returns a real `ResponseEntity` (451 when blocked, 200
otherwise), and writes outcome data only as exchange attributes for `AuditFilter` to consume.

`AuditLogStore`: in-memory `CopyOnWriteArrayList` capped at 100 (used by `/audit`'s "recent
activity" view) **plus** a real SQLite database on disk (`audit.db`, configurable via
`AUDIT_DB_FILE`, `PRAGMA journal_mode=WAL`) so a restart doesn't lose audit history and the
full history can actually be queried (e.g. for compliance reporting), not just preserved as
an opaque flat file. Fails open on `SQLException` (logs a warning, the in-memory view still
works, but that entry won't survive a restart) — same fail-open philosophy as
`PiiServiceClient`/`OllamaSemanticGuardrailClassifier`. **Not yet compiled/tested in this
sandbox** — run `./mvnw clean test` locally before trusting this end-to-end.

`GuardrailPolicy` (`com.example.demo.guardrail`) is the single source of truth for the threat
taxonomy. Both `OutputGuardrailFilter` and `LlmController` depend on it. **This is keyword
matching, not semantic validation — see the PFE subject mapping gap above before treating
this as "done" for the subject's purposes.**

`GlobalExceptionHandler` (`com.example.demo.error`, `@RestControllerAdvice`) maps Ollama
connection failures (`ResourceAccessException`/`ConnectException`) to 503, timeouts to 504,
bad input to 400, and anything else to a generic 500 — all with a stable `{"error": "..."}`
body instead of a raw stack trace.

## Key things to watch for when changing security logic

- Guardrail keywords live in **one place**: `GuardrailPolicy`. Update it and both
  `OutputGuardrailFilter` and `LlmController` pick up the change. If you're implementing the
  semantic-validator gap from the PFE subject, this is the class to replace/extend —
  `classify()`'s signature (`String → Verdict`) can stay the same even if the implementation
  becomes a model call instead of `String.contains()`.
- PII detection is layered: `PiiFilter`'s regexes run first, then `PiiServiceClient` (Presidio)
  as a second pass. `PiiServiceClient` fails open (logs a warning, passes through
  regex-sanitized text) on any pii-service error/timeout — don't change this to fail-closed
  without discussing the availability tradeoff explicitly, per
  `AUDIT_AND_REFACTOR_PLAN.md` section 4.
- Tests for `GuardrailPolicy`, `OutputGuardrailFilter`, `PiiFilter`, `AuditFilter`,
  `AuditLogStore`, `LlmController`, and `GlobalExceptionHandler` exercise the real production
  classes (mocking only true I/O boundaries — `PiiServiceClient`, `ChatClient`). Keep new
  tests pointed at the real classes. `AuditLogStore`'s tests use JUnit `@TempDir` for its
  on-disk SQLite file so test runs don't write an `audit.db` into the repo working directory.
- This sandbox/CI environment has no Maven Central access — if `./mvnw test` can't resolve
  dependencies here, that's environment, not a real regression. **As of the last session,
  none of the Java changes in this repo have actually been compiled** — verify with a real
  `./mvnw clean test` locally before trusting any of this description.
- Before adding the rate-limiting fix (PFE_TODO.md task 2), read how `AuditFilter`/`PiiFilter`/
  `OutputGuardrailFilter` were converted from `GlobalFilter` to `WebFilter` — the same pattern
  (call the underlying logic directly in a `WebFilter`, ordered appropriately, instead of
  relying on Spring Cloud Gateway's route-filter machinery) is almost certainly the fix here
  too, since `RequestRateLimiterGatewayFilterFactory` requires a route.

See `PFE_TODO.md` for the prioritized list of what's left to fully satisfy the PFE subject.
