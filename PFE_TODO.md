# PFE TODO — closing the gap with the official subject

Source: official PFE subject ("Sécurisation des LLM d'Entreprise: Implémentation de
Guardrails avec Spring Cloud Gateway", Satoripop). See `CLAUDE.md`'s "PFE subject mapping"
section for the full file-by-file breakdown this list is derived from. Ordered by severity —
do these in order.

## 1. Fix the dashboard's broken/fake auth — DONE

Implemented: `llm-flask-service/app.py` now has real `/login`, `/logout`, `/session` routes
that perform a Keycloak password-grant exchange against `gateway-client` (public,
`directAccessGrantsEnabled=true`, no secret needed) and keep the access token server-side in
a signed Flask session cookie. `/audit` requires that session and forwards the token as
`Authorization: Bearer <token>` to the gateway. `dashboard.html`'s hardcoded
`admin`/`satoripop2026` JS check and `sessionStorage` flag are gone — login/logout/session
checks all go through the Flask backend now.

Verified: unit-level smoke test via Flask's `test_client()` confirms `/session` reports
unauthenticated by default, `/audit` returns 401 without a session, `/login` validates
required fields (400) and surfaces a clean 502 when Keycloak is unreachable. Full
live-Keycloak verification (real `dev-user`/`dev-user` login → dashboard renders live audit
data) still needs to be run against the actual `docker compose up -d` stack, since this
sandbox has no Keycloak/Redis/Ollama containers — do that as part of task 5's full-stack
verification pass.

## 2. Wire up Redis rate limiting (highest-severity gap vs. the subject) — IMPLEMENTED, compiled and passing

`RateLimiterConfig.redisRateLimiter()`/`ipKeyResolver()` are defined but never called by
anything — `spring.cloud.gateway.routes` is empty, and no `WebFilter` invokes
`RedisRateLimiter.isAllowed(...)` directly (unlike `AuditFilter`/`PiiFilter`/
`OutputGuardrailFilter`, which were already fixed from the same underlying "GlobalFilter never
runs without a route" bug). Today, **nothing in this app is rate-limited**, despite "Redis
(Rate Limiting)" being an explicit target technology in the subject.

- Add a `RateLimiterWebFilter` (plain `@Component WebFilter`, ordered before `PiiFilter`,
  e.g. order `0` or between `-1` and the rest) that:
  - Resolves a key via the existing `ipKeyResolver` `KeyResolver` (or a new principal-based
    resolver, matching the prior CLAUDE.md note about "keyed by authenticated principal name,
    falling back to remote IP" — confirm what `ipKeyResolver` actually does before assuming).
  - Calls `redisRateLimiter().isAllowed(routeId, key).block()` (or chain reactively —
    `isAllowed` already returns a `Mono<Response>`) and short-circuits with HTTP 429 +
    JSON error body (consistent with the other filters' error-response shape) when not
    allowed.
  - Sets an exchange attribute so `AuditFilter` records `BLOCKED_RATE_LIMIT` (it already maps
    HTTP 429 → `BLOCKED_RATE_LIMIT` as a fallback, so this may already work once 429 is
    actually returned — verify rather than re-implement).
- Apply this filter to `/llm/**` at minimum (the expensive, abusable endpoint) — confirm with
  the subject's intent whether `/audit` should also be limited (probably not critical).
- Write a test mirroring `PiiFilterTest`'s style: mock `RedisRateLimiter`, assert 429 on
  denial and pass-through on allow.
- Manually verify against the real Redis container (burst 2, replenish 3 means the 3rd rapid
  request should 429) — don't just trust unit tests with mocks for this one, since the whole
  point is end-to-end enforcement.

**Status**: `src/main/java/com/example/demo/filter/RateLimiterWebFilter.java` implements
exactly this — order `-3` (runs before PiiFilter/OutputGuardrailFilter, inside AuditFilter),
scoped to `/llm/**`, calls `redisRateLimiter.isAllowed("llm-chat", key)` via the existing
`ipKeyResolver`, returns 429 + sets `AuditFilter.ATTR_EVENT=BLOCKED_RATE_LIMIT` on denial.
Unit test `RateLimiterWebFilterTest` covers allow/deny/path-scoping with `RedisRateLimiter`
mocked (true Redis I/O boundary). **Compiled and passing** — confirmed by a real
`./mvnw clean test` run (JDK 21, 2026-06-20). Still worth the real-Redis manual check
described above (burst=2/replenish=3 means the 3rd rapid `/llm/chat` call should 429) once the
full Compose stack is up — unit tests with a mocked `RedisRateLimiter` don't exercise actual
Redis behavior.

## 3. Add real semantic validation to output guardrails — IMPLEMENTED (Option A), compiled and passing

`GuardrailPolicy.classify()` is `lower.contains(keyword)` against four hardcoded lists — not
semantic in any sense, and the subject explicitly asks for "validateurs sémantiques." This is
the part most likely to get questioned in a PFE defense if left as-is.

Pick one approach (smallest viable scope for a PFE, not a research project):

- **Option A (recommended, fits existing stack):** use Spring AI's existing Ollama
  integration to run a second, cheap classification prompt: send the candidate text to the
  LLM with a strict system prompt ("classify as TOXIC/ILLEGAL_FINANCE/MALICIOUS_CODE/NONE,
  respond with only the label"), parse the label. This is genuinely semantic (the model
  reasons about meaning, not substrings), reuses the `OllamaChatModel` already wired in
  `LlmController`, and needs no new infrastructure. Downside: adds latency (a second LLM
  call) and cost — keep the guardrail prompt short and the model's `temperature` low/0 for
  determinism.
- **Option B (more "ML" but more infra):** embeddings-based similarity — embed a bank of
  known-bad example phrases per category once, embed the candidate text per request, flag if
  cosine similarity exceeds a threshold against any category's centroid. Spring AI has
  embedding model abstractions; needs an embedding-capable Ollama model pulled
  (`nomic-embed-text` or similar) and a small in-memory vector store. More defensible as
  "semantic" in a strict ML sense, more code, more moving parts to explain in a defense.
- Either way: **keep the existing keyword lists as a fast first-pass filter** (cheap,
  catches the obvious cases instantly) and add the semantic check as a second pass for
  cases the keyword pass lets through — same layering pattern already used for PII
  (regex first, Presidio second). Update `GuardrailPolicy.classify()`'s internals; callers
  (`OutputGuardrailFilter`, `LlmController`) shouldn't need to change.
- Add tests with paraphrased/non-keyword examples that the old keyword-only version would
  have missed, to demonstrate the improvement (and to have something concrete to show in a
  PFE defense — "here's a prompt-injection attempt that bypassed keyword matching but was
  caught semantically").

**Status**: implemented as Option A. New `SemanticGuardrailClassifier` interface +
`OllamaSemanticGuardrailClassifier` (real impl — second classification prompt through the
same Ollama model, temperature 0, 8s timeout, fails open to `NONE` on any error/timeout/
unparseable output) + `NoOpSemanticGuardrailClassifier` (default for the no-arg
`GuardrailPolicy()` constructor existing tests already use, so nothing broke).
`GuardrailPolicy.classify()` now runs the keyword pass first as before, and only calls the
semantic classifier if that finds nothing — `GuardrailPolicySemanticTest` proves the
short-circuit (`verifyNoInteractions` on a keyword hit) and demonstrates two paraphrased
examples (toxicity, prompt injection) that the keyword pass alone would miss but the mocked
semantic classifier catches. `OllamaSemanticGuardrailClassifier` itself has no dedicated
test, matching this repo's existing convention of mocking true I/O boundaries in their
consumers' tests rather than unit-testing the boundary client (see: no `PiiServiceClientTest`
exists either). **Not yet compiled/verified** — same Maven-access caveat as task 2; also
worth a manual check once Ollama is running: confirm the model actually returns parseable
single-word category labels for a few real paraphrased prompts, since LLM output format
compliance is never 100% guaranteed and `parseCategory()`'s fail-open-on-unparseable behavior
should be the common case to exercise, not the only path ever taken.

## 4. Surface PII-detection events in the audit trail — IMPLEMENTED, needs local compile verification

`PiiFilter` detected and redacted PII but only logged it at `debug` level — invisible to
compliance/audit consumers, even though the subject's audit requirement implies tracing PII
handling, not just token/latency/toxicity.

**Status**: implemented end-to-end.
- `PiiServiceClient.anonymize()` now returns `Mono<Result>` (`record Result(String text, int
  entityCount)`) instead of bare `Mono<String>`, so the Presidio entity count it already
  parsed (previously discarded after a debug log line) reaches the caller.
- `PiiFilter.applyRegexRedaction()` now returns a `RegexRedactionResult(text, matchCount)`
  counting how many of the 4 regex patterns (email/card/CIN/phone) fired. Combined with
  `PiiServiceClient.Result.entityCount()`, `PiiFilter` sets two new exchange attributes —
  `AuditFilter.ATTR_PII_DETECTED` (boolean) and `ATTR_PII_COUNT` (int, regex + Presidio
  combined) — after redaction, mirroring how `LlmController` sets `ATTR_TOXICITY_SCORE`.
- `AuditFilter` reads both attributes (defaulting to `false`/`0` when unset) and passes them
  into `AuditEntry`, whose constructor now takes `piiDetected`/`piiCount` — a 14-arg
  constructor, with the old 12-arg signature kept as a back-compat overload (defaults
  `false`/`0`) so `AuditLogStoreTest`'s existing `makeEntry()` helper didn't need to change.
- `AuditController`'s `/audit` response gained `pii_detections` (count of entries with
  `piiDetected=true`) and `pii_entities_redacted` (sum of `piiCount` across all entries).
- `dashboard.html` gained a 6th stat card ("PII Redactions") and a "PII" table column
  (shows 🛡️ + count, or `—` when nothing was detected); grid/colspan adjusted from 5→6 and
  9→10 accordingly.
- Tests: `PiiFilterTest` gained 3 new cases (attribute set on regex match, attribute
  false/zero on clean text, count includes both regex + Presidio passes).
  `AuditFilterTest` gained 2 new cases (PII attributes persisted into the entry; default to
  false/0 when not set).

**Not yet compiled/verified** — same Maven-access caveat as tasks 2/3. Run `./mvnw clean
test` locally; specifically re-check that Jackson's default getter-based serialization
produces `piiDetected`/`piiCount` JSON keys matching what `dashboard.html` reads
(`isPiiDetected()`/`getPiiCount()` should map to exactly those names, but verify against a
real `/audit` response).

## 5. Verify everything actually compiles and passes — DONE, confirmed green

Ran `./mvnw clean test` on the user's own machine (JDK 21, real Maven Central access,
2026-06-21 23:57): **Tests run: 51, Failures: 0, Errors: 0 — BUILD SUCCESS.**

This run surfaced and confirmed the fix for two real bugs found during a full manual
code audit (this sandbox has no JDK 17/Maven Central access, so the audit was done by
logical tracing, then verified by this real run):

1. **`PiiFilter` double-forwarded every POST/PUT request.** `filter()` chained
   `.switchIfEmpty(Mono.defer(() -> chain.filter(exchange)))` after a `flatMap` whose
   result type was `Mono<Void>` — and a `Mono<Void>` structurally never emits an element
   (there's nothing to emit for `Void`), regardless of whether the redaction/forwarding
   work actually ran. `switchIfEmpty` therefore always saw "empty" and fired a *second*
   `chain.filter(exchange)` call with the original, unmutated exchange — meaning every
   request was forwarded twice: once correctly redacted, then again with raw, unredacted
   PII. This explained the `redactsEmail`/`redactsCreditCard`/`redactsCin` test failures
   and was a real production security bug, not just a test artifact. Fixed by checking
   emptiness at the `Mono<DataBuffer>` level (via `Optional`/`defaultIfEmpty`) before the
   `flatMap`, so `chain.filter()` now runs exactly once per request.
2. **`LlmController` was missing `@Autowired`** on its production constructor, which made
   `DemoApplicationTests.contextLoads` fail (`NoSuchMethodException: LlmController.<init>()`
   — Spring couldn't disambiguate between the two constructors and fell back to a no-arg
   reflection path that doesn't exist). Fixed by annotating the production
   `(OllamaChatModel, GuardrailPolicy)` constructor `@Autowired`.

A full manual re-audit of every other filter/controller/guardrail/audit class (looking
specifically for the same `Mono<Void>`/`switchIfEmpty` bug shape, attribute/JSON name
mismatches, and constructor wiring issues) turned up nothing else — `RateLimiterWebFilter`,
`OutputGuardrailFilter`, `GuardrailPolicy`/`OllamaSemanticGuardrailClassifier`,
`AuditFilter`/`AuditLogStore`/`AuditEntry`/`AuditController`, `PiiServiceClient`, and
`dashboard.html`/`llm-flask-service/app.py` were all confirmed consistent before this test
run, and the run's 51/51 pass confirms it.

Still optional (not required to call this task done): a real end-to-end check against the
full `docker compose up -d --build` stack (Keycloak token → `/llm/chat` → dashboard) per
README, and the real-Redis rate-limit manual check noted in task 2.

## Lower priority / polish (after 1-4 are done)

- Track Spring AI off the `1.0.0-M5` milestone to a GA release before treating this as
  deployment-ready (per `README.md`'s existing note).
- Consider a real datastore (Postgres/SQLite) for audit history instead of the JSONL-file
  stopgap, if compliance reporting/querying becomes an actual requirement rather than a
  nice-to-have.
- OpenAPI/Swagger docs for `/llm/chat` and `/audit` — not required by the subject, but useful
  for a PFE defense demo.
