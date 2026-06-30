package com.example.demo.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Defines a real, proxying Spring Cloud Gateway route — previously
 * spring.cloud.gateway.routes was an empty list (see CLAUDE.md/AUDIT_AND_REFACTOR_PLAN.md
 * "Spring Cloud Gateway: dependency present... no actual gateway routes"), so the project
 * named Spring Cloud Gateway as a targeted technology in the PFE subject without actually
 * using it as a gateway/reverse-proxy anywhere. LlmController's existing /llm/chat
 * endpoint — which calls Ollama via Spring AI's OllamaChatModel, not over HTTP — remains
 * the primary, richer endpoint (token accounting, semantic guardrails, structured
 * 451/200 responses) and is unaffected by this change.
 *
 * This route adds a second, literal proxy path: POST/GET /llm/ollama/** is forwarded
 * (StripPrefix=2) straight to Ollama's own HTTP API (e.g. /llm/ollama/api/generate ->
 * {ollama.base-url}/api/generate) via Spring Cloud Gateway's real RouteLocator/
 * GatewayFilterFactory machinery (NettyRoutingFilter actually proxies the request) —
 * the literal "passerelle qui intercepte... les requêtes... transitant entre les
 * applications internes et les fournisseurs de LLM" the subject describes.
 *
 * Critically, this route is covered by the exact same security/PII/guardrail/audit
 * posture as every other endpoint: AuditFilter, RateLimiterWebFilter, OutputGuardrailFilter
 * and PiiFilter are plain WebFilters (not Spring Cloud Gateway GlobalFilters), so they run
 * against every request on the universal WebFlux filter chain regardless of whether
 * Spring Cloud Gateway's routing matched it — see those classes' Javadoc for why they were
 * deliberately converted away from GlobalFilter in the first place. RateLimiterConfig's
 * pathMatchers("/llm/**").hasRole("llm-user") also already covers this new sub-path with
 * no changes needed there.
 */
@Configuration
public class GatewayRoutesConfig {

    @Bean
    public RouteLocator ollamaProxyRoute(RouteLocatorBuilder builder,
                                          @Value("${ollama.base-url:http://localhost:11434}") String ollamaBaseUrl) {
        return builder.routes()
                .route("ollama-proxy", r -> r
                        .path("/llm/ollama/**")
                        .filters(f -> f.stripPrefix(2))
                        .uri(ollamaBaseUrl))
                .build();
    }
}
