package com.example.demo.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Security policy for the gateway.
 *
 * Previously: /audit was permitAll (leaking every prompt's latency/tokens/toxicity/event
 * to any anonymous caller — issue #3 in AUDIT_AND_REFACTOR_PLAN.md), /llm/** only checked
 * authenticated() (any valid Keycloak token, regardless of role, could call the LLM), and
 * the JWK set URI was hardcoded to localhost in this class in addition to being configured
 * separately via application.yml's issuer-uri property. Now: /audit requires the
 * "audit-viewer" realm role, /llm/** requires the "llm-user" realm role, and the JWK
 * verification relies on Spring Boot's auto-configured ReactiveJwtDecoder (built from
 * spring.security.oauth2.resourceserver.jwt.issuer-uri in application.yml) instead of a
 * second, separately-hardcoded jwkSetUri here.
 *
 * The Keycloak realm "llm-gateway" must define "llm-user" and "audit-viewer" realm roles
 * and assign them to the relevant client/users — see README for setup steps.
 *
 * Fixed 2026-06-24 (audit finding): the "/audit" pathMatcher only matched that exact
 * literal path, NOT "/audit/summary" or "/audit/detail/{id}" (both defined in
 * AuditController) — those two sub-routes fell through to the anyExchange() catch-all
 * below and were reachable by anyone, with no token at all, bypassing the audit-viewer
 * role entirely. Changed to "/audit/**". The catch-all itself was also changed from
 * permitAll() to denyAll() (deny-by-default, more defensible for a banking-style
 * deployment) with the root health-check route ("/", TestController) explicitly
 * permitted instead of relying on the wildcard.
 */
@Configuration
public class RateLimiterConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> exchange.getPrincipal()
            .map(p -> p.getName())
            .defaultIfEmpty(
                exchange.getRequest()
                    .getRemoteAddress()
                    .getAddress()
                    .getHostAddress()
            );
    }

    @Bean
    public RedisRateLimiter redisRateLimiter() {
        return new RedisRateLimiter(2, 3, 1);
    }

    /**
     * Maps Keycloak's realm_access.roles claim (not handled by Spring Security's default
     * JwtGrantedAuthoritiesConverter, which only looks at "scope"/"scp") into
     * ROLE_-prefixed GrantedAuthoritys, in addition to the default scope-based authorities.
     *
     * ReactiveJwtAuthenticationConverterAdapter wraps the (blocking) JwtAuthenticationConverter
     * and itself implements Converter<Jwt, Mono<AbstractAuthenticationToken>> — the exact
     * type JwtSpec.jwtAuthenticationConverter(...) expects in a reactive (WebFlux) app.
     */
    @Bean
    public ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();

        Converter<Jwt, Collection<GrantedAuthority>> realmRolesConverter = jwt -> {
            Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess == null || !(realmAccess.get("roles") instanceof List<?> roles)) {
                return List.of();
            }
            return roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
        };

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt ->
            Stream.concat(
                scopeConverter.convert(jwt).stream(),
                realmRolesConverter.convert(jwt).stream()
            ).collect(Collectors.toList())
        );
        return new ReactiveJwtAuthenticationConverterAdapter(converter);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            ReactiveJwtAuthenticationConverterAdapter jwtAuthenticationConverter) {
        return http
            .csrf(csrf -> csrf.disable())
            .authorizeExchange(auth -> auth
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/").permitAll()
                .pathMatchers("/audit/**").hasRole("audit-viewer")
                .pathMatchers("/llm/**").hasRole("llm-user")
                .anyExchange().denyAll()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter))
            )
            .build();
    }
}
