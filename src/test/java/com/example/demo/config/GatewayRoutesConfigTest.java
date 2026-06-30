package com.example.demo.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.route.RouteLocator;
import reactor.core.publisher.Flux;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the real ollamaProxyRoute bean is registered and resolvable — confirms
 * spring.cloud.gateway.routes is no longer an empty no-op (see GatewayRoutesConfig's class
 * Javadoc for the PFE-subject gap this closes) and that the route is configured with the
 * expected id/URI.
 *
 * An earlier version of this test tried to build the RouteLocator in isolation, first via a
 * (wrong-typed) WebClient.Builder, then via a bare/manually-refreshed GenericApplicationContext.
 * Both failed: the route DSL's .path(...) predicate looks up a PathRoutePredicateFactory bean
 * via the context at build time, and that bean only exists once Spring Cloud Gateway's real
 * auto-configuration has run — a hand-built context doesn't have it
 * (NoSuchBeanDefinitionException). Booting the actual Spring Boot application context (same
 * approach as DemoApplicationTests, which already does this successfully) sidesteps that
 * entirely and is a more faithful test of what actually runs in production anyway.
 *
 * GatewayAutoConfiguration registers more than one RouteLocator bean (e.g. the
 * route-definition-backed locator plus this app's ollamaProxyRoute), so routes are gathered
 * from all of them rather than relying on a single ambiguous @Autowired RouteLocator.
 */
@SpringBootTest
class GatewayRoutesConfigTest {

    @Autowired
    private List<RouteLocator> routeLocators;

    @Test
    void definesARealOllamaProxyRoute() {
        Route route = Flux.fromIterable(routeLocators)
                .flatMap(RouteLocator::getRoutes)
                .filter(r -> "ollama-proxy".equals(r.getId()))
                .blockFirst();

        assertNotNull(route, "expected the ollama-proxy route to be registered");
        assertEquals("http://localhost:11434", route.getUri().toString());
    }
}
