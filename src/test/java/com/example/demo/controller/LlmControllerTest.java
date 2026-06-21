package com.example.demo.controller;

import com.example.demo.filter.AuditFilter;
import com.example.demo.guardrail.GuardrailPolicy;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Exercises the real LlmController.
 *
 * LlmController used to always return HTTP 200 (a bare Map) even when its own keyword
 * checks logically "blocked" the model's response, and it wrote directly to
 * AuditLogStore — duplicating AuditFilter's logging and making status-code-based audit
 * classification wrong. It now returns a proper ResponseEntity and sets exchange
 * attributes for AuditFilter to read (see AuditFilter.ATTR_*); these tests assert both
 * the HTTP status and the attributes, since either regressing silently would break the
 * audit trail without any visible test failure otherwise.
 *
 * The constructor takes OllamaChatModel and builds its own ChatClient internally, so we
 * build a real LlmController via the production constructor with a mock OllamaChatModel,
 * then use reflection to swap in a fully mocked ChatClient — this avoids depending on
 * Ollama actually being reachable while still exercising the controller's real logic.
 */
class LlmControllerTest {

    private LlmController controllerWithMockedResponse(String modelOutputText) throws Exception {
        ChatClient chatClient = mock(ChatClient.class);
        ChatClient.ChatClientRequestSpec requestSpec = mock(ChatClient.ChatClientRequestSpec.class);
        ChatClient.CallResponseSpec callResponseSpec = mock(ChatClient.CallResponseSpec.class);

        when(chatClient.prompt()).thenReturn(requestSpec);
        when(requestSpec.user(anyString())).thenReturn(requestSpec);
        when(requestSpec.call()).thenReturn(callResponseSpec);

        AssistantMessage assistantMessage = new AssistantMessage(modelOutputText);
        Generation generation = new Generation(assistantMessage);
        ChatResponse chatResponse = new ChatResponse(List.of(generation));
        when(callResponseSpec.chatResponse()).thenReturn(chatResponse);

        // LlmController's primary constructor builds its own ChatClient from the
        // OllamaChatModel, which would require a real/mocked Ollama call chain. The
        // package-private constructor below accepts a ChatClient directly so tests can
        // inject a fully mocked one without touching Ollama at all.
        return new LlmController(chatClient, new GuardrailPolicy());
    }

    @Test
    void allowedResponseReturns200AndSetsAllowedEvent() throws Exception {
        LlmController controller = controllerWithMockedResponse("Cloud computing is a great technology");
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/llm/chat").build());

        ResponseEntity<Map<String, Object>> result =
                controller.chat(Map.of("message", "What is cloud computing?"), exchange);

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals("ALLOWED", exchange.getAttribute(AuditFilter.ATTR_EVENT));
    }

    @Test
    void toxicResponseReturns451AndSetsBlockedToxicEvent() throws Exception {
        LlmController controller = controllerWithMockedResponse("You are such an idiot for asking this");
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/llm/chat").build());

        ResponseEntity<Map<String, Object>> result =
                controller.chat(Map.of("message", "hello"), exchange);

        assertEquals(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS, result.getStatusCode());
        assertEquals("BLOCKED_TOXIC", exchange.getAttribute(AuditFilter.ATTR_EVENT));
        assertTrue(result.getBody().containsKey("error"));
    }

    @Test
    void maliciousCodeResponseIncludesBlockedPattern() throws Exception {
        LlmController controller = controllerWithMockedResponse(
                "Here is how: <script>eval(base64.decode('x'))</script>");
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/llm/chat").build());

        ResponseEntity<Map<String, Object>> result =
                controller.chat(Map.of("message", "hello"), exchange);

        assertEquals(HttpStatus.UNAVAILABLE_FOR_LEGAL_REASONS, result.getStatusCode());
        assertEquals("BLOCKED_MALICIOUS_CODE", exchange.getAttribute(AuditFilter.ATTR_EVENT));
        assertTrue(result.getBody().containsKey("blocked_pattern"));
    }

    @Test
    void tokenAttributesAreSetOnExchange() throws Exception {
        LlmController controller = controllerWithMockedResponse("A clean response with several words in it");
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/llm/chat").build());

        controller.chat(Map.of("message", "hello there"), exchange);

        assertNotNull(exchange.getAttribute(AuditFilter.ATTR_TOTAL_TOKENS));
        assertNotNull(exchange.getAttribute(AuditFilter.ATTR_TOXICITY_SCORE));
    }
}
