package com.example.demo.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.ResourceAccessException;

import java.net.ConnectException;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Exercises the real GlobalExceptionHandler directly (no Spring context needed — it's
 * plain methods), confirming each exception type maps to the intended status code and
 * that the response body always has the stable {"error": "..."} shape rather than a
 * raw stack trace.
 */
class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void connectionFailureMapsTo503() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleConnectionFailure(new ResourceAccessException("connection refused"));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
        assertTrue(response.getBody().containsKey("error"));
    }

    @Test
    void connectExceptionMapsTo503() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleConnectionFailure(new ConnectException("refused"));

        assertEquals(HttpStatus.SERVICE_UNAVAILABLE, response.getStatusCode());
    }

    @Test
    void timeoutMapsTo504() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleTimeout(new TimeoutException("too slow"));

        assertEquals(HttpStatus.GATEWAY_TIMEOUT, response.getStatusCode());
        assertTrue(response.getBody().containsKey("error"));
    }

    @Test
    void illegalArgumentMapsTo400AndIncludesMessage() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleBadInput(new IllegalArgumentException("message is required"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertTrue(response.getBody().get("error").toString().contains("message is required"));
    }

    @Test
    void unexpectedExceptionMapsTo500WithoutLeakingDetails() {
        ResponseEntity<Map<String, Object>> response =
                handler.handleUnexpected(new RuntimeException("some internal detail with a stack trace"));

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals("An unexpected error occurred.", response.getBody().get("error"));
    }
}
