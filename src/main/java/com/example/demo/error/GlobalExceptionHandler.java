package com.example.demo.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.ResourceAccessException;

import java.net.ConnectException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;

/**
 * Consistent JSON error shape for the gateway, instead of letting exceptions surface
 * as raw 500s with a stack trace body (AUDIT_AND_REFACTOR_PLAN.md issue #15).
 *
 * LlmController previously had no handling at all for Ollama being down/slow/unreachable
 * beyond a narrow try/catch around token-usage parsing — a connection failure or timeout
 * talking to Ollama propagated as an unhandled exception. This advice catches the
 * realistic failure modes (connection refused, timeout, and a catch-all) and returns a
 * stable {"error": "..."} body with an appropriate status instead.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler({ResourceAccessException.class, ConnectException.class})
    public ResponseEntity<Map<String, Object>> handleConnectionFailure(Exception ex) {
        log.error("Upstream connection failure (likely Ollama is down/unreachable): {}", ex.toString());
        return ResponseEntity
                .status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(errorBody("The LLM backend is currently unreachable. Please try again shortly."));
    }

    @ExceptionHandler(TimeoutException.class)
    public ResponseEntity<Map<String, Object>> handleTimeout(TimeoutException ex) {
        log.error("Upstream call timed out: {}", ex.toString());
        return ResponseEntity
                .status(HttpStatus.GATEWAY_TIMEOUT)
                .body(errorBody("The LLM backend took too long to respond."));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadInput(IllegalArgumentException ex) {
        log.warn("Bad request: {}", ex.toString());
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorBody("Invalid request: " + ex.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleUnexpected(Exception ex) {
        log.error("Unhandled exception reached GlobalExceptionHandler", ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorBody("An unexpected error occurred."));
    }

    private Map<String, Object> errorBody(String message) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", message);
        return body;
    }
}
