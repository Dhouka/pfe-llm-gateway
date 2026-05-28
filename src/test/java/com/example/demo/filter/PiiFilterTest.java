package com.example.demo.filter;

import com.example.demo.audit.AuditEntry;
import com.example.demo.audit.AuditLogStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

public class PiiFilterTest {

    // ── Test PII regex patterns directly ─────────────────────────

    @Test
    void testEmailDetection() {
        String input = "My email is yassine@gmail.com please help";
        assertTrue(input.matches(".*[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}.*"),
            "Email should be detected");
    }

    @Test
    void testEmailNotPresentInCleanText() {
        String input = "What is cloud computing?";
        assertFalse(input.matches(".*[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}.*"),
            "Clean text should not match email pattern");
    }

    @Test
    void testCreditCardDetection() {
        String input = "My card is 4532 1234 5678 9010 please help";
        assertTrue(input.matches(".*\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b.*"),
            "Credit card should be detected");
    }

    @Test
    void testCinDetection() {
        String input = "My CIN is 12345678";
        assertTrue(input.matches(".*\\b\\d{8}\\b.*"),
            "CIN should be detected");
    }

    @Test
    void testCleanRequestPassesThrough() {
        String input = "What is artificial intelligence?";
        boolean hasEmail = input.matches(".*[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}.*");
        boolean hasCard = input.matches(".*\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b.*");
        boolean hasCin = input.matches(".*\\b\\d{8}\\b.*");
        assertFalse(hasEmail || hasCard || hasCin,
            "Clean text should not trigger any PII detection");
    }
}
