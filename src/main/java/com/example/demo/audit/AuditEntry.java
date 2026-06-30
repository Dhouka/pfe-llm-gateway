package com.example.demo.audit;

public class AuditEntry {

    private String correlationId;
    private String timestamp;
    private String user;
    private String method;
    private String path;
    private int statusCode;
    private String latency;
    private String event;
    private int promptTokens;
    private int completionTokens;
    private int totalTokens;
    private double toxicityScore;
    private boolean piiDetected;
    private int piiCount;
    private String matchedCategory;
    private String matchedPattern;

    public AuditEntry(String correlationId, String timestamp, String user, String method,
                      String path, int statusCode, String latency, String event,
                      int promptTokens, int completionTokens, int totalTokens,
                      double toxicityScore, boolean piiDetected, int piiCount,
                      String matchedCategory, String matchedPattern) {
        this.correlationId = correlationId;
        this.timestamp = timestamp;
        this.user = user;
        this.method = method;
        this.path = path;
        this.statusCode = statusCode;
        this.latency = latency;
        this.event = event;
        this.promptTokens = promptTokens;
        this.completionTokens = completionTokens;
        this.totalTokens = totalTokens;
        this.toxicityScore = toxicityScore;
        this.piiDetected = piiDetected;
        this.piiCount = piiCount;
        this.matchedCategory = matchedCategory;
        this.matchedPattern = matchedPattern;
    }

    /** Back-compat overload for callers not yet passing the new fields. */
    public AuditEntry(String correlationId, String timestamp, String user, String method,
                      String path, int statusCode, String latency, String event,
                      int promptTokens, int completionTokens, int totalTokens,
                      double toxicityScore, boolean piiDetected, int piiCount) {
        this(correlationId, timestamp, user, method, path, statusCode, latency, event,
                promptTokens, completionTokens, totalTokens, toxicityScore,
                piiDetected, piiCount, null, null);
    }

    /** Back-compat overload for callers not yet passing PII or guardrail fields. */
    public AuditEntry(String correlationId, String timestamp, String user, String method,
                      String path, int statusCode, String latency, String event,
                      int promptTokens, int completionTokens, int totalTokens,
                      double toxicityScore) {
        this(correlationId, timestamp, user, method, path, statusCode, latency, event,
                promptTokens, completionTokens, totalTokens, toxicityScore, false, 0,
                null, null);
    }

    public String getCorrelationId() { return correlationId; }
    public String getTimestamp() { return timestamp; }
    public String getUser() { return user; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public int getStatusCode() { return statusCode; }
    public String getLatency() { return latency; }
    public String getEvent() { return event; }
    public int getPromptTokens() { return promptTokens; }
    public int getCompletionTokens() { return completionTokens; }
    public int getTotalTokens() { return totalTokens; }
    public double getToxicityScore() { return toxicityScore; }
    public boolean isPiiDetected() { return piiDetected; }
    public int getPiiCount() { return piiCount; }
    public String getMatchedCategory() { return matchedCategory; }
    public String getMatchedPattern() { return matchedPattern; }

    @Override
    public String toString() {
        return "[" + timestamp + "] (" + correlationId + ") " + user + " " + method + " " + path +
               " -> " + statusCode + " (" + event + ") " + latency +
               " tokens:" + totalTokens + " toxicity:" + toxicityScore +
               " pii:" + piiDetected + "(" + piiCount + ")" +
               (matchedCategory != null ? " match:" + matchedCategory + "/" + matchedPattern : "");
    }
}
