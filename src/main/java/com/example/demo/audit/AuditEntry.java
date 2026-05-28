package com.example.demo.audit;

public class AuditEntry {

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

    public AuditEntry(String timestamp, String user, String method,
                      String path, int statusCode, String latency, String event,
                      int promptTokens, int completionTokens, int totalTokens,
                      double toxicityScore) {
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
    }

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

    @Override
    public String toString() {
        return "[" + timestamp + "] " + user + " " + method + " " + path +
               " -> " + statusCode + " (" + event + ") " + latency +
               " tokens:" + totalTokens + " toxicity:" + toxicityScore;
    }
}
