# LLM Secure Gateway - PFE Satoripop

Built with Spring Cloud Gateway + Spring AI to protect banking LLM deployments.

## Technologies
- Spring Cloud Gateway 4.1
- Spring AI 1.0.0-M5 + Ollama (TinyLlama)
- Keycloak 24 JWT Authentication
- Redis Rate Limiting
- PII Detection with regex
- Output Guardrails (toxic, financial, injection)
- Live Audit Dashboard

## Quick Start
1. docker compose up -d
2. ollama pull tinyllama
3. java -jar target/gateway-0.0.1-SNAPSHOT.jar
4. cd llm-flask-service && python3 app.py
5. Open http://127.0.0.1:5000/dashboard

## Author
Yassine Kooli - PFE Satoripop 2026
