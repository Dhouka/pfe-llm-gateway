FROM python:3.11-slim

# Found 2026-06-30: without this, `docker logs gateway-pii-service` showed nothing at all
# for 5+ minutes while the container was actively loading (251% CPU) spaCy models — Python
# block-buffers stdout/stderr by default when it isn't attached to a TTY (always true under
# Docker), so nothing gets flushed until the buffer fills or the process exits. That made a
# slow-but-healthy startup look indistinguishable from a silent hang. Unbuffered output costs
# nothing at this service's request volume and makes `docker logs -f` actually useful for
# diagnosing startup timing in the future.
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -m spacy download en_core_web_lg && \
    python -m spacy download fr_core_news_lg

COPY app.py .

ENV PII_SERVICE_PORT=5001
EXPOSE 5001

CMD ["python3", "app.py"]
