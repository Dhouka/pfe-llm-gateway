FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV PII_SERVICE_PORT=5001
EXPOSE 5001

CMD ["python3", "app.py"]
