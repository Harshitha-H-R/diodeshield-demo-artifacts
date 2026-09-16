FROM python:3.11-slim
WORKDIR /app

# Install system dependencies for libpcap packet capture
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN pip install --no-cache-dir .[ml]

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["uvicorn", "diodeshield.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
