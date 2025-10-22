FROM python:3.11-slim

LABEL maintainer="Eergygroup <info@eergygroup.com>"
LABEL description="DTE Microservice for Chilean Electronic Invoicing"

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libssl-dev \
        libxml2-dev \
        libxslt1-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        gcc \
        && rm -rf /var/lib/apt/lists/*

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ═══════════════════════════════════════════════════════════
# RABBITMQ - FASE 2: Instalar aio-pika y dependencias
# ═══════════════════════════════════════════════════════════
RUN pip install --no-cache-dir \
    aio-pika==9.3.0 \
    tenacity==8.2.3

# Copiar código
COPY . .

# Exponer puerto (solo red interna Docker)
EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8001/health')"

# Comando de inicio
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]

