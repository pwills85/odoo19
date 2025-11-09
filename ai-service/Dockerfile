FROM python:3.11-slim

LABEL maintainer="Eergygroup <info@eergygroup.com>"
LABEL description="AI Microservice for DTE Intelligence"

WORKDIR /app

# Instalar solo dependencias necesarias (lxml, web scraping)
# OPTIMIZACIÓN: Removidas dependencias OCR y PDF no utilizadas (-200MB)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libxml2-dev \
        libxslt1-dev \
        curl \
        && rm -rf /var/lib/apt/lists/*

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Exponer puerto (solo red interna Docker)
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Comando de inicio
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]

