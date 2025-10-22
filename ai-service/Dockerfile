FROM python:3.11-slim

LABEL maintainer="Eergygroup <info@eergygroup.com>"
LABEL description="AI Microservice for DTE Intelligence"

WORKDIR /app

# Instalar dependencias del sistema para OCR y PDF
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tesseract-ocr \
        tesseract-ocr-spa \
        poppler-utils \
        gcc \
        && rm -rf /var/lib/apt/lists/*

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar código
COPY . .

# Crear directorios de datos
RUN mkdir -p /app/data/chromadb /app/cache /app/uploads

# Exponer puerto (solo red interna Docker)
EXPOSE 8002

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8002/health')"

# Comando de inicio
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]

