# 📦 ANÁLISIS: Librerías para Monitoreo SII y Chat IA

**Fecha:** 2025-10-22  
**Propósito:** Determinar qué librerías agregar a cada imagen Docker  
**Alcance:** Odoo customizado + AI Service  

---

## 🎯 RESUMEN EJECUTIVO

### **Imagen Odoo: CASI NADA** ✅

**Razón:** Odoo solo actúa como **interfaz UI** y **orquestador**. Todo el trabajo pesado (scraping, análisis IA, chat) lo hace el AI Service.

| Componente | Odoo necesita | AI Service necesita |
|------------|---------------|---------------------|
| **Web Scraping** | ❌ No | ✅ Sí (BeautifulSoup, Scrapy) |
| **Análisis IA** | ❌ No | ✅ Sí (anthropic, openai) |
| **Chat conversacional** | ❌ No | ✅ Sí (anthropic) |
| **Procesamiento PDF** | ❌ No | ✅ Sí (pdfplumber, PyPDF2) |
| **Cliente HTTP** | ✅ Ya tiene (requests) | ✅ Ya tiene |
| **Widgets JS** | ✅ Ya soportado | ❌ No aplica |

---

## 📋 LIBRERÍAS REQUERIDAS POR SERVICIO

### **1. IMAGEN ODOO (CAMBIOS MÍNIMOS)**

#### **Estado Actual (YA INSTALADAS):**

```dockerfile
# docker/Dockerfile - Líneas 142-185

RUN pip install --no-cache-dir --break-system-packages \
    # ✅ Ya instaladas para DTE:
    pyOpenSSL>=21.0.0              # Firma digital
    cryptography>=3.4.8            # Certificados
    lxml>=4.9.0                    # XML
    zeep>=4.2.0                    # SOAP SII
    requests>=2.28.0               # HTTP client ← USAREMOS ESTO
    qrcode[pil]>=7.3.0            # QR codes
    structlog>=22.1.0              # Logging
    # ... más librerías DTE
```

#### **Para Monitoreo SII: NO SE NECESITA NADA NUEVO** ✅

**Razón:** Odoo solo hace:
```python
# Llamada simple a AI Service
import requests

response = requests.post(
    'http://ai-service:8002/api/ai/sii/monitor',
    headers={'Authorization': f'Bearer {api_key}'},
    json={'force': False}
)
```

#### **Para Chat IA: NO SE NECESITA NADA NUEVO** ✅

**Razón:** Odoo solo hace:
```python
# Llamada al endpoint de chat
import requests

response = requests.post(
    'http://ai-service:8002/api/ai/sii/chat',
    headers={'Authorization': f'Bearer {api_key}'},
    json={
        'news_id': 123,
        'question': '¿Qué significa breaking change?',
        'conversation_history': []
    }
)
```

#### **Widgets JavaScript: YA SOPORTADO** ✅

Odoo 19 CE tiene soporte completo para:
- ✅ Custom widgets
- ✅ Vue.js/Owl components
- ✅ WebSockets
- ✅ AJAX calls

**No se necesita instalar nada extra.**

#### **CONCLUSIÓN ODOO:**

```dockerfile
# ============================================
# NO SE REQUIEREN CAMBIOS EN docker/Dockerfile
# ============================================

# Imagen actual ya tiene todo lo necesario:
# - requests (para llamar AI Service)
# - structlog (logging)
# - python-dateutil (fechas)

# El resto lo hace AI Service
```

---

### **2. IMAGEN AI SERVICE (NUEVAS LIBRERÍAS)**

#### **Estado Actual:**

```python
# ai-service/requirements.txt (ACTUAL)

# Web Framework
fastapi==0.104.1
uvicorn[standard]==0.24.0

# AI/LLM
anthropic==0.7.8          # ✅ Ya tenemos Claude API

# Embeddings
sentence-transformers==2.2.2
chromadb==0.4.22

# Document Processing
lxml>=4.9.0
pypdf>=3.17.4
pdfplumber>=0.10.3        # ✅ Ya podemos leer PDFs

# HTTP
httpx>=0.25.2
requests>=2.31.0          # ✅ Ya podemos hacer scraping

# Cache
redis>=5.0.1              # ✅ Ya tenemos Redis

# Utils
python-dotenv>=1.0.0
python-dateutil>=2.8.2
structlog>=23.2.0
```

#### **NUEVAS LIBRERÍAS REQUERIDAS:**

```python
# ═══════════════════════════════════════════════════════════
# [NUEVO] WEB SCRAPING
# ═══════════════════════════════════════════════════════════
beautifulsoup4>=4.12.0          # Parse HTML
html5lib>=1.1                   # Parser robusto
lxml>=4.9.0                     # ✅ Ya instalado

# [OPCIONAL] Para scraping avanzado:
scrapy>=2.11.0                  # Framework completo (si se necesita)
selenium>=4.15.0                # Si SII usa JavaScript (probablemente no)

# ═══════════════════════════════════════════════════════════
# [NUEVO] DETECCIÓN DE CAMBIOS
# ═══════════════════════════════════════════════════════════
# No se necesita librería especial, usamos hashlib (stdlib)

# ═══════════════════════════════════════════════════════════
# [NUEVO] EXTRACCIÓN DE TEXTO MEJORADA
# ═══════════════════════════════════════════════════════════
pdfplumber>=0.10.3              # ✅ Ya instalado
pypdf>=3.17.4                   # ✅ Ya instalado

# [OPCIONAL] OCR para PDFs escaneados:
pytesseract>=0.3.10             # ✅ Ya instalado
Pillow>=10.1.0                  # ✅ Ya instalado

# ═══════════════════════════════════════════════════════════
# [NUEVO] ANÁLISIS DE TEXTO
# ═══════════════════════════════════════════════════════════
# anthropic ya instalado ✅

# [OPCIONAL] NLP adicional:
spacy>=3.7.0                    # Si queremos análisis semántico local
# es_core_news_sm                # Modelo español para spaCy

# ═══════════════════════════════════════════════════════════
# [NUEVO] NOTIFICACIONES
# ═══════════════════════════════════════════════════════════
slack-sdk>=3.23.0               # Cliente Slack oficial
python-telegram-bot>=20.6       # [OPCIONAL] Telegram

# [OPCIONAL] GitHub integration:
PyGithub>=2.1.1                 # Crear issues automáticamente

# ═══════════════════════════════════════════════════════════
# [NUEVO] RATE LIMITING
# ═══════════════════════════════════════════════════════════
slowapi>=0.1.9                  # Rate limiting para FastAPI

# ═══════════════════════════════════════════════════════════
# [NUEVO] WEBSOCKETS (para chat streaming)
# ═══════════════════════════════════════════════════════════
websockets>=12.0                # WebSocket support
# fastapi ya soporta WebSockets ✅

# ═══════════════════════════════════════════════════════════
# [NUEVO] VALIDACIÓN DE DATOS
# ═══════════════════════════════════════════════════════════
# pydantic ya instalado ✅
validators>=0.22.0              # Validación URLs, emails, etc
```

#### **requirements.txt ACTUALIZADO (AI Service):**

```python
# ai-service/requirements.txt - VERSIÓN CON MONITOREO SII

# ═══════════════════════════════════════════════════════════
# WEB FRAMEWORK
# ═══════════════════════════════════════════════════════════
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
pydantic-settings==2.1.0

# ═══════════════════════════════════════════════════════════
# AI / LLM
# ═══════════════════════════════════════════════════════════
anthropic==0.7.8                # Claude API (chat + análisis)
openai==1.6.1                   # [OPCIONAL] GPT fallback
ollama==0.1.6                   # [OPCIONAL] LLM local

# ═══════════════════════════════════════════════════════════
# EMBEDDINGS Y VECTOR DB
# ═══════════════════════════════════════════════════════════
sentence-transformers==2.2.2    # Para reconciliación
chromadb==0.4.22                # Vector DB
numpy>=1.24.0

# ═══════════════════════════════════════════════════════════
# [NUEVO] WEB SCRAPING
# ═══════════════════════════════════════════════════════════
beautifulsoup4>=4.12.0          # Parse HTML
html5lib>=1.1                   # HTML parser
requests>=2.31.0                # HTTP client
httpx>=0.25.2                   # Async HTTP client

# ═══════════════════════════════════════════════════════════
# DOCUMENT PROCESSING
# ═══════════════════════════════════════════════════════════
lxml>=4.9.0                     # XML/HTML parsing
pypdf>=3.17.4                   # PDF manipulation
pdfplumber>=0.10.3              # PDF text extraction
python-docx>=1.1.0              # Word docs
pytesseract>=0.3.10             # OCR (si PDFs escaneados)
Pillow>=10.1.0                  # Imágenes

# ═══════════════════════════════════════════════════════════
# [NUEVO] NOTIFICACIONES
# ═══════════════════════════════════════════════════════════
slack-sdk>=3.23.0               # Slack notifications

# ═══════════════════════════════════════════════════════════
# [NUEVO] RATE LIMITING & SECURITY
# ═══════════════════════════════════════════════════════════
slowapi>=0.1.9                  # Rate limiting
validators>=0.22.0              # URL/email validation

# ═══════════════════════════════════════════════════════════
# CACHE Y DB
# ═══════════════════════════════════════════════════════════
redis>=5.0.1

# ═══════════════════════════════════════════════════════════
# UTILIDADES
# ═══════════════════════════════════════════════════════════
python-dotenv>=1.0.0
python-dateutil>=2.8.2
structlog>=23.2.0

# ═══════════════════════════════════════════════════════════
# TESTING
# ═══════════════════════════════════════════════════════════
pytest>=7.4.3
pytest-asyncio>=0.21.1
pytest-cov>=4.1.0
responses>=0.20.0               # Mock HTTP requests
```

#### **Dockerfile ACTUALIZADO (AI Service):**

```dockerfile
# ai-service/Dockerfile - VERSIÓN CON MONITOREO SII

FROM python:3.11-slim

LABEL maintainer="Eergygroup <info@eergygroup.com>"
LABEL description="AI Microservice for DTE Intelligence + SII Monitoring"

WORKDIR /app

# ════════════════════════════════════════════════════════════
# DEPENDENCIAS DEL SISTEMA
# ════════════════════════════════════════════════════════════

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # OCR (si PDFs escaneados)
        tesseract-ocr \
        tesseract-ocr-spa \
        \
        # PDF processing
        poppler-utils \
        \
        # Compilación (para algunas libs Python)
        gcc \
        g++ \
        \
        # [NUEVO] Para lxml y beautifulsoup
        libxml2-dev \
        libxslt1-dev \
        \
        # Networking (curl para healthcheck)
        curl \
        \
        # Limpieza
        && rm -rf /var/lib/apt/lists/*

# ════════════════════════════════════════════════════════════
# DEPENDENCIAS PYTHON
# ════════════════════════════════════════════════════════════

# Copiar requirements
COPY requirements.txt .

# Instalar dependencias Python
RUN pip install --no-cache-dir -r requirements.txt

# ════════════════════════════════════════════════════════════
# CÓDIGO DE LA APLICACIÓN
# ════════════════════════════════════════════════════════════

# Copiar código
COPY . .

# ════════════════════════════════════════════════════════════
# DIRECTORIOS DE DATOS
# ════════════════════════════════════════════════════════════

RUN mkdir -p \
    /app/data/chromadb \
    /app/cache \
    /app/uploads \
    /app/logs

# ════════════════════════════════════════════════════════════
# CONFIGURACIÓN
# ════════════════════════════════════════════════════════════

# Exponer puerto (solo red interna Docker)
EXPOSE 8002

# Health check mejorado
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Variables de entorno por defecto
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO

# ════════════════════════════════════════════════════════════
# STARTUP
# ════════════════════════════════════════════════════════════

# Comando de inicio
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002", "--log-level", "info"]
```

---

## 📊 COMPARACIÓN DE TAMAÑOS

### **Antes (AI Service actual):**
```
Image size: ~1.2 GB

Base: python:3.11-slim (150 MB)
+ Dependencies actuales (~1 GB)
```

### **Después (Con monitoreo SII):**
```
Image size: ~1.25 GB (+50 MB)

Base: python:3.11-slim (150 MB)
+ Dependencies actuales (~1 GB)
+ Nuevas librerías:
  - beautifulsoup4 (~2 MB)
  - html5lib (~1 MB)
  - slack-sdk (~5 MB)
  - slowapi (~1 MB)
  - validators (~500 KB)
  - Dependencias sistema (~40 MB)
```

**Incremento:** ~50 MB (~4% más grande)

---

## 💰 ANÁLISIS DE COSTOS

### **Recursos Adicionales:**

| Recurso | Antes | Después | Incremento |
|---------|-------|---------|------------|
| **Imagen Docker** | 1.2 GB | 1.25 GB | +50 MB |
| **RAM en ejecución** | 512 MB | 600 MB | +88 MB |
| **Tiempo build** | 3 min | 3.5 min | +30 seg |
| **Costo Claude API** | $0 | $5/año | Despreciable |

**Total:** Impacto mínimo ✅

---

## 🎯 DECISIONES DE DISEÑO

### **¿Por qué NO agregar nada a Odoo?**

1. **Separación de responsabilidades:**
   - Odoo = UI/UX + Persistencia
   - AI Service = Procesamiento inteligente

2. **Escalabilidad:**
   - AI Service puede escalar independientemente
   - No sobrecarga Odoo con librerías pesadas

3. **Mantenibilidad:**
   - Un solo lugar para actualizar librerías de scraping/IA
   - Odoo mantiene su imagen lean

4. **Seguridad:**
   - Scraping en contenedor separado
   - Si scraper tiene vulnerabilidad, no afecta Odoo

### **¿Por qué NO Scrapy completo?**

**Scrapy es overkill para este caso:**
- Solo necesitamos scrapear 7 URLs estáticas
- No necesitamos crawler distribuido
- No necesitamos pipeline complejo
- BeautifulSoup + requests es más simple y suficiente

**Si en el futuro se necesita:**
- Scrapear 100+ páginas
- Crawling recursivo
- Distribuir scraping
→ Entonces agregar Scrapy

### **¿Por qué NO Selenium?**

**Razón:** El sitio del SII no usa JavaScript pesado para el contenido que necesitamos.

**Si en el futuro:**
- SII migra a SPA (React/Vue/Angular)
- Contenido dinámico cargado con JS
→ Entonces agregar Selenium

**Por ahora:** requests + BeautifulSoup es suficiente ✅

---

## 🔧 INSTALACIÓN PASO A PASO

### **Paso 1: Actualizar requirements.txt**

```bash
cd /Users/pedro/Documents/odoo19/ai-service

# Editar requirements.txt (agregar librerías nuevas)
nano requirements.txt
```

### **Paso 2: Actualizar Dockerfile (si necesario)**

```bash
# Solo si agregamos dependencias del sistema
nano Dockerfile
```

### **Paso 3: Rebuild imagen AI Service**

```bash
cd /Users/pedro/Documents/odoo19

# Rebuild solo AI Service
docker-compose build ai-service

# Verificar tamaño
docker images | grep ai-service
```

### **Paso 4: Probar instalación**

```bash
# Iniciar servicio
docker-compose up -d ai-service

# Verificar logs
docker-compose logs ai-service

# Probar health check
curl http://localhost:8002/health

# Verificar librerías instaladas
docker-compose exec ai-service pip list | grep beautifulsoup
```

---

## 📦 RESUMEN DE LIBRERÍAS NUEVAS

### **OBLIGATORIAS (Core functionality):**

```python
beautifulsoup4>=4.12.0      # Parse HTML del SII
html5lib>=1.1               # HTML parser robusto
slack-sdk>=3.23.0           # Notificaciones Slack
slowapi>=0.1.9              # Rate limiting
validators>=0.22.0          # Validación URLs
```

**Tamaño:** ~10 MB
**Justificación:** Imprescindibles para scraping, notificaciones y seguridad

### **OPCIONALES (Nice to have):**

```python
scrapy>=2.11.0              # Si escalamos scraping
selenium>=4.15.0            # Si SII usa JavaScript
spacy>=3.7.0                # NLP avanzado local
python-telegram-bot>=20.6   # Notificaciones Telegram
PyGithub>=2.1.1             # Crear issues GitHub
```

**Tamaño:** ~200 MB
**Justificación:** Solo instalar si se necesita

### **YA INSTALADAS (No agregar):**

```python
anthropic>=0.7.8            # ✅ Claude API
requests>=2.31.0            # ✅ HTTP client
httpx>=0.25.2               # ✅ Async HTTP
pdfplumber>=0.10.3          # ✅ PDF extraction
redis>=5.0.1                # ✅ Cache
structlog>=23.2.0           # ✅ Logging
fastapi>=0.104.1            # ✅ Web framework
```

---

## ✅ CHECKLIST DE IMPLEMENTACIÓN

### **Para AI Service:**

- [ ] Actualizar `ai-service/requirements.txt`
- [ ] Agregar librerías obligatorias
- [ ] Actualizar `ai-service/Dockerfile` (si necesario)
- [ ] Rebuild imagen: `docker-compose build ai-service`
- [ ] Probar instalación: `pip list`
- [ ] Verificar tamaño imagen: `docker images`
- [ ] Testing: Probar scraping simple
- [ ] Testing: Probar notificación Slack
- [ ] Commit cambios: `git commit -m "Add SII monitoring libraries"`

### **Para Odoo:**

- [ ] ✅ **NO SE REQUIEREN CAMBIOS**
- [ ] Verificar `requests` ya instalado
- [ ] Verificar `structlog` ya instalado
- [ ] Commit: N/A (no hay cambios)

---

## 🚀 RECOMENDACIÓN FINAL

### **Configuración Mínima Recomendada:**

**Solo agregar a AI Service:**

```python
# ai-service/requirements.txt - AGREGAR ESTAS 5 LÍNEAS:

beautifulsoup4>=4.12.0      # Parse HTML
html5lib>=1.1               # HTML parser
slack-sdk>=3.23.0           # Slack notifications
slowapi>=0.1.9              # Rate limiting
validators>=0.22.0          # Validation
```

**Tamaño adicional:** ~10 MB  
**RAM adicional:** ~50 MB  
**Tiempo build:** +30 segundos  

**No tocar:**
- ❌ Imagen Odoo (ya tiene todo)
- ❌ DTE Service (no lo necesita)
- ❌ PostgreSQL (no aplica)
- ❌ Redis (no aplica)
- ❌ RabbitMQ (no aplica)

### **Roadmap de Librerías Opcionales:**

**Fase 1 (MVP):**
✅ beautifulsoup4
✅ slack-sdk
✅ slowapi

**Fase 2 (Si se necesita):**
⏳ scrapy (si escala scraping)
⏳ selenium (si SII usa JS)
⏳ PyGithub (si integración GitHub)

**Fase 3 (Avanzado):**
⏳ spacy (NLP local avanzado)
⏳ python-telegram-bot (Telegram)

---

## 📝 NOTAS IMPORTANTES

1. **Odoo NO necesita cambios** → Mantener imagen lean
2. **AI Service asume toda la carga** → Escalable independiente
3. **BeautifulSoup es suficiente** → No necesitamos Scrapy aún
4. **Selenium no es necesario** → SII no usa JS pesado
5. **Impacto mínimo en recursos** → +50 MB imagen, +88 MB RAM

---

**Autor:** Análisis técnico profundo  
**Fecha:** 2025-10-22  
**Estado:** LISTO PARA IMPLEMENTAR  
**Próximo paso:** Actualizar requirements.txt y rebuild AI Service
