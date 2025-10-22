# 🚀 PRODUCTION PLAN: FACTURACIÓN CHILENA + MICROSERVICIOS + IA

**Versión:** 3.0 PRODUCTION-FOCUSED  
**Fecha:** 2025-10-21  
**Scope:** Performance + DTE + Microservicios + IA (SIN Kubernetes)  
**Stack:** Docker Compose + Traefik (proxy inverso)  
**Duración:** 50 semanas (12 meses)  
**Equipo:** 3 Senior Developers + 1 DevOps  
**Target:** Production-ready, high-performance, scalable  

---

## 📋 TABLA DE CONTENIDOS

1. Arquitectura Production-Ready (Docker Compose + Traefik)
2. Plan Refocado (50 semanas)
3. Performance Optimization Strategy
4. Docker Compose Stack Completo
5. Traefik Configuration
6. Monitoreo & Observabilidad
7. Scaling Strategy (sin Kubernetes)

---

## 🏗️ PARTE 1: ARQUITECTURA PRODUCTION (DOCKER COMPOSE + TRAEFIK)

### 1.1 Diagrama de Stack

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│                    TRAEFIK (Proxy Inverso)                         │
│          (SSL/TLS termination, routing, load balancing)            │
│                                                                     │
│  ├─ Container: traefik:v3                                          │
│  ├─ Labels: routing rules (Odoo, DTE, AI services)               │
│  ├─ Volumes: /etc/traefik/traefik.yml, certs, acme.json          │
│  ├─ Ports: 80 (HTTP), 443 (HTTPS), 8080 (dashboard)             │
│  └─ Network: traefik-network (bridged to all services)           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
                    ↓                   ↓                   ↓
        ┌─────────────────┐   ┌──────────────────┐  ┌────────────────┐
        │ ODOO Container  │   │ DTE Service      │  │ AI Service     │
        │ (eergygroup/...)│   │ (FastAPI)        │  │ (FastAPI+LLM)  │
        │                 │   │                  │  │                │
        │ ├─ Port: 8069   │   │ ├─ Port: 5000    │  │ ├─ Port: 8001  │
        │ ├─ Labels:      │   │ ├─ Labels:       │  │ ├─ Labels:     │
        │ │ traefik.http  │   │ │ traefik.http   │  │ │ traefik.http │
        │ │ router=odoo   │   │ │ router=dte     │  │ │ router=ai    │
        │ └─ Env vars     │   │ └─ Env vars      │  │ └─ Env vars    │
        │                 │   │                  │  │                │
        └─────────────────┘   └──────────────────┘  └────────────────┘
           ↓                        ↓                      ↓
        ┌─────────────────────────────────────────────────────────────┐
        │                  DOCKER NETWORK (bridge)                    │
        │         (Service-to-service communication)                  │
        └─────────────────────────────────────────────────────────────┘
           ↓                        ↓                      ↓
    ┌─────────────────────────────────────────────────────────────────┐
    │                    DATA TIER (Shared Volumes)                   │
    │                                                                 │
    │  ├─ PostgreSQL 15 (postgres:15-alpine)                         │
    │  ├─ Redis (redis:7-alpine)                                     │
    │  ├─ RabbitMQ (rabbitmq:3.12-management-alpine)                 │
    │  ├─ filestore (/var/lib/odoo/filestore)                        │
    │  └─ logs (/var/log/odoo, /app/logs)                           │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
           ↓
    ┌─────────────────────────────────────────────────────────────────┐
    │              MONITORING & LOGGING                               │
    │                                                                 │
    │  ├─ Prometheus (prom/prometheus:latest)                        │
    │  ├─ Grafana (grafana/grafana:latest)                           │
    │  ├─ ELK Stack (docker.elastic.co/elasticsearch/...)           │
    │  │  ├─ Elasticsearch                                           │
    │  │  ├─ Logstash                                                │
    │  │  └─ Kibana                                                  │
    │  └─ Traefik dashboard (localhost:8080)                        │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
```

### 1.2 Docker Compose Services (simplificado, production-ready)

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v3
    container_name: traefik
    ports:
      - "80:80"           # HTTP
      - "443:443"         # HTTPS
      - "8080:8080"       # Dashboard
    volumes:
      - ./traefik/traefik.yml:/traefik.yml:ro
      - ./traefik/certs:/etc/traefik/certs:ro
      - ./traefik/acme.json:/acme.json
      - /var/run/docker.sock:/var/run/docker.sock:ro
    networks:
      - traefik-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "traefik", "healthcheck", "--ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  odoo:
    build:
      context: ./docker
      dockerfile: Dockerfile
    image: eergygroup/odoo19:v1
    container_name: odoo19_app
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
      dte-service:
        condition: service_healthy
      ai-service:
        condition: service_healthy
    environment:
      - HOST=db
      - PORT=5432
      - USER=odoo
      - PASSWORD=odoo
      - DB_NAME=odoo
      - TIMEZONE=America/Santiago
      - LANG=es_CL.UTF-8
      - PYTHONUNBUFFERED=1
      - DTE_SERVICE_URL=http://dte-service:5000
      - AI_SERVICE_URL=http://ai-service:8000
      - REDIS_URL=redis://redis:6379/0
    volumes:
      - ./config/odoo.conf:/etc/odoo/odoo.conf:ro
      - ./addons/custom:/opt/odoo/addons/custom:rw
      - ./addons/localization:/opt/odoo/addons/localization:rw
      - ./addons/third_party:/opt/odoo/addons/third_party:rw
      - ./data/filestore:/var/lib/odoo/filestore:rw
      - ./data/logs:/var/log/odoo:rw
    networks:
      - traefik-network
      - backend-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.odoo.rule=Host(`odoo.ejemplo.com`)"
      - "traefik.http.routers.odoo.entrypoints=websecure"
      - "traefik.http.routers.odoo.tls=true"
      - "traefik.http.routers.odoo.tls.certresolver=letsencrypt"
      - "traefik.http.services.odoo.loadbalancer.server.port=8069"
      - "traefik.http.services.odoo.loadbalancer.server.scheme=http"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8069/web/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 40s

  dte-service:
    build:
      context: ./dte-service
      dockerfile: Dockerfile
    image: eergygroup/dte-service:v1
    container_name: dte-service
    depends_on:
      redis:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    environment:
      - FLASK_ENV=production
      - SII_ENVIRONMENT=production
      - LOG_LEVEL=info
      - REDIS_URL=redis://redis:6379/1
      - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
    volumes:
      - ./dte-service/app:/app:ro
      - ./data/dte-certs:/dte-certs:ro
      - ./data/logs/dte-service:/app/logs:rw
    networks:
      - backend-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.dte.rule=Host(`api.ejemplo.com`) && PathPrefix(`/dte`)"
      - "traefik.http.routers.dte.entrypoints=websecure"
      - "traefik.http.routers.dte.tls=true"
      - "traefik.http.services.dte.loadbalancer.server.port=5000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  ai-service:
    build:
      context: ./ai-service
      dockerfile: Dockerfile
    image: eergygroup/ai-service:v1
    container_name: ai-service
    depends_on:
      redis:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    environment:
      - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
      - OLLAMA_API_URL=http://ollama:11434
      - ODOO_URL=http://odoo:8069
      - REDIS_URL=redis://redis:6379/2
      - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672/
      - LOG_LEVEL=info
    volumes:
      - ./ai-service/app:/app:ro
      - ./data/ai-cache:/app/cache:rw
      - ./data/ai-uploads:/app/uploads:rw
      - ./data/logs/ai-service:/app/logs:rw
    networks:
      - backend-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.ai.rule=Host(`api.ejemplo.com`) && PathPrefix(`/ai`)"
      - "traefik.http.routers.ai.entrypoints=websecure"
      - "traefik.http.routers.ai.tls=true"
      - "traefik.http.services.ai.loadbalancer.server.port=8000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  db:
    image: postgres:15-alpine
    container_name: odoo19_db
    environment:
      - POSTGRES_DB=odoo
      - POSTGRES_USER=odoo
      - POSTGRES_PASSWORD=odoo
      - POSTGRES_INITDB_ARGS=--encoding=UTF8 --locale=es_CL.UTF-8
    volumes:
      - postgres_data:/var/lib/postgresql/data:rw
      - ./config/postgresql.conf:/etc/postgresql/postgresql.conf:ro
    networks:
      - backend-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U odoo -d odoo"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    container_name: redis_cache
    command: redis-server --appendonly yes --maxmemory 512mb --maxmemory-policy allkeys-lru
    volumes:
      - redis_data:/data:rw
    networks:
      - backend-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 3

  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    container_name: rabbitmq
    environment:
      - RABBITMQ_DEFAULT_USER=guest
      - RABBITMQ_DEFAULT_PASS=guest
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq:rw
    networks:
      - backend-network
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "check_port_connectivity"]
      interval: 10s
      timeout: 5s
      retries: 3

  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    volumes:
      - ./data/ollama-models:/root/.ollama:rw
    networks:
      - backend-network
    environment:
      - OLLAMA_HOST=0.0.0.0:11434
    restart: unless-stopped

  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus_data:/prometheus:rw
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - backend-network
    restart: unless-stopped

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_INSTALL_PLUGINS=grafana-piechart-panel
    volumes:
      - grafana_data:/var/lib/grafana:rw
      - ./monitoring/grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      - traefik-network
      - backend-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.grafana.rule=Host(`grafana.ejemplo.com`)"
      - "traefik.http.routers.grafana.entrypoints=websecure"
      - "traefik.http.routers.grafana.tls=true"
      - "traefik.http.services.grafana.loadbalancer.server.port=3000"
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  rabbitmq_data:
  prometheus_data:
  grafana_data:

networks:
  traefik-network:
    driver: bridge
  backend-network:
    driver: bridge
```

---

## 📈 PARTE 2: PLAN REFOCADO (50 SEMANAS)

### 2.1 Cronograma Production-Ready

```
FASE 0: SETUP PRODUCTION (Semanas 1-2)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 1:
  ├─ Setup docker-compose stack
  ├─ Setup Traefik (routing, SSL/TLS)
  ├─ Setup PostgreSQL 15 optimizado
  ├─ Setup Redis (cache, sessions)
  └─ Setup RabbitMQ (async jobs)

Semana 2:
  ├─ Setup Prometheus + Grafana
  ├─ Setup Ollama container
  ├─ Network configuration
  ├─ Volume management
  └─ Environment variables


FASE 1: MÓDULO l10n_cl_dte (Semanas 3-12)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 3-4:
  ├─ Modelos Odoo (extensiones + DTE models)
  ├─ Validadores (básicos + avanzados)
  ├─ RUT validator con padrón SII
  └─ Tests unitarios

Semana 5-6:
  ├─ DTE types (33, 39, 61, 56, 52)
  ├─ State machine (draft → sent → accepted)
  ├─ Audit logging system (ir.logging)
  ├─ User interface (vistas XML)
  └─ Wizards (upload cert, send batch)

Semana 7-8:
  ├─ Reports (invoice PDF + QR)
  ├─ Dashboard DTE monitoring
  ├─ Email notifications
  ├─ Error handling
  └─ Integration tests

Semana 9-10:
  ├─ Performance optimization (queries)
  ├─ Caching strategy (Redis)
  ├─ Database indexing
  ├─ Load testing (1000 DTEs)
  └─ Code review

Semana 11-12:
  ├─ Code quality (linting, coverage > 80%)
  ├─ Security hardening
  ├─ Documentation (API, models)
  └─ Production readiness


FASE 2: DTE SERVICE - MICROSERVICIO (Semanas 13-20)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 13-14:
  ├─ FastAPI application structure
  ├─ DTEGenerator (XML generation)
  ├─ DTESigner (digital signature)
  ├─ XSD validation
  └─ Tests

Semana 15-16:
  ├─ DTESender (SOAP client → SII)
  ├─ Error handling (50+ SII codes)
  ├─ Retry logic (exponential backoff)
  ├─ State persistence
  └─ Tests con SII

Semana 17:
  ├─ DTEReceiver (compras)
  ├─ CompraReconciliation (matching)
  ├─ Auto-create purchase.bill
  └─ Tests

Semana 18:
  ├─ Certificate manager (renovación, alertas)
  ├─ Batch API (masivo)
  ├─ Webhook receiver
  └─ Tests

Semana 19-20:
  ├─ Load testing (1000+ DTEs/min)
  ├─ Performance profiling
  ├─ Security review
  ├─ Docker optimization
  └─ Production checklist


FASE 3: AI SERVICE - ESPECIALIZADO (Semanas 21-30)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 21-22:
  ├─ FastAPI application
  ├─ Document processors (PDF, XML, OCR)
  ├─ Ollama integration (local LLM)
  ├─ Embeddings (Sentence-Transformers)
  └─ ChromaDB (vector DB)

Semana 23-24:
  ├─ Anthropic client (secure)
  ├─ Odoo RPC client
  ├─ Context builders
  ├─ Prompt templates (7 casos)
  └─ Tests

Semana 25-26:
  ├─ CASO 1-2: Validación DTE + Reconciliación
  ├─ Tests
  ├─ Threshold tuning
  └─ Integration tests

Semana 27-28:
  ├─ CASO 3-5: Clasificación + Anomalía + Reportes
  ├─ CASO 6-7: Predicción + Sugerencias
  ├─ Tests
  └─ Performance tuning

Semana 29-30:
  ├─ Load testing (LLM inference)
  ├─ Cost optimization (Anthropic)
  ├─ Security review
  ├─ Monitoring setup
  └─ Production checklist


FASE 4: INTEGRACIÓN & TESTING (Semanas 31-38)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 31-32:
  ├─ Odoo ↔ DTE Service REST calls
  ├─ Odoo ↔ AI Service REST calls
  ├─ RabbitMQ async events
  ├─ Redis session management
  └─ Tests

Semana 33-34:
  ├─ End-to-end testing (E2E)
  ├─ Workflow validation
  ├─ Error scenario testing
  ├─ Database migration (if needed)
  └─ UAT

Semana 35-36:
  ├─ Load testing (integrated)
  ├─ Performance optimization
  ├─ Query optimization
  ├─ Cache strategy tuning
  └─ Metrics validation

Semana 37-38:
  ├─ Security audit (OWASP Top 10)
  ├─ Penetration testing
  ├─ Data encryption validation
  ├─ SII compliance check
  └─ Production readiness


FASE 5: OPERACIONES & MONITORING (Semanas 39-44)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 39-40:
  ├─ Prometheus metrics setup
  ├─ Grafana dashboards (5-10 boards)
  ├─ Alert configuration
  ├─ SLA monitoring (p95 < 500ms)
  └─ Logging (ELK stack)

Semana 41-42:
  ├─ Backup strategy (daily + weekly)
  ├─ Recovery testing
  ├─ Disaster recovery plan
  ├─ Documentation
  └─ Runbooks (20+ scenarios)

Semana 43-44:
  ├─ Auditoría completa (ir.logging)
  ├─ Compliance reporting
  ├─ Legal review (LATAM)
  ├─ Data retention policies
  └─ GDPR-like compliance


FASE 6: DOCUMENTACIÓN & TRAINING (Semanas 45-47)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 45:
  ├─ API documentation (OpenAPI 3.0)
  ├─ Architecture documentation
  ├─ Deployment guide
  └─ Configuration reference

Semana 46:
  ├─ User manual (30 páginas)
  ├─ Troubleshooting guide (40+ scenarios)
  ├─ FAQ (50+ preguntas)
  └─ Video tutorials (5-10 videos)

Semana 47:
  ├─ Developer training (API, extensiones)
  ├─ SysAdmin training (deployment, monitoring)
  ├─ User training (2 days)
  └─ Support setup


FASE 7: DEPLOYMENT & CUTOVER (Semanas 48-50)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Semana 48:
  ├─ Pre-production environment (exact copy)
  ├─ Data migration (if applicable)
  ├─ Integration testing with SII
  ├─ Final UAT
  └─ Rollback procedure

Semana 49:
  ├─ Production deployment (blue-green)
  ├─ Smoke testing
  ├─ Monitor all systems
  ├─ 24x7 support standby
  └─ Performance monitoring

Semana 50:
  ├─ Go-live support
  ├─ Bug fix fast track
  ├─ Performance tuning (live data)
  ├─ Customer feedback integration
  └─ Post-production review
```

---

## ⚡ PARTE 3: PERFORMANCE OPTIMIZATION STRATEGY

### 3.1 Database Performance

```sql
-- 1. INDEXING (Critical queries)
CREATE INDEX idx_dte_document_state ON dte_document(state);
CREATE INDEX idx_dte_document_date ON dte_document(date_issued);
CREATE INDEX idx_account_move_date ON account_move(invoice_date);
CREATE INDEX idx_account_move_partner ON account_move(partner_id);

-- 2. QUERY OPTIMIZATION
-- Usar select_related + prefetch_related en Odoo ORM
# Python (Odoo):
DTEDocument.objects.select_related('move_id', 'partner_id').filter(state='sent')

-- 3. VACUUM & ANALYZE (Nightly)
VACUUM ANALYZE;

-- 4. CONNECTION POOLING
# PgBouncer (min_pool_size=10, max_pool_size=50)

-- 5. PARTITION STRATEGY
-- DTEs por año (table partitioning)
CREATE TABLE dte_document_2025 PARTITION OF dte_document
  FOR VALUES FROM ('2025-01-01') TO ('2026-01-01');
```

### 3.2 Redis Cache Strategy

```python
# Odoo cache backend configuration
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://redis:6379/0',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
            'CONNECTION_POOL_KWARGS': {
                'max_connections': 50,
                'retry_on_timeout': True
            },
            'SOCKET_CONNECT_TIMEOUT': 5,
            'SOCKET_TIMEOUT': 5,
            'COMPRESSOR': 'django_redis.compressors.zlib.ZlibCompressor',
        }
    }
}

# Cache warm-up (on app startup)
# Cache: DTEs últimos 7 días, partners frecuentes, configuración SII

# TTL by data type:
# - DTEs vigentes: 1 hora
# - Partners: 24 horas
# - Configuración: 7 días
# - Reportes: 15 minutos
```

### 3.3 Application Performance

```python
# 1. ASYNC PROCESSING (RabbitMQ + Celery)
@task(bind=True, max_retries=3)
def send_dte_to_sii(self, dte_id):
    """Async task: enviar DTE a SII"""
    try:
        dte = DTEDocument.objects.get(id=dte_id)
        result = dte_service.send_to_sii(dte)
        return result
    except Exception as exc:
        # Retry con exponential backoff
        raise self.retry(exc=exc, countdown=2 ** self.request.retries)

# 2. QUERY OPTIMIZATION
# Django ORM: use select_related(), prefetch_related()
# Avoid N+1 queries

# 3. SERIALIZATION
# Use MessagePack instead of JSON for cache (30% faster)

# 4. LAZY LOADING
# Generate heavy reports asynchronously (PDF + email)

# 5. PAGINATION
# APIs: default page_size=20, max=100
```

### 3.4 API Performance

```python
# FastAPI settings (dte-service, ai-service)

# 1. Response compression
from fastapi import FastAPI
from fastapi.middleware.gzip import GZIPMiddleware

app = FastAPI()
app.add_middleware(GZIPMiddleware, minimum_size=1000)

# 2. Connection pooling
from sqlalchemy.pool import QueuePool
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=40,
    pool_recycle=3600
)

# 3. Rate limiting
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)

@limiter.limit("100/minute")
@app.get("/api/dte")
async def get_dtes():
    pass

# 4. Timeout handling
# Set timeouts: 10s read, 5s write, 30s total
```

---

## 🔍 PARTE 4: TRAEFIK CONFIGURATION (Production)

### 4.1 traefik.yml

```yaml
# Traefik configuration (production)

global:
  checkNewVersion: false
  sendAnonymousUsage: false

entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entrypoint:
          regex: "^http://(.*)$"
          replacement: "https://$1"
          permanent: true

  websecure:
    address: ":443"
    http:
      tls:
        certResolver: letsencrypt
        domains:
          - main: "ejemplo.com"
            sans:
              - "odoo.ejemplo.com"
              - "api.ejemplo.com"
              - "grafana.ejemplo.com"

  metrics:
    address: ":8082"

api:
  dashboard: true
  debug: false

providers:
  docker:
    endpoint: "unix:///var/run/docker.sock"
    exposedByDefault: false
    network: traefik-network
    swarmMode: false

  file:
    filename: /traefik/dynamic.yml
    watch: true

certificatesResolvers:
  letsencrypt:
    acme:
      email: "admin@ejemplo.com"
      storage: /acme.json
      httpChallenge:
        entryPoint: web

metrics:
  prometheus:
    addEntryPointsLabels: true
    addServicesLabels: true
    buckets:
      - 0.1
      - 0.3
      - 1.2
      - 5.0

log:
  level: INFO
  format: json

accessLog:
  format: json
```

---

## 📊 PARTE 5: MONITOREO & OBSERVABILIDAD

### 5.1 Prometheus Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  # Traefik
  - job_name: 'traefik'
    static_configs:
      - targets: ['localhost:8082']

  # Odoo (via prometheus exporter)
  - job_name: 'odoo'
    static_configs:
      - targets: ['localhost:9090']

  # PostgreSQL (via postgres_exporter)
  - job_name: 'postgres'
    static_configs:
      - targets: ['localhost:9187']

  # Redis (via redis_exporter)
  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']

  # Docker (via cadvisor)
  - job_name: 'docker'
    static_configs:
      - targets: ['localhost:8080']
```

### 5.2 Grafana Dashboards

```
Dashboard 1: SYSTEM OVERVIEW
  ├─ CPU utilization (%)
  ├─ Memory usage (%)
  ├─ Disk usage (%)
  ├─ Network I/O (MB/s)
  └─ Container status

Dashboard 2: ODOO PERFORMANCE
  ├─ HTTP requests/sec
  ├─ Response time (p50, p95, p99)
  ├─ Active sessions
  ├─ Database connections
  └─ Cache hit ratio

Dashboard 3: DTE SERVICE
  ├─ DTEs generated/hour
  ├─ DTEs sent/hour
  ├─ SII error rate (%)
  ├─ API response time
  └─ Queue depth (RabbitMQ)

Dashboard 4: AI SERVICE
  ├─ LLM inference time
  ├─ Anthropic API calls/hour
  ├─ Document processing rate
  ├─ Model inference p95
  └─ Cache hit ratio (embeddings)

Dashboard 5: DATABASE
  ├─ Query time (p50, p95, p99)
  ├─ Active connections
  ├─ Cache hit ratio
  ├─ Table size
  └─ Slow queries
```

---

## 📈 PARTE 6: PERFORMANCE TARGETS

```
MÉTRICA                           TARGET            METHOD
──────────────────────────────────────────────────────────
HTTP request latency (p50)        < 100ms           SSD + cache
HTTP request latency (p95)        < 500ms           Query optimization
HTTP request latency (p99)        < 1000ms          Load testing
API response time (DTE Service)   < 200ms           FastAPI + Redis
API response time (AI Service)    < 2s              LLM inference
Database query (p95)              < 100ms           Indexing
DTEs processed/hour               1000+             Async + queue
Concurrent users                  500+              Odoo sessions
Cache hit ratio                   > 80%             Redis tuning
CPU utilization                   < 60%             Container limits
Memory utilization                < 70%             OOM prevention
Disk utilization                  < 80%             Storage expansion
```

---

## 🚀 PARTE 7: SCALING STRATEGY (Sin Kubernetes)

### 7.1 Horizontal Scaling (Docker Compose)

```yaml
# Scale servicios específicos:

# 1. ODOO (múltiples workers)
version: '3.8'
services:
  odoo-1:
    image: eergygroup/odoo19:v1
    # worker_processes=4 en odoo.conf

  odoo-2:
    image: eergygroup/odoo19:v1
    # worker_processes=4

  odoo-3:
    image: eergygroup/odoo19:v1
    # worker_processes=4

# Traefik load balancing (round-robin):
# traefik.http.services.odoo.loadbalancer.server.port=8069

# 2. DTE SERVICE (replicas)
dte-service-1:
  image: eergygroup/dte-service:v1
  environment:
    - WORKERS=4

dte-service-2:
  image: eergygroup/dte-service:v1
  environment:
    - WORKERS=4

# 3. AI SERVICE (replicas)
ai-service-1:
  image: eergygroup/ai-service:v1

ai-service-2:
  image: eergygroup/ai-service:v1
```

### 7.2 Vertical Scaling (Docker resource limits)

```yaml
services:
  odoo:
    image: eergygroup/odoo19:v1
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 8G
        reservations:
          cpus: '2.0'
          memory: 4G

  dte-service:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G

  ai-service:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 8G  # LLM inference needs more memory

  db:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 8G
```

---

## 📊 COMPARATIVA: PLAN ORIGINAL vs PRODUCTION-FOCUSED

| Aspecto | Original | Production-Focused | Cambio |
|---------|----------|-------------------|--------|
| **Duración** | 65 sem | 50 sem | -23% ✅ |
| **Equipo** | 4-5 devs | 3 devs + 1 devops | -30% |
| **Infraestructura** | Kubernetes | Docker Compose | Simplificado |
| **Proxy Inverso** | Nginx | Traefik | Mejor routing |
| **Focus** | Enterprise | Performance | Pragmático |
| **Escalabilidad** | Auto-scaling | Manual pero fácil | Trade-off |
| **Complexity** | Alta | Media | -50% |
| **Time-to-market** | 15 meses | 12 meses | -3 meses |
| **Costo año 1** | $250k | $150-180k | -40% |
| **Production-ready** | SÍ (99.95%) | SÍ (99.5%) | Trade-off |

---

## ✅ CONCLUSIÓN

### Recomendación Final

**→ PRODUCTION-FOCUSED PLAN (50 SEMANAS)**

**Ventajas:**
- ✅ 12 meses hasta production (vs 15)
- ✅ Docker Compose + Traefik (simple, elegante)
- ✅ Focus TOTAL en performance + funcionalidad
- ✅ 3 developers (vs 5)
- ✅ 40% menos inversión ($150-180k)
- ✅ 99.5% uptime SLA (suficiente)
- ✅ Escalable manualmente (fácil)

**Trade-offs:**
- ❌ Auto-scaling manual (vs Kubernetes)
- ❌ Monitoring más manual
- ❌ Infraestructura menos resiliente

**Este plan es PRAGMÁTICO para producción real.**
