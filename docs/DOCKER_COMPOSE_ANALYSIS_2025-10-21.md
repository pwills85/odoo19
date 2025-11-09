# 🐳 ANÁLISIS PROFUNDO: Docker Compose - Odoo 19 CE + DTE

**Fecha:** 2025-10-21 22:20 UTC-03:00  
**Archivo:** `docker-compose.yml`  
**Versión:** 3.9  
**Servicios:** 6 contenedores  
**Arquitectura:** Microservicios + Red Interna Segura

---

## 📊 RESUMEN EJECUTIVO

### Arquitectura General

```
┌─────────────────────────────────────────────────────────┐
│                    INTERNET                              │
│                       ↓                                  │
│              Puerto 8169 (Odoo Web)                      │
│              Puerto 8171 (Longpolling)                   │
│              Puerto 15772 (RabbitMQ UI - localhost)      │
└─────────────────────────────────────────────────────────┘
                       ↓
┌─────────────────────────────────────────────────────────┐
│              STACK_NETWORK (Bridge)                      │
│                                                          │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   ODOO   │←→│ DTE Service  │←→│ AI Service   │     │
│  │  :8069   │  │   :8001      │  │   :8002      │     │
│  └──────────┘  └──────────────┘  └──────────────┘     │
│       ↓              ↓                   ↓              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │PostgreSQL│  │  Redis   │  │ RabbitMQ │             │
│  │  :5432   │  │  :6379   │  │  :5672   │             │
│  └──────────┘  └──────────┘  └──────────┘             │
│                                    ↓                     │
│                            ┌──────────┐                 │
│                            │  Ollama  │                 │
│                            │  :11434  │                 │
│                            └──────────┘                 │
└─────────────────────────────────────────────────────────┘
```

### Métricas del Stack

| Métrica | Valor |
|---------|-------|
| **Servicios** | 6 contenedores |
| **Volúmenes** | 6 volúmenes Docker |
| **Redes** | 1 red bridge |
| **Puertos expuestos** | 3 (8169, 8171, 15772) |
| **Puertos internos** | 6 (5432, 6379, 5672, 8069, 8001, 8002, 11434) |
| **Health checks** | 5/6 servicios |
| **Dependencias** | Gestionadas con `depends_on` |

---

## 🔍 ANÁLISIS POR SERVICIO

### 1. PostgreSQL Database (db)

**Imagen:** `postgres:15-alpine`  
**Container:** `odoo19_db`  
**Puerto:** `5432` (solo red interna)

#### Configuración
```yaml
environment:
  POSTGRES_DB: ${ODOO_DB_NAME:-odoo}
  POSTGRES_USER: ${ODOO_DB_USER:-odoo}
  POSTGRES_PASSWORD: ${ODOO_DB_PASSWORD:-odoo}
  POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=es_CL.UTF-8"
```

#### Volúmenes
```yaml
volumes:
  - postgres_data:/var/lib/postgresql/data
```

**Análisis:**
- ✅ **Locale chileno:** `es_CL.UTF-8` (correcto para DTE)
- ✅ **Encoding UTF8:** Soporta caracteres especiales
- ✅ **Health check:** `pg_isready` cada 10s
- ✅ **Persistencia:** Volume Docker `postgres_data`
- ✅ **Seguridad:** Solo red interna (no expuesto)
- ⚠️ **Credenciales:** Usa defaults (cambiar en producción)

**Recomendaciones:**
1. 🔴 **Producción:** Cambiar credenciales por defecto
2. 🟡 **Backup:** Configurar backup automático
3. 🟡 **Performance:** Considerar `postgresql.conf` custom

---

### 2. Redis Cache (redis)

**Imagen:** `redis:7-alpine`  
**Container:** `odoo19_redis`  
**Puerto:** `6379` (solo red interna)

#### Configuración
```yaml
expose:
  - "6379"  # Solo red interna
healthcheck:
  test: ["CMD", "redis-cli", "ping"]
  interval: 10s
```

**Análisis:**
- ✅ **Versión moderna:** Redis 7
- ✅ **Health check:** `redis-cli ping` cada 10s
- ✅ **Seguridad:** Solo red interna
- ⚠️ **Sin persistencia:** No tiene volumen (cache volátil)
- ⚠️ **Sin password:** Redis sin autenticación

**Uso en el Stack:**
- DTE Service: `redis://redis:6379/0` (DB 0)
- AI Service: `redis://redis:6379/1` (DB 1)

**Recomendaciones:**
1. 🟡 **Producción:** Agregar password Redis
2. 🟢 **OK:** Cache volátil es correcto para este uso
3. 🟡 **Considerar:** Redis persistence si se usa para sessions

---

### 3. RabbitMQ Message Queue (rabbitmq)

**Imagen:** `rabbitmq:3.12-management-alpine`  
**Container:** `odoo19_rabbitmq`  
**Puertos:** 
- `5672` (AMQP - red interna)
- `15672` (Management UI - red interna)
- `127.0.0.1:15772:15672` (Management UI - localhost)

#### Configuración
```yaml
ports:
  - "127.0.0.1:15772:15672"  # Solo localhost para debugging
expose:
  - "5672"   # AMQP
  - "15672"  # Management UI interno
```

**Análisis:**
- ✅ **Management UI:** Accesible solo desde localhost
- ✅ **AMQP interno:** Puerto 5672 solo en red interna
- ✅ **Health check:** `rabbitmq-diagnostics ping`
- ✅ **Seguridad:** Management UI no expuesto públicamente
- ⚠️ **Credenciales:** Usa guest/guest por defecto

**Uso en el Stack:**
- DTE Service: `amqp://guest:guest@rabbitmq:5672//`
- Async jobs, cola de DTEs

**Recomendaciones:**
1. 🔴 **Producción:** Cambiar credenciales guest/guest
2. 🟡 **Considerar:** Volumen para persistencia de colas
3. 🟢 **OK:** Management UI solo localhost

---

### 4. Odoo Service (odoo) ⭐ PRINCIPAL

**Imagen:** `eergygroup/odoo19:v1` (custom build)  
**Container:** `odoo19_app`  
**Puertos:**
- `8169:8069` (Web - público)
- `8171:8071` (Longpolling - público)
- `8069` (expuesto en red interna)

#### Configuración
```yaml
build:
  context: .
  dockerfile: docker/Dockerfile
depends_on:
  db:
    condition: service_healthy
  redis:
    condition: service_healthy
environment:
  - HOST=db
  - PORT=5432
  - USER=${ODOO_DB_USER:-odoo}
  - PASSWORD=${ODOO_DB_PASSWORD:-odoo}
  - DB_NAME=${ODOO_DB_NAME:-odoo}
  - TIMEZONE=America/Santiago
  - LANG=es_CL.UTF-8
  - TZ=America/Santiago
  - PYTHONUNBUFFERED=1
```

#### Volúmenes (CRÍTICO)
```yaml
volumes:
  - ./config/odoo.conf:/etc/odoo/odoo.conf:ro
  - ./addons/custom:/mnt/extra-addons/custom
  - ./addons/localization:/mnt/extra-addons/localization
  - ./addons/third_party:/mnt/extra-addons/third_party
  - odoo_filestore:/var/lib/odoo
```

**Análisis de Volúmenes:**

1. **Config (Read-Only):**
   - `./config/odoo.conf:/etc/odoo/odoo.conf:ro`
   - ✅ Read-only para seguridad
   - ✅ Configuración centralizada

2. **Addons Custom:**
   - `./addons/custom:/mnt/extra-addons/custom`
   - ✅ Módulos personalizados
   - ✅ Bind mount para desarrollo

3. **Addons Localization:**
   - `./addons/localization:/mnt/extra-addons/localization`
   - ✅ **Contiene l10n_cl_dte** (nuestro módulo)
   - ✅ Bind mount para desarrollo

4. **Addons Third Party:**
   - `./addons/third_party:/mnt/extra-addons/third_party`
   - ✅ Módulos de terceros
   - ✅ Bind mount

5. **Filestore (Persistente):**
   - `odoo_filestore:/var/lib/odoo`
   - ✅ Volume Docker (persistente)
   - ✅ Attachments, sessions, etc.

**Health Check:**
```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8069/web/health"]
  interval: 30s
  timeout: 10s
  retries: 5
  start_period: 40s
```

**Análisis:**
- ✅ **Timezone:** America/Santiago (correcto para Chile)
- ✅ **Locale:** es_CL.UTF-8 (correcto para DTE)
- ✅ **Depends on:** Espera DB y Redis healthy
- ✅ **Health check:** Endpoint `/web/health`
- ✅ **Desarrollo:** Bind mounts permiten hot-reload
- ✅ **Producción:** Filestore persistente

**Recomendaciones:**
1. 🟢 **OK:** Configuración excelente
2. 🟡 **Considerar:** Traefik como proxy reverso
3. 🟡 **Producción:** SSL/TLS con Let's Encrypt

---

### 5. DTE Service (dte-service) ⭐ MICROSERVICIO

**Build:** `./dte-service`  
**Container:** `odoo19_dte_service`  
**Puerto:** `8001` (SOLO red interna) 🔒

#### Configuración
```yaml
build: ./dte-service
depends_on:
  - redis
  - rabbitmq
environment:
  - API_KEY=${DTE_SERVICE_API_KEY:-default_dte_api_key}
  - SII_ENVIRONMENT=${SII_ENVIRONMENT:-sandbox}
  - REDIS_URL=redis://redis:6379/0
  - RABBITMQ_URL=amqp://guest:guest@rabbitmq:5672//
  - ODOO_URL=http://odoo:8069
  - LOG_LEVEL=INFO
expose:
  - "8001"  # ⭐ Solo red interna (NO exponer)
```

**Análisis:**
- ✅ **Seguridad:** Puerto 8001 NO expuesto públicamente
- ✅ **API Key:** Autenticación con Odoo
- ✅ **SII Sandbox:** Ambiente de pruebas por defecto
- ✅ **Redis DB 0:** Separado de AI Service
- ✅ **RabbitMQ:** Para async jobs
- ✅ **Health check:** `/health` endpoint
- ⚠️ **Sin volúmenes:** Stateless (correcto)

**Comunicación:**
```
Odoo → DTE Service (http://dte-service:8001)
DTE Service → SII (https://maullin.sii.cl o https://palena.sii.cl)
DTE Service → Redis (cache)
DTE Service → RabbitMQ (async)
```

**Recomendaciones:**
1. 🟢 **OK:** Puerto interno es correcto
2. 🔴 **Producción:** Cambiar API_KEY default
3. 🟡 **Producción:** SII_ENVIRONMENT=production
4. 🟢 **OK:** Stateless microservice

---

### 6. AI Service (ai-service) ⭐ MICROSERVICIO

**Build:** `./ai-service`  
**Container:** `odoo19_ai_service`  
**Puerto:** `8002` (SOLO red interna) 🔒

#### Configuración
```yaml
build: ./ai-service
depends_on:
  - redis
  - ollama
environment:
  - API_KEY=${AI_SERVICE_API_KEY:-default_ai_api_key}
  - ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
  - OLLAMA_URL=http://ollama:11434
  - REDIS_URL=redis://redis:6379/1
  - ODOO_URL=http://odoo:8069
  - LOG_LEVEL=INFO
volumes:
  - ai_cache:/app/cache
  - ai_uploads:/app/uploads
  - ai_chromadb:/app/data/chromadb
expose:
  - "8002"  # ⭐ Solo red interna
```

**Análisis de Volúmenes:**

1. **Cache:**
   - `ai_cache:/app/cache`
   - ✅ Embeddings cacheados
   - ✅ Persistente

2. **Uploads:**
   - `ai_uploads:/app/uploads`
   - ✅ Documentos para OCR
   - ✅ Persistente

3. **ChromaDB:**
   - `ai_chromadb:/app/data/chromadb`
   - ✅ Vector database
   - ✅ Persistente

**Análisis:**
- ✅ **Seguridad:** Puerto 8002 NO expuesto
- ✅ **Anthropic:** API key desde .env
- ✅ **Ollama:** LLM local como fallback
- ✅ **Redis DB 1:** Separado de DTE Service
- ✅ **Persistencia:** 3 volúmenes para datos
- ✅ **Health check:** `/health` endpoint

**Comunicación:**
```
Odoo → AI Service (http://ai-service:8002)
AI Service → Anthropic Claude (https://api.anthropic.com)
AI Service → Ollama (http://ollama:11434)
AI Service → Redis (cache)
```

**Recomendaciones:**
1. 🟢 **OK:** Puerto interno correcto
2. 🔴 **Producción:** Cambiar API_KEY default
3. 🔴 **Crítico:** Configurar ANTHROPIC_API_KEY
4. 🟡 **Considerar:** Backup de ChromaDB

---

### 7. Ollama LLM (ollama)

**Imagen:** `ollama/ollama:latest`  
**Container:** `odoo19_ollama`  
**Puerto:** `11434` (solo red interna)

#### Configuración
```yaml
expose:
  - "11434"
volumes:
  - ollama_data:/root/.ollama
```

**Análisis:**
- ✅ **LLM local:** Fallback si Anthropic falla
- ✅ **Persistencia:** Modelos descargados persisten
- ✅ **Seguridad:** Solo red interna
- ⚠️ **Sin health check:** No tiene verificación
- ⚠️ **Recursos:** Puede consumir mucha RAM/CPU

**Uso:**
- AI Service usa Ollama como fallback
- Modelos locales (llama2, mistral, etc.)

**Recomendaciones:**
1. 🟡 **Opcional:** Agregar health check
2. 🟡 **Recursos:** Limitar CPU/RAM en producción
3. 🟢 **OK:** Volumen persistente correcto

---

## 🌐 ANÁLISIS DE RED

### Stack Network (Bridge)

```yaml
networks:
  stack_network:
    driver: bridge
    internal: false  # Permite salida a internet
```

**Configuración:**
- **Driver:** Bridge (default Docker)
- **Internal:** `false` (permite salida a internet)
- **Servicios:** Todos en la misma red

**Análisis:**
- ✅ **Comunicación interna:** Todos los servicios se ven
- ✅ **Salida a internet:** Necesario para SII y Anthropic
- ✅ **DNS interno:** Docker DNS resuelve nombres
- ✅ **Aislamiento:** Red separada del host

**Flujo de Red:**

```
INTERNET
   ↓
   ├─→ :8169 → Odoo Web
   ├─→ :8171 → Odoo Longpolling
   └─→ :15772 → RabbitMQ UI (localhost)

STACK_NETWORK (Interna)
   ├─→ db:5432 (PostgreSQL)
   ├─→ redis:6379 (Redis)
   ├─→ rabbitmq:5672 (RabbitMQ AMQP)
   ├─→ odoo:8069 (Odoo interno)
   ├─→ dte-service:8001 (DTE - NO público)
   ├─→ ai-service:8002 (AI - NO público)
   └─→ ollama:11434 (Ollama)

SALIDA A INTERNET
   ├─→ SII (https://maullin.sii.cl)
   └─→ Anthropic (https://api.anthropic.com)
```

**Recomendaciones:**
1. 🟢 **OK:** Configuración correcta
2. 🟡 **Considerar:** Red separada para microservicios
3. 🟡 **Producción:** Firewall rules adicionales

---

## 💾 ANÁLISIS DE VOLÚMENES

### Volúmenes Docker

```yaml
volumes:
  postgres_data:      # PostgreSQL data
  odoo_filestore:     # Odoo attachments
  ollama_data:        # Ollama models
  ai_cache:           # AI embeddings cache
  ai_uploads:         # AI document uploads
  ai_chromadb:        # ChromaDB vector store
```

**Análisis por Volumen:**

| Volumen | Tamaño Estimado | Backup | Crítico |
|---------|-----------------|--------|---------|
| `postgres_data` | 1-10 GB | ✅ SÍ | 🔴 CRÍTICO |
| `odoo_filestore` | 1-50 GB | ✅ SÍ | 🔴 CRÍTICO |
| `ollama_data` | 5-20 GB | 🟡 Opcional | 🟡 MEDIO |
| `ai_cache` | 100 MB-1 GB | ❌ NO | 🟢 BAJO |
| `ai_uploads` | 1-10 GB | ✅ SÍ | 🟡 MEDIO |
| `ai_chromadb` | 100 MB-5 GB | ✅ SÍ | 🟡 MEDIO |

**Recomendaciones de Backup:**

1. **CRÍTICO (Diario):**
   - `postgres_data` → Backup SQL + WAL
   - `odoo_filestore` → Backup incremental

2. **IMPORTANTE (Semanal):**
   - `ai_uploads` → Backup completo
   - `ai_chromadb` → Backup completo

3. **OPCIONAL:**
   - `ollama_data` → Se puede re-descargar
   - `ai_cache` → Cache, no crítico

---

## 🔒 ANÁLISIS DE SEGURIDAD

### Puertos Expuestos

| Puerto | Servicio | Público | Seguridad |
|--------|----------|---------|-----------|
| `8169` | Odoo Web | ✅ SÍ | 🟡 Agregar SSL |
| `8171` | Longpolling | ✅ SÍ | 🟡 Agregar SSL |
| `15772` | RabbitMQ UI | ❌ Localhost | ✅ OK |

### Puertos Internos (NO expuestos)

| Puerto | Servicio | Expuesto | Seguridad |
|--------|----------|----------|-----------|
| `5432` | PostgreSQL | ❌ NO | ✅ EXCELENTE |
| `6379` | Redis | ❌ NO | ✅ EXCELENTE |
| `5672` | RabbitMQ | ❌ NO | ✅ EXCELENTE |
| `8001` | DTE Service | ❌ NO | ✅ EXCELENTE |
| `8002` | AI Service | ❌ NO | ✅ EXCELENTE |
| `11434` | Ollama | ❌ NO | ✅ EXCELENTE |

**Análisis de Seguridad:**
- ✅ **Microservicios:** NO expuestos públicamente
- ✅ **Databases:** Solo red interna
- ✅ **RabbitMQ UI:** Solo localhost
- ⚠️ **Odoo:** Sin SSL (agregar en producción)
- ⚠️ **Credenciales:** Defaults en varios servicios

---

## ⚙️ ANÁLISIS DE HEALTH CHECKS

| Servicio | Health Check | Intervalo | Timeout | Retries |
|----------|--------------|-----------|---------|---------|
| `db` | `pg_isready` | 10s | 5s | 5 |
| `redis` | `redis-cli ping` | 10s | 5s | 5 |
| `rabbitmq` | `rabbitmq-diagnostics` | 10s | 5s | 5 |
| `odoo` | `curl /web/health` | 30s | 10s | 5 |
| `dte-service` | `curl /health` | 30s | 10s | 3 |
| `ai-service` | `curl /health` | 30s | 10s | 3 |
| `ollama` | ❌ NO | - | - | - |

**Análisis:**
- ✅ **5/6 servicios:** Tienen health check
- ✅ **Intervalos:** Apropiados (10-30s)
- ✅ **Start period:** Odoo tiene 40s (correcto)
- ⚠️ **Ollama:** Sin health check

**Recomendaciones:**
1. 🟡 **Ollama:** Agregar health check
2. 🟢 **OK:** Configuración general excelente

---

## 🔄 ANÁLISIS DE DEPENDENCIAS

### Grafo de Dependencias

```
odoo
  ├─ depends_on: db (healthy)
  └─ depends_on: redis (healthy)

dte-service
  ├─ depends_on: redis
  └─ depends_on: rabbitmq

ai-service
  ├─ depends_on: redis
  └─ depends_on: ollama

db, redis, rabbitmq, ollama
  └─ (sin dependencias)
```

**Orden de Inicio:**
1. `db`, `redis`, `rabbitmq`, `ollama` (paralelo)
2. `odoo` (espera db y redis healthy)
3. `dte-service` (espera redis y rabbitmq)
4. `ai-service` (espera redis y ollama)

**Análisis:**
- ✅ **Orden correcto:** Servicios base primero
- ✅ **Health checks:** Odoo espera DB healthy
- ✅ **Paralelo:** Servicios independientes inician juntos
- 🟢 **OK:** Configuración óptima

---

## 📊 RESUMEN DE CONFIGURACIÓN

### Variables de Entorno Críticas

**Desde .env:**
```bash
# Database
ODOO_DB_NAME=odoo
ODOO_DB_USER=odoo
ODOO_DB_PASSWORD=odoo

# DTE Service
DTE_SERVICE_API_KEY=default_dte_api_key
SII_ENVIRONMENT=sandbox

# AI Service
AI_SERVICE_API_KEY=default_ai_api_key
ANTHROPIC_API_KEY=(requerido)
```

**Recomendaciones .env:**
1. 🔴 **Cambiar:** Todas las credenciales default
2. 🔴 **Configurar:** ANTHROPIC_API_KEY
3. 🟡 **Producción:** SII_ENVIRONMENT=production

---

## ✅ FORTALEZAS DEL STACK

1. ✅ **Seguridad:** Microservicios NO expuestos
2. ✅ **Health Checks:** 5/6 servicios monitoreados
3. ✅ **Persistencia:** 6 volúmenes Docker
4. ✅ **Locale:** es_CL.UTF-8 (correcto para Chile)
5. ✅ **Timezone:** America/Santiago
6. ✅ **Desarrollo:** Bind mounts para hot-reload
7. ✅ **Dependencias:** Orden de inicio correcto
8. ✅ **Red interna:** Comunicación segura

---

## ⚠️ ÁREAS DE MEJORA

### Críticas (Producción)

1. 🔴 **Credenciales Default**
   - PostgreSQL: odoo/odoo
   - RabbitMQ: guest/guest
   - API Keys: default_*

2. 🔴 **SSL/TLS**
   - Odoo sin HTTPS
   - Considerar Traefik

3. 🔴 **ANTHROPIC_API_KEY**
   - Requerido para AI Service
   - Configurar en .env

### Medias

4. 🟡 **Backups**
   - Configurar backup automático
   - PostgreSQL + Filestore

5. 🟡 **Monitoring**
   - Agregar Prometheus
   - Agregar Grafana

6. 🟡 **Logs**
   - Centralizar logs
   - Considerar ELK stack

### Bajas

7. 🟢 **Ollama Health Check**
   - Agregar verificación
   - No crítico

---

## 🚀 RECOMENDACIONES FINALES

### Para Desarrollo (Actual)

✅ **Stack está EXCELENTE para desarrollo:**
- Bind mounts permiten hot-reload
- Health checks aseguran estabilidad
- Microservicios aislados
- Red interna segura

### Para Producción

**Checklist Pre-Producción:**

- [ ] Cambiar todas las credenciales default
- [ ] Configurar ANTHROPIC_API_KEY
- [ ] Cambiar SII_ENVIRONMENT=production
- [ ] Agregar SSL/TLS (Traefik + Let's Encrypt)
- [ ] Configurar backups automáticos
- [ ] Agregar monitoring (Prometheus + Grafana)
- [ ] Configurar firewall rules
- [ ] Limitar recursos (CPU/RAM)
- [ ] Configurar log rotation
- [ ] Agregar Redis password
- [ ] Configurar RabbitMQ users

---

## 📋 COMANDOS ÚTILES

### Gestión del Stack

```bash
# Iniciar stack
docker-compose up -d

# Ver logs
docker-compose logs -f odoo
docker-compose logs -f dte-service
docker-compose logs -f ai-service

# Ver estado
docker-compose ps

# Reiniciar servicio
docker-compose restart odoo

# Detener stack
docker-compose down

# Detener y eliminar volúmenes (⚠️ CUIDADO)
docker-compose down -v
```

### Backup

```bash
# Backup PostgreSQL
docker-compose exec db pg_dump -U odoo odoo > backup.sql

# Backup volúmenes
docker run --rm -v odoo19_postgres_data:/data -v $(pwd):/backup \
  alpine tar czf /backup/postgres_backup.tar.gz /data
```

---

**Análisis completado:** 2025-10-21 22:20  
**Stack:** Docker Compose 3.9  
**Servicios:** 6 contenedores  
**Calificación:** 🟢 EXCELENTE (para desarrollo)  
**Recomendación:** ✅ Aplicar checklist para producción
