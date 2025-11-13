# 🏗️ DEPLOYMENT ENVIRONMENT - Stack Técnico Completo

**Versión:** 1.0.0
**Fecha:** 2025-11-12
**Proyecto:** Odoo 19 CE EERGYGROUP
**Platform:** macOS M3 (ARM64)

---

## 🎯 Arquitectura General

```
┌─────────────────────────────────────────────────────────┐
│                    ODOO 19 STACK                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐   ┌──────────────┐   ┌────────────┐ │
│  │  Odoo 19 CE  │──▶│ PostgreSQL   │   │  AI Service│ │
│  │  (Python)    │   │  15-alpine   │   │  (FastAPI) │ │
│  └──────┬───────┘   └──────────────┘   └────────────┘ │
│         │                                              │
│         │           ┌──────────────────────────────┐  │
│         └──────────▶│   Redis HA Cluster           │  │
│                     │   Master + 2 Replicas         │  │
│                     │   + 3 Sentinels               │  │
│                     └──────────────────────────────┘  │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 🐳 DOCKER COMPOSE SERVICES

### 1. PostgreSQL Database

```yaml
Service: db
Image: postgres:15-alpine
Container: odoo19_db
Restart: unless-stopped

Environment:
  POSTGRES_DB: odoo
  POSTGRES_USER: odoo
  POSTGRES_PASSWORD: ${ODOO_DB_PASSWORD}
  POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=es_CL.UTF-8"

Volumes:
  - postgres_data:/var/lib/postgresql/data

Network:
  - stack_network (internal)

Ports:
  - 5432 (expose only, no publish)

Health Check:
  Command: pg_isready -U odoo
  Interval: 10s
  Timeout: 5s
  Retries: 5
```

**Características:**
- Encoding UTF-8
- Locale español Chile (es_CL.UTF-8)
- Persistencia en volume Docker
- Solo accesible desde red interna

---

### 2. Redis High Availability Cluster

**Arquitectura:** 1 Master + 2 Replicas + 3 Sentinels

#### 2.1 Redis Master

```yaml
Service: redis-master
Image: redis:7-alpine
Container: odoo19_redis_master

Command: redis-server /usr/local/etc/redis/redis.conf

Volumes:
  - ./redis/redis-master.conf:/usr/local/etc/redis/redis.conf:ro
  - redis_master_data:/data

Configuration:
  - Password protection
  - AOF persistence enabled
  - RDB snapshots
  - MaxMemory policy: allkeys-lru

Health Check:
  Command: redis-cli -a password ping
  Interval: 10s
```

#### 2.2 Redis Replicas (2)

```yaml
Services: redis-replica-1, redis-replica-2
Profiles: ["production", "ha"]
Master: redis-master (automatic replication)
Read-only: yes
```

**Nota:** Replicas solo se inician en modo producción/HA:
```bash
docker compose --profile production up -d
docker compose --profile ha up -d
```

#### 2.3 Redis Sentinels (3)

```yaml
Services: redis-sentinel-1, redis-sentinel-2, redis-sentinel-3
Quorum: 2/3 (mínimo 2 sentinels para failover)
Down After: 5000ms
Failover Timeout: 60000ms
Parallel Syncs: 1
```

**Características HA:**
- Automatic failover (<10s downtime)
- Health monitoring continuo
- Replicación asíncrona master → replicas
- Quorum 2/3 para decidir failover

---

### 3. Odoo 19 CE

```yaml
Service: odoo
Image: eergygroup/odoo19:chile-1.0.5 (custom)
Container: odoo19_app

Depends On:
  - db (healthcheck required)
  - redis-master

Environment:
  HOST: db
  PORT: 5432
  USER: odoo
  PASSWORD: ${ODOO_DB_PASSWORD}

Volumes:
  - ./addons:/mnt/extra-addons
  - ./config:/etc/odoo
  - odoo_data:/var/lib/odoo
  - odoo_filestore:/var/lib/odoo/filestore

Ports:
  - 8069:8069 (HTTP)
  - 8072:8072 (Longpolling)

Network:
  - stack_network

Health Check:
  Command: curl -f http://localhost:8069/web/health
  Interval: 30s
  Timeout: 10s
  Retries: 3
  Start Period: 60s
```

**Addons Montados:**
- `/mnt/extra-addons/localization/` - Módulos localization chilena
- `/mnt/extra-addons/custom/` - Módulos custom EERGYGROUP

**Módulos Críticos:**
- `l10n_cl_dte` - Facturación Electrónica (DTE 33/34/52/56/61)
- `l10n_cl_hr_payroll` - Nómina + Previred
- `l10n_cl_financial_reports` - Reportes Financieros Chile
- `ai_service_integration` - Integración AI Service

---

### 4. AI Service (FastAPI)

```yaml
Service: ai_service
Build: ./ai_service
Container: odoo19_ai_service

Environment:
  CLAUDE_API_KEY: ${CLAUDE_API_KEY}
  ANTHROPIC_MODEL: claude-sonnet-4-5-20250929
  LOG_LEVEL: INFO
  REDIS_URL: redis://redis-master:6379/0

Volumes:
  - ./ai_service:/app

Ports:
  - 8000:8000 (FastAPI)

Network:
  - stack_network

Health Check:
  Command: curl -f http://localhost:8000/health
  Interval: 30s
```

**Endpoints:**
- `POST /v1/chat/completions` - Claude API proxy
- `POST /v1/document/analyze` - Análisis documentos DTE
- `POST /v1/payroll/validate` - Validación Previred
- `GET /health` - Health check

**Caché:**
- Redis cache para respuestas frecuentes
- TTL: 3600s (1 hora)

---

## 🌐 NETWORKING

### Networks

```yaml
stack_network:
  Driver: bridge
  Internal: false
  Subnet: 172.20.0.0/16
```

**Aislamiento:**
- DB solo accesible internamente (no puertos expuestos)
- Redis solo accesible internamente
- Odoo y AI Service exponen puertos para acceso externo

---

## 💾 VOLUMES

```yaml
Volumes Persistentes:
  - postgres_data (PostgreSQL data)
  - redis_master_data (Redis master persistence)
  - redis_replica1_data (Redis replica 1)
  - redis_replica2_data (Redis replica 2)
  - odoo_data (Odoo application data)
  - odoo_filestore (Archivos attachments)

Bind Mounts:
  - ./addons → /mnt/extra-addons (código módulos)
  - ./config → /etc/odoo (configuración)
  - ./redis → /usr/local/etc/redis (config Redis)
```

**Backups:**
- PostgreSQL: `docker compose exec db pg_dump -Fc odoo > backup.dump`
- Redis: automático vía AOF + RDB snapshots
- Filestore: backup directo de volume `odoo_filestore`

---

## 🔐 SECRETS MANAGEMENT

**Variables de Entorno (.env):**

```bash
# Database
ODOO_DB_NAME=odoo
ODOO_DB_USER=odoo
ODOO_DB_PASSWORD=<secret>

# Redis
REDIS_PASSWORD=odoo19_redis_pass

# AI Service
CLAUDE_API_KEY=<secret>

# Odoo Config
ODOO_ADMIN_PASSWORD=<secret>
```

**⚠️ IMPORTANTE:**
- Archivo `.env` en `.gitignore`
- NO commit secrets al repositorio
- Rotación periódica passwords (recomendado: 90 días)

---

## 📊 RESOURCE LIMITS

**Recomendaciones Producción:**

```yaml
PostgreSQL:
  CPU: 2 cores
  Memory: 2GB
  Shared Buffers: 512MB
  Max Connections: 200

Redis (cada instancia):
  CPU: 0.5 cores
  Memory: 512MB
  MaxMemory: 512mb
  MaxMemory Policy: allkeys-lru

Odoo:
  CPU: 4 cores
  Memory: 4GB
  Workers: 4
  Max Cron Threads: 2

AI Service:
  CPU: 2 cores
  Memory: 2GB
```

**Aplicar limits en docker-compose.yml:**

```yaml
services:
  odoo:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 1G
```

---

## 🚀 DEPLOYMENT MODES

### Desarrollo (Local)

```bash
# Iniciar solo servicios esenciales
docker compose up -d

# Servicios activos:
# - db
# - redis-master (solo master, sin replicas)
# - odoo
# - ai_service
```

### Producción (HA)

```bash
# Iniciar con alta disponibilidad
docker compose --profile production up -d

# Servicios activos:
# - db
# - redis-master
# - redis-replica-1
# - redis-replica-2
# - redis-sentinel-1
# - redis-sentinel-2
# - redis-sentinel-3
# - odoo (multi-worker)
# - ai_service
```

---

## 📈 MONITORING

### Health Checks

```bash
# Ver estado todos los servicios
docker compose ps

# Esperado output:
# NAME                    STATUS              HEALTH
# odoo19_app              Up (healthy)
# odoo19_db               Up (healthy)
# odoo19_redis_master     Up (healthy)
# odoo19_ai_service       Up (healthy)
```

### Logs

```bash
# Logs en tiempo real
docker compose logs -f

# Logs servicio específico
docker compose logs -f odoo

# Buscar errores
docker compose logs odoo | grep ERROR
```

### Metrics

```bash
# Recursos (CPU, Memory, I/O)
docker stats

# Conexiones PostgreSQL
docker compose exec db psql -U odoo -d odoo -c "SELECT count(*) FROM pg_stat_activity;"

# Redis info
docker compose exec redis-master redis-cli -a odoo19_redis_pass INFO
```

---

## 🔧 CONFIGURACIÓN ODOO

**Archivo:** `config/odoo.conf`

```ini
[options]
addons_path = /mnt/extra-addons/localization,/mnt/extra-addons/custom,/usr/lib/python3/dist-packages/odoo/addons
admin_passwd = ${ODOO_ADMIN_PASSWORD}
db_host = db
db_port = 5432
db_user = odoo
db_password = ${ODOO_DB_PASSWORD}
dbfilter = ^odoo.*$
http_port = 8069
longpolling_port = 8072
workers = 4
max_cron_threads = 2
limit_memory_hard = 2684354560
limit_memory_soft = 2147483648
limit_request = 8192
limit_time_cpu = 600
limit_time_real = 1200
log_level = info
logfile = False  # Logs a stdout para Docker
proxy_mode = True

# Redis Session Store
session_store_dbname = False
session_store_cache = redis://redis-master:6379/1

# AI Service Integration
ai_service_url = http://ai_service:8000
ai_service_timeout = 30
```

---

## 🌍 PLATFORM SPECIFICS

### macOS M3 (ARM64)

**Images usadas:**
- `postgres:15-alpine` - ARM64 nativo
- `redis:7-alpine` - ARM64 nativo
- `eergygroup/odoo19:chile-1.0.5` - Multi-arch (ARM64 + AMD64)

**Performance:**
- Rosetta 2 NO requerido
- Docker Desktop para Mac (latest)
- RAM disponible: 16GB mínimo
- Disco SSD recomendado

**Paths macOS:**
- Proyecto: `/Users/pedro/Documents/odoo19`
- Docker Desktop data: `~/Library/Containers/com.docker.docker/Data/`

---

## 🔍 TROUBLESHOOTING

### Odoo no inicia

```bash
# 1. Verificar DB healthcheck
docker compose ps db

# 2. Verificar logs
docker compose logs odoo --tail=100

# 3. Reiniciar stack
docker compose restart
```

### Alta latencia

```bash
# 1. Verificar Redis cluster
docker compose exec redis-master redis-cli -a odoo19_redis_pass PING

# 2. Ver queries lentas (PostgreSQL)
docker compose exec db psql -U odoo -d odoo -c \
  "SELECT pid, query_start, state, query FROM pg_stat_activity WHERE state != 'idle';"

# 3. Recursos contenedores
docker stats
```

### Failover Redis no funciona

```bash
# 1. Ver logs Sentinels
docker compose logs redis-sentinel-1 redis-sentinel-2 redis-sentinel-3

# 2. Verificar quorum
docker compose exec redis-sentinel-1 redis-cli -p 26379 SENTINEL masters

# 3. Test failover manual
docker compose exec redis-sentinel-1 redis-cli -p 26379 \
  SENTINEL failover odoo19_redis_master
```

---

## 📚 REFERENCIAS

**Documentación Relacionada:**
- `docker_odoo_command_reference.md` - Comandos Docker + Odoo CLI
- `odoo19_patterns.md` - Patrones desarrollo Odoo 19
- `project_architecture.md` - Decisiones arquitectura EERGYGROUP

**Documentación Oficial:**
- Docker Compose: https://docs.docker.com/compose/
- PostgreSQL 15: https://www.postgresql.org/docs/15/
- Redis 7: https://redis.io/docs/
- Odoo 19: https://www.odoo.com/documentation/19.0/

---

## 🎯 QUICK REFERENCE

```bash
# Iniciar stack
docker compose up -d

# Parar stack
docker compose stop

# Ver estado
docker compose ps

# Logs
docker compose logs -f odoo

# Shell Odoo
docker compose exec odoo odoo-bin shell -d odoo

# Shell DB
docker compose exec db psql -U odoo -d odoo

# Backup DB
docker compose exec db pg_dump -Fc odoo > backup.dump

# Monitoring
docker stats
```

---

**Versión:** 1.0.0
**Última actualización:** 2025-11-12
**Mantenedor:** Pedro Troncoso (@pwills85)
**Deployment:** Producción EERGYGROUP
