# 🏗️ TEMPLATE P4 INFRASTRUCTURE AUDIT - Auditoría Infraestructura & DevOps

**Versión:** 1.0.0
**Nivel:** P4 (Máxima Precisión)
**Tipo:** Auditoría Infraestructura, Docker, DB, Networking, Seguridad
**Tiempo Estimado:** 2-4 horas ejecución
**Tokens Estimados:** 50K-80K

---

## 📋 Metadata Prompt

```yaml
prompt_id: TPL-P4-INFRA-001
version: 1.0.0
created: 2025-11-12
scope: [docker, database, redis, networking, security, monitoring, backup]
compliance_level: Production_Ready
outputs: [infrastructure_report, security_assessment, recommendations, runbook]
```

---

## 🎯 Objetivo de la Auditoría

Evaluar stack infraestructura completo del proyecto Odoo 19 CE EERGYGROUP:

1. **Docker Compose:** Configuración servicios, networking, volumes, healthchecks
2. **PostgreSQL:** Performance, indexación, backups, seguridad
3. **Redis:** Configuración cache, persistencia, monitoring
4. **Networking:** Puertos, reverse proxy, SSL/TLS, firewalls
5. **Seguridad:** Secrets management, permisos, vulnerabilidades
6. **Monitoring:** Logs, métricas, alertas, observabilidad
7. **Backup & DR:** Estrategia respaldo, recovery, RTO/RPO

**Output esperado:** Reporte infraestructura con score cuantitativo, hallazgos priorizados, y runbook operacional.

---

## 📐 Contexto del Stack

### Arquitectura Actual

```yaml
Platform: macOS M3 (ARM64)
Ubicación: /Users/pedro/Documents/odoo19
Orchestration: Docker Compose v2.24+

Services:
  odoo:
    image: eergygroup/odoo19:chile-1.0.5
    ports: 8069:8069
    volumes: ./addons, ./config, ./data
    depends_on: [db, redis]

  db:
    image: postgres:15-alpine
    ports: 5432:5432
    volumes: ./db_data
    environment: POSTGRES_DB=odoo19_db

  redis:
    image: redis:7-alpine
    ports: 6379:6379
    volumes: ./redis_data

  ai_service:
    build: ./ai_service
    ports: 8000:8000
    environment: CLAUDE_API_KEY=${CLAUDE_API_KEY}
```

### Comandos Validación Infraestructura

```bash
# Status servicios
docker compose ps

# Logs en tiempo real
docker compose logs -f --tail=100

# Recursos (CPU, memoria)
docker stats --no-stream

# Healthchecks
docker compose ps | grep "healthy"

# Networks
docker network ls
docker network inspect odoo19_default

# Volumes
docker volume ls
docker volume inspect odoo19_db_data
```

---

## 🐳 DOCKER COMPOSE AUDIT

### 1. Configuración Servicios

**Archivo a revisar:** `docker-compose.yml`

#### 1.1 Servicio Odoo

```yaml
# Validar configuración productiva
services:
  odoo:
    image: eergygroup/odoo19:chile-1.0.5
    container_name: odoo_production  # ✅ Nombre explícito
    restart: unless-stopped  # ✅ Auto-restart
    ports:
      - "8069:8069"  # ⚠️ Exponer solo si reverse proxy
    volumes:
      - ./addons:/mnt/extra-addons:ro  # ✅ Read-only si producción
      - ./config:/etc/odoo:ro
      - ./data:/var/lib/odoo
    environment:
      - HOST=db
      - PORT=5432
      - USER=odoo
      - PASSWORD=${DB_PASSWORD}  # ✅ Usar secrets
    depends_on:
      db:
        condition: service_healthy  # ✅ Health checks
      redis:
        condition: service_started
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8069/web/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    deploy:
      resources:
        limits:
          cpus: '2.0'  # ✅ Límites recursos
          memory: 4G
        reservations:
          cpus: '0.5'
          memory: 1G
```

**Checklist Odoo Service:**
- [ ] restart policy configurado
- [ ] volumes con permisos correctos (ro para config)
- [ ] secrets desde env vars (no hardcoded)
- [ ] healthcheck implementado
- [ ] resource limits definidos
- [ ] depends_on con conditions
- [ ] logging driver configurado

**Reportar:** Configuraciones faltantes + riesgos seguridad.

---

#### 1.2 Servicio PostgreSQL

```yaml
db:
  image: postgres:15-alpine
  container_name: postgres_odoo
  restart: unless-stopped
  ports:
    - "127.0.0.1:5432:5432"  # ✅ Bind localhost only
  volumes:
    - db_data:/var/lib/postgresql/data
    - ./backups:/backups  # ✅ Directorio backups
  environment:
    POSTGRES_DB: odoo19_db
    POSTGRES_USER: odoo
    POSTGRES_PASSWORD: ${DB_PASSWORD}
    POSTGRES_INITDB_ARGS: "--encoding=UTF8 --lc-collate=es_CL.UTF-8 --lc-ctype=es_CL.UTF-8"
  healthcheck:
    test: ["CMD-SHELL", "pg_isready -U odoo"]
    interval: 10s
    timeout: 5s
    retries: 5
  deploy:
    resources:
      limits:
        cpus: '2.0'
        memory: 2G
  command:
    - "postgres"
    - "-c"
    - "max_connections=200"
    - "-c"
    - "shared_buffers=512MB"
    - "-c"
    - "effective_cache_size=1GB"
    - "-c"
    - "work_mem=16MB"
    - "-c"
    - "maintenance_work_mem=128MB"
```

**Checklist PostgreSQL:**
- [ ] Puerto bindeado solo a localhost
- [ ] Healthcheck configurado
- [ ] Volumen persistente para data
- [ ] Parámetros tuning (shared_buffers, work_mem)
- [ ] Locale correcto (es_CL.UTF-8)
- [ ] Backups directory montado
- [ ] Resource limits apropiados

**Reportar:** Tuning subóptimo + missing backups strategy.

---

#### 1.3 Servicio Redis

```yaml
redis:
  image: redis:7-alpine
  container_name: redis_cache
  restart: unless-stopped
  ports:
    - "127.0.0.1:6379:6379"  # ✅ Bind localhost only
  volumes:
    - redis_data:/data
  command:
    - "redis-server"
    - "--appendonly"
    - "yes"  # ✅ Persistencia AOF
    - "--maxmemory"
    - "512mb"
    - "--maxmemory-policy"
    - "allkeys-lru"  # ✅ Eviction policy
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]
    interval: 10s
    timeout: 3s
    retries: 5
  deploy:
    resources:
      limits:
        cpus: '0.5'
        memory: 512M
```

**Checklist Redis:**
- [ ] Persistencia habilitada (AOF o RDB)
- [ ] maxmemory configurado
- [ ] Eviction policy apropiado
- [ ] Healthcheck funcional
- [ ] Puerto no expuesto públicamente

**Reportar:** Configuración cache + riesgo pérdida datos.

---

### 2. Networking y Seguridad

#### 2.1 Networks

```yaml
networks:
  odoo_internal:
    driver: bridge
    internal: false  # ⚠️ True si no necesita internet
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  odoo:
    networks:
      - odoo_internal
  db:
    networks:
      - odoo_internal  # ✅ Aislada, no exponer
  redis:
    networks:
      - odoo_internal
```

**Validar:**
```bash
# Ver networks
docker network ls

# Inspeccionar
docker network inspect odoo19_odoo_internal

# Validar containers en network
docker network inspect odoo19_odoo_internal | jq '.[].Containers'
```

**Checklist Networks:**
- [ ] Network dedicada (no usar default)
- [ ] DB y Redis en network interna (no puertos externos)
- [ ] Subnet configurada (evitar conflictos)
- [ ] Firewall rules si aplica

**Reportar:** Exposición innecesaria servicios + network segmentation.

---

#### 2.2 Volumes y Persistencia

```yaml
volumes:
  db_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /Users/pedro/Documents/odoo19/db_data
  redis_data:
    driver: local
```

**Validar:**
```bash
# Listar volumes
docker volume ls

# Inspeccionar volume
docker volume inspect odoo19_db_data

# Verificar permisos
ls -la /Users/pedro/Documents/odoo19/db_data

# Espacio disponible
df -h | grep odoo19
```

**Checklist Volumes:**
- [ ] Named volumes para persistencia
- [ ] Permisos correctos (UID/GID match container)
- [ ] Backups regulares configurados
- [ ] Espacio suficiente (>20% libre)
- [ ] Montajes read-only donde aplique

**Reportar:** Riesgo pérdida datos + permisos incorrectos.

---

### 3. Secrets Management

**Validar .env file:**

```bash
# Verificar .env existe y no está en git
test -f .env && echo "✅ .env exists"
grep -q ".env" .gitignore && echo "✅ .env in .gitignore"

# Validar secrets no hardcoded
grep -r "POSTGRES_PASSWORD=" docker-compose.yml && echo "🔴 Hardcoded secret!"
```

**Checklist Secrets:**
- [ ] .env para variables sensibles
- [ ] .env en .gitignore
- [ ] Sin secrets hardcoded en docker-compose.yml
- [ ] Rotación periódica passwords
- [ ] Secrets no en logs

**Reportar:** Secrets expuestos + riesgo seguridad.

---

## 🗄️ POSTGRESQL AUDIT

### 1. Performance y Tuning

#### 1.1 Configuración Actual

```bash
# Conectar a PostgreSQL
docker compose exec db psql -U odoo -d odoo19_db

# Ver configuración
SHOW max_connections;
SHOW shared_buffers;
SHOW effective_cache_size;
SHOW work_mem;
SHOW maintenance_work_mem;
```

**Parámetros recomendados (4GB RAM disponible):**

| Parámetro | Valor Actual | Recomendado | Status |
|-----------|--------------|-------------|--------|
| max_connections | {N} | 200 | 🔴/🟢 |
| shared_buffers | {N} | 512MB | 🔴/🟢 |
| effective_cache_size | {N} | 1.5GB | 🔴/🟢 |
| work_mem | {N} | 16MB | 🔴/🟢 |
| maintenance_work_mem | {N} | 128MB | 🔴/🟢 |
| checkpoint_completion_target | {N} | 0.9 | 🔴/🟢 |
| wal_buffers | {N} | 16MB | 🔴/🟢 |
| default_statistics_target | {N} | 100 | 🔴/🟢 |

**Reportar:** Desviaciones configuración + impacto performance.

---

#### 1.2 Queries Lentas

```sql
-- Habilitar log queries lentas
ALTER SYSTEM SET log_min_duration_statement = 1000; -- 1s
SELECT pg_reload_conf();

-- Ver queries activas
SELECT pid, usename, application_name, state, query_start, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY query_start;

-- Top 10 queries más lentas (requiere pg_stat_statements)
SELECT query, calls, total_exec_time, mean_exec_time, max_exec_time
FROM pg_stat_statements
ORDER BY mean_exec_time DESC
LIMIT 10;
```

**Reportar:**
- Queries >1s con frecuencia alta
- Queries sin indexes
- Full table scans

---

#### 1.3 Indexación

```sql
-- Ver indexes existentes
SELECT
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY tablename, indexname;

-- Detectar missing indexes (table scans frecuentes)
SELECT
    schemaname,
    tablename,
    seq_scan,
    seq_tup_read,
    idx_scan,
    seq_tup_read / seq_scan AS avg_seq_tup_read
FROM pg_stat_user_tables
WHERE seq_scan > 0
ORDER BY seq_tup_read DESC
LIMIT 20;

-- Indexes no usados (candidatos para drop)
SELECT
    schemaname,
    tablename,
    indexname,
    idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0
ORDER BY idx_scan;
```

**Reportar:**
- Tablas con alto seq_scan (necesitan indexes)
- Indexes no usados (overhead mantenimiento)
- Recomendaciones indexes compuestos

---

### 2. Espacio y Crecimiento

```sql
-- Tamaño database
SELECT pg_size_pretty(pg_database_size('odoo19_db'));

-- Top 10 tablas más grandes
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS size
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 10;

-- Bloat (espacio desperdiciado)
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS size,
    (pg_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename, 'main'))::float / NULLIF(pg_relation_size(schemaname||'.'||tablename), 0) * 100 AS bloat_pct
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
ORDER BY bloat_pct DESC NULLS LAST
LIMIT 10;
```

**Reportar:**
- Database size total
- Crecimiento mensual estimado
- Tablas con bloat >20% (necesitan VACUUM)
- Proyección espacio 6 meses

---

### 3. Backups y Recovery

```bash
# Validar script backup existe
test -f scripts/backup_db.sh && echo "✅ Backup script exists"

# Backup manual
docker compose exec db pg_dump -U odoo -Fc odoo19_db > backups/odoo19_db_$(date +%Y%m%d_%H%M%S).dump

# Verificar backups recientes
ls -lth backups/ | head -10

# Test restore (DB test)
docker compose exec db pg_restore -U odoo -d odoo19_db_test backups/latest.dump
```

**Checklist Backups:**
- [ ] Script automatizado backup
- [ ] Backups diarios configurados (cron)
- [ ] Retención 30 días mínimo
- [ ] Backups fuera del servidor (offsite)
- [ ] Test restore mensual documentado
- [ ] RTO <4h, RPO <24h documentado

**Reportar:**
- Estrategia backup actual
- Gaps vs best practices
- RTO/RPO real vs objetivo

---

## 🔴 REDIS AUDIT

### 1. Configuración y Uso

```bash
# Conectar a Redis
docker compose exec redis redis-cli

# Info general
INFO

# Memoria
INFO memory

# Stats
INFO stats

# Keyspace
INFO keyspace

# Config
CONFIG GET maxmemory
CONFIG GET maxmemory-policy
CONFIG GET appendonly
```

**Validar:**

| Métrica | Valor Actual | Recomendado | Status |
|---------|--------------|-------------|--------|
| maxmemory | {N} | 512MB | 🔴/🟢 |
| maxmemory-policy | {N} | allkeys-lru | 🔴/🟢 |
| appendonly | {yes/no} | yes | 🔴/🟢 |
| used_memory | {N} | <80% maxmemory | 🔴/🟢 |
| evicted_keys | {N} | <1% keys | 🔴/🟢 |

**Reportar:**
- Uso memoria (evictions frecuentes)
- Persistencia configurada
- Cache hit ratio estimado

---

### 2. Persistencia y Backup

```bash
# Verificar AOF habilitado
docker compose exec redis redis-cli CONFIG GET appendonly

# Último save
docker compose exec redis redis-cli LASTSAVE

# Forzar save (si RDB)
docker compose exec redis redis-cli BGSAVE

# Verificar archivos persistencia
docker compose exec redis ls -lh /data/
```

**Checklist Persistencia:**
- [ ] AOF o RDB habilitado
- [ ] Fsync policy apropiado (everysec)
- [ ] Backup periódico /data volume
- [ ] Monitoring disk space

**Reportar:** Riesgo pérdida cache + estrategia backup.

---

## 🔒 SEGURIDAD INFRAESTRUCTURA

### 1. Secrets Scanning

```bash
# Buscar secrets hardcoded
grep -r "password\|secret\|token\|api_key" docker-compose.yml .env.example config/

# Validar .env no en git
git ls-files | grep "^\.env$" && echo "🔴 .env committed to git!"

# Validar secrets en logs
docker compose logs | grep -i "password\|secret\|token" | head -20
```

**Reportar:**
- Secrets expuestos (archivos, logs, env vars)
- Recomendación Docker secrets o vault

---

### 2. CVE Scanning (Vulnerabilidades)

```bash
# Scan images con Trivy
trivy image eergygroup/odoo19:chile-1.0.5
trivy image postgres:15-alpine
trivy image redis:7-alpine

# Validar updates disponibles
docker compose pull --dry-run
```

**Reportar:**
- CVEs críticas (score >7.0)
- Recomendación updates images

---

### 3. Permisos y Access Control

```bash
# Validar permisos directorio datos
ls -la db_data/ redis_data/ data/

# Validar usuario containers (no root)
docker compose exec odoo whoami
docker compose exec db whoami

# Validar capabilities
docker inspect odoo | jq '.[].HostConfig.CapAdd'
```

**Checklist Permisos:**
- [ ] Containers run as non-root user
- [ ] Directories con permisos restrictivos (700)
- [ ] Sin capabilities innecesarias
- [ ] SELinux/AppArmor profiles si aplica

**Reportar:** Permisos excesivos + riesgo escalación privilegios.

---

## 📊 MONITORING Y OBSERVABILIDAD

### 1. Logs

```bash
# Ver logs todos servicios
docker compose logs --tail=100

# Logs con timestamp
docker compose logs -f --timestamps

# Filtrar errores
docker compose logs | grep -i "error\|exception\|critical"

# Validar rotación logs
docker inspect odoo | jq '.[].HostConfig.LogConfig'
```

**Checklist Logging:**
- [ ] Log driver configurado (json-file, syslog)
- [ ] Log rotation habilitada (max-size, max-file)
- [ ] Logs centralizados (ELK, Loki, CloudWatch)
- [ ] Alertas en errores críticos

**Reportar:**
- Estrategia logging actual
- Gaps vs observabilidad producción

---

### 2. Métricas

```bash
# Recursos containers
docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# Health checks status
docker compose ps | grep "healthy"

# Disk usage
docker system df
```

**Implementar métricas (recomendación):**
- Prometheus + Grafana
- cAdvisor para container metrics
- PostgreSQL exporter
- Redis exporter

**Reportar:**
- Métricas actuales disponibles
- Recomendación stack monitoring

---

### 3. Alertas

**Definir alertas críticas:**

| Alerta | Condición | Acción |
|--------|-----------|--------|
| DB disk >90% | df -h \| grep db_data | Expandir disco / limpiar |
| Odoo down | healthcheck fail >3 | Restart + investigar logs |
| High memory | used_memory >90% | Investigar leak / escalar |
| Backup failed | script exit ≠0 | Notificación + retry manual |

**Reportar:** Sistema alertas actual + gaps críticos.

---

## 📋 DELIVERABLES

### 1. Infrastructure Score Card

```markdown
# Infrastructure Audit Score: {X}/100

## Scores por Área

| Área | Score | Status |
|------|-------|--------|
| Docker Compose Config | {N}/20 | 🔴/🟡/🟢 |
| PostgreSQL Performance | {N}/20 | 🔴/🟡/🟢 |
| Redis Configuration | {N}/10 | 🔴/🟡/🟢 |
| Networking & Security | {N}/15 | 🔴/🟡/🟢 |
| Secrets Management | {N}/10 | 🔴/🟡/🟢 |
| Backup & DR | {N}/15 | 🔴/🟡/🟢 |
| Monitoring | {N}/10 | 🔴/🟡/🟢 |

## Hallazgos Críticos
1. [INFRA-P0-01] Descripción
2. [INFRA-P0-02] Descripción

## Recomendaciones Top 5
1. Acción inmediata
2. Acción inmediata
...
```

---

### 2. Runbook Operacional

```markdown
# Runbook Operacional - Odoo 19 EERGYGROUP

## Startup Procedures
1. Verificar .env configurado
2. `docker compose up -d`
3. Validar healthchecks: `docker compose ps`
4. Verificar logs: `docker compose logs -f --tail=50`

## Shutdown Procedures
1. `docker compose stop` (graceful)
2. Backup pre-shutdown: `scripts/backup_db.sh`
3. Verificar backup exitoso
4. `docker compose down` (solo si mantenimiento)

## Backup Procedures
- Diario: cron 2 AM `scripts/backup_db.sh`
- Retención: 30 días
- Offsite: sync a S3/NAS

## Recovery Procedures
1. Restore DB: `scripts/restore_db.sh {backup_file}`
2. Restart services: `docker compose restart`
3. Validar integridad

## Troubleshooting
- Odoo slow: Check PostgreSQL queries lentas
- DB connection errors: Verify network, credentials
- High memory: Check Redis evictions, PostgreSQL bloat
```

---

### 3. Reporte Técnico Detallado

**Incluir:**
1. Docker Compose audit completo
2. PostgreSQL performance + tuning recommendations
3. Redis configuration + cache analysis
4. Security assessment (secrets, CVEs, permissions)
5. Monitoring gaps + recommendations
6. Backup strategy + DR plan
7. Appendix: comandos útiles, configs recomendadas

---

### 4. Métricas JSON

```json
{
  "infrastructure_audit": {
    "date": "2025-11-12",
    "score": 78,
    "docker": {
      "healthchecks": true,
      "resource_limits": true,
      "secrets_management": false
    },
    "postgresql": {
      "size_gb": 12.3,
      "slow_queries": 15,
      "missing_indexes": 8,
      "backup_strategy": "manual"
    },
    "redis": {
      "maxmemory_mb": 512,
      "persistence": "aof",
      "evictions_pct": 2.1
    },
    "security": {
      "cves_critical": 2,
      "secrets_exposed": 0,
      "non_root_containers": true
    },
    "monitoring": {
      "centralized_logs": false,
      "metrics_collection": false,
      "alerting": false
    }
  }
}
```

---

## ✅ Checklist Pre-Entrega

- [ ] Docker Compose config auditado
- [ ] PostgreSQL performance evaluado
- [ ] Redis configuration validado
- [ ] Secrets scanning completado
- [ ] CVE scanning ejecutado
- [ ] Backup strategy documentado
- [ ] Monitoring gaps identificados
- [ ] Runbook operacional creado
- [ ] Score card generado
- [ ] Reporte técnico completo
- [ ] Métricas JSON exportadas

---

**Template Version:** 1.0.0
**Creado:** 2025-11-12
**Mantenedor:** Pedro Troncoso (@pwills85)
